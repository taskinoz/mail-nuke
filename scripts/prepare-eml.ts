import { promises as fs } from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { simpleParser } from "mailparser";
import { convert as htmlToText } from "html-to-text";

type Label = "ham" | "spam";

type ReplacementConfig = {
  subjectPrefixes: string[];
  subjectContains: string[];
  bodyContains: string[];
};

type PreparedEmail = {
  id: string;
  label: Label;
  sourcePath: string;
  split: "train" | "valid" | "test";
  dedupeKey: string;
  from: {
    raw: string;
    address: string;
    name: string;
    domain: string;
  };
  subject: {
    raw: string;
    clean: string;
  };
  body: {
    raw: string;
    clean: string;
    length: number;
    urlCount: number;
  };
  flags: {
    hadProviderSpamMarker: boolean;
    hadUserEmail: boolean;
    hadUserName: boolean;
    hadLeakedPassword: boolean;
    hadConfiguredSpamPhrase: boolean;
  };
  redactions: {
    userEmailCount: number;
    userNameCount: number;
    leakedPasswordCount: number;
    providerMarkerCount: number;
    configuredPhraseCount: number;
  };
  modelText: string;
};

type Args = {
  hamDir: string;
  spamDir: string;
  outDir: string;
  configDir: string;
  trainPct: number;
  validPct: number;
  testPct: number;
};

function parseArgs(argv: string[]): Args {
  const args: Record<string, string> = {};
  for (let i = 2; i < argv.length; i += 2) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!key?.startsWith("--") || value == null) continue;
    args[key.slice(2)] = value;
  }

  const trainPct = Number(args.trainPct ?? "0.7");
  const validPct = Number(args.validPct ?? "0.15");
  const testPct = Number(args.testPct ?? "0.15");

  if (Math.abs(trainPct + validPct + testPct - 1) > 0.0001) {
    throw new Error("trainPct + validPct + testPct must equal 1");
  }

  return {
    hamDir: args.hamDir ?? path.resolve("exports/ham"),
    spamDir: args.spamDir ?? path.resolve("exports/spam"),
    outDir: args.outDir ?? path.resolve("prepared"),
    configDir: args.configDir ?? path.resolve("config"),
    trainPct,
    validPct,
    testPct,
  };
}

async function readLines(filePath: string): Promise<string[]> {
  try {
    const content = await fs.readFile(filePath, "utf8");
    return content
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean)
      .filter((s) => !s.startsWith("#"));
  } catch {
    return [];
  }
}

async function readJson<T>(filePath: string, fallback: T): Promise<T> {
  try {
    const content = await fs.readFile(filePath, "utf8");
    return JSON.parse(content) as T;
  } catch {
    return fallback;
  }
}

async function ensureDir(dir: string) {
  await fs.mkdir(dir, { recursive: true });
}

async function walkEmlFiles(dir: string): Promise<string[]> {
  const out: string[] = [];

  async function walk(current: string) {
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
      } else if (entry.isFile() && full.toLowerCase().endsWith(".eml")) {
        out.push(full);
      }
    }
  }

  await walk(dir);
  return out.sort();
}

function escapeRegex(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normaliseWhitespace(input: string): string {
  return input.replace(/\s+/g, " ").trim();
}

function stripQuotedReplies(text: string): string {
  const lines = text.split(/\r?\n/);
  const kept: string[] = [];

  for (const line of lines) {
    const trimmed = line.trim();

    if (
      trimmed.startsWith(">") ||
      /^on .+wrote:$/i.test(trimmed) ||
      /^from:\s/i.test(trimmed) ||
      /^sent:\s/i.test(trimmed) ||
      /^subject:\s/i.test(trimmed) ||
      /^to:\s/i.test(trimmed)
    ) {
      break;
    }

    kept.push(line);
  }

  return kept.join("\n");
}

function countUrls(text: string): number {
  const matches = text.match(/\bhttps?:\/\/[^\s]+/gi);
  return matches?.length ?? 0;
}

function stableHash(input: string): string {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function mulberry32(seed: number) {
  return function () {
    let t = (seed += 0x6d2b79f5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function hashToSeed(input: string): number {
  const hex = stableHash(input).slice(0, 8);
  return Number.parseInt(hex, 16) >>> 0;
}

function chooseSplit(
  key: string,
  trainPct: number,
  validPct: number,
): "train" | "valid" | "test" {
  const rand = mulberry32(hashToSeed(key))();
  if (rand < trainPct) return "train";
  if (rand < trainPct + validPct) return "valid";
  return "test";
}

function lowerIncludesAny(text: string, phrases: string[]): boolean {
  const lower = text.toLowerCase();
  return phrases.some((p) => lower.includes(p.toLowerCase()));
}

function replaceAllWithCount(
  input: string,
  regex: RegExp,
  replacement: string,
): { text: string; count: number } {
  let count = 0;
  const text = input.replace(regex, () => {
    count += 1;
    return replacement;
  });
  return { text, count };
}

function buildWordRegex(words: string[]): RegExp | null {
  const filtered = [...new Set(words.map((w) => w.trim()).filter(Boolean))];
  if (filtered.length === 0) return null;
  filtered.sort((a, b) => b.length - a.length);
  return new RegExp(filtered.map(escapeRegex).join("|"), "gi");
}

function cleanText(input: string): string {
  return normaliseWhitespace(
    input
      .replace(/\u0000/g, " ")
      .replace(/\r/g, "\n")
      .replace(/\t/g, " "),
  );
}

async function checkReadableNonEmptyFile(filePath: string): Promise<{
  ok: boolean;
  reason?: string;
  size?: number;
}> {
  try {
    const info = await fs.stat(filePath);

    if (!info.isFile()) {
      return { ok: false, reason: "not_a_file" };
    }

    if (info.size <= 0) {
      return { ok: false, reason: "empty_file", size: info.size };
    }

    return { ok: true, size: info.size };
  } catch (error: any) {
    if (error?.code === "ENOENT") {
      return { ok: false, reason: "missing" };
    }

    return {
      ok: false,
      reason: error?.code ? `stat_failed:${error.code}` : "stat_failed",
    };
  }
}

async function parseEml(filePath: string) {
  const raw = await fs.readFile(filePath);

  if (!raw || raw.length === 0) {
    throw new Error(`Empty .eml file: ${filePath}`);
  }

  const parsed = await simpleParser(raw);

  const fromValue = parsed.from?.value?.[0];
  const fromAddress = fromValue?.address?.trim().toLowerCase() ?? "";
  const fromName = fromValue?.name?.trim() ?? "";
  const fromRaw =
    parsed.headers.get("from")?.toString() ??
    [fromName, fromAddress].filter(Boolean).join(" ");

  const subjectRaw = parsed.subject ?? "";
  const textPart = parsed.text?.trim() ?? "";
  const htmlPart = parsed.html ? String(parsed.html) : "";
  const bodyRaw = textPart
    ? textPart
    : htmlPart
      ? htmlToText(htmlPart, {
          wordwrap: false,
          selectors: [{ selector: "a", options: { ignoreHref: true } }],
        })
      : "";

  if (!subjectRaw && !bodyRaw && !fromRaw) {
    throw new Error(`Malformed or blank .eml content: ${filePath}`);
  }

  return {
    fromRaw,
    fromAddress,
    fromName,
    fromDomain: fromAddress.includes("@") ? fromAddress.split("@")[1] : "",
    subjectRaw,
    bodyRaw,
  };
}
function makeDedupeKey(
  fromDomain: string,
  subject: string,
  body: string,
): string {
  const firstBody = body.slice(0, 250);
  const basis = `${fromDomain}\n${subject}\n${firstBody}`;
  return stableHash(basis);
}

async function main() {
  const args = parseArgs(process.argv);
  await ensureDir(args.outDir);

  const userEmails = (
    await readLines(path.join(args.configDir, "user-emails.txt"))
  ).map((s) => s.toLowerCase());
  const userNames = await readLines(
    path.join(args.configDir, "user-names.txt"),
  );
  const leakedPasswords = await readLines(
    path.join(args.configDir, "leaked-passwords.txt"),
  );
  const replacements = await readJson<ReplacementConfig>(
    path.join(args.configDir, "replacements.json"),
    {
      subjectPrefixes: [],
      subjectContains: [],
      bodyContains: [],
    },
  );

  const emailRegex = buildWordRegex(userEmails);
  const nameRegex = buildWordRegex(userNames);
  const passwordRegex = buildWordRegex(leakedPasswords);

  const subjectPrefixRegex =
    replacements.subjectPrefixes.length > 0
      ? new RegExp(
          `^(?:\\s*(?:${replacements.subjectPrefixes
            .map(escapeRegex)
            .join("|")})\\s*)+`,
          "i",
        )
      : null;

  const hamFiles = await walkEmlFiles(args.hamDir);
  const spamFiles = await walkEmlFiles(args.spamDir);

  const allFiles: Array<{ file: string; label: Label }> = [
    ...hamFiles.map((file) => ({ file, label: "ham" as const })),
    ...spamFiles.map((file) => ({ file, label: "spam" as const })),
  ];

  const dataset: PreparedEmail[] = [];
  const seenDedupe = new Set<string>();

  const skippedFiles: Array<{
    file: string;
    label: Label;
    reason: string;
  }> = [];

  const stats = {
    total: 0,
    ham: 0,
    spam: 0,
    deduped: 0,
    skipped: 0,
    skippedByReason: {} as Record<string, number>,
    parseErrors: 0,
    train: 0,
    valid: 0,
    test: 0,
    redactions: {
      userEmailCount: 0,
      userNameCount: 0,
      leakedPasswordCount: 0,
      providerMarkerCount: 0,
      configuredPhraseCount: 0,
    },
  };

  for (const item of allFiles) {
    const fileCheck = await checkReadableNonEmptyFile(item.file);

    if (!fileCheck.ok) {
      const reason = fileCheck.reason ?? "unknown";
      skippedFiles.push({
        file: item.file,
        label: item.label,
        reason,
      });
      stats.skipped += 1;
      stats.skippedByReason[reason] = (stats.skippedByReason[reason] ?? 0) + 1;
      console.warn(`Skipping ${item.file}: ${reason}`);
      continue;
    }

    let parsed;
    try {
      parsed = await parseEml(item.file);
    } catch (error: any) {
      const reason = error?.message || "parse_failed";
      skippedFiles.push({
        file: item.file,
        label: item.label,
        reason,
      });
      stats.skipped += 1;
      stats.parseErrors += 1;
      stats.skippedByReason["parse_failed"] =
        (stats.skippedByReason["parse_failed"] ?? 0) + 1;
      console.warn(`Skipping ${item.file}: ${reason}`);
      continue;
    }

    const originalSubject = cleanText(parsed.subjectRaw);
    let cleanSubject = originalSubject;
    let cleanBody = cleanText(stripQuotedReplies(parsed.bodyRaw));

    let providerMarkerCount = 0;
    let configuredPhraseCount = 0;
    let userEmailCount = 0;
    let userNameCount = 0;
    let leakedPasswordCount = 0;

    if (subjectPrefixRegex) {
      const match = cleanSubject.match(subjectPrefixRegex);
      if (match) {
        providerMarkerCount += 1;
        cleanSubject = cleanSubject.replace(
          subjectPrefixRegex,
          "__PROVIDER_SPAM_MARKER__ ",
        );
      }
    }

    for (const phrase of replacements.subjectContains) {
      const rx = new RegExp(escapeRegex(phrase), "gi");
      const result = replaceAllWithCount(
        cleanSubject,
        rx,
        "__CONFIGURED_WARNING_PHRASE__",
      );
      cleanSubject = result.text;
      configuredPhraseCount += result.count;
    }

    for (const phrase of replacements.bodyContains) {
      const rx = new RegExp(escapeRegex(phrase), "gi");
      const result = replaceAllWithCount(
        cleanBody,
        rx,
        "__CONFIGURED_WARNING_PHRASE__",
      );
      cleanBody = result.text;
      configuredPhraseCount += result.count;
    }

    if (emailRegex) {
      const subjectResult = replaceAllWithCount(
        cleanSubject,
        emailRegex,
        "__USER_EMAIL__",
      );
      cleanSubject = subjectResult.text;
      userEmailCount += subjectResult.count;

      const bodyResult = replaceAllWithCount(
        cleanBody,
        emailRegex,
        "__USER_EMAIL__",
      );
      cleanBody = bodyResult.text;
      userEmailCount += bodyResult.count;
    }

    if (nameRegex) {
      const subjectResult = replaceAllWithCount(
        cleanSubject,
        nameRegex,
        "__USER_NAME__",
      );
      cleanSubject = subjectResult.text;
      userNameCount += subjectResult.count;

      const bodyResult = replaceAllWithCount(
        cleanBody,
        nameRegex,
        "__USER_NAME__",
      );
      cleanBody = bodyResult.text;
      userNameCount += bodyResult.count;
    }

    if (passwordRegex) {
      const subjectResult = replaceAllWithCount(
        cleanSubject,
        passwordRegex,
        "__LEAKED_PASSWORD__",
      );
      cleanSubject = subjectResult.text;
      leakedPasswordCount += subjectResult.count;

      const bodyResult = replaceAllWithCount(
        cleanBody,
        passwordRegex,
        "__LEAKED_PASSWORD__",
      );
      cleanBody = bodyResult.text;
      leakedPasswordCount += bodyResult.count;
    }

    cleanSubject = cleanText(cleanSubject);
    cleanBody = cleanText(cleanBody);

    const dedupeKey = makeDedupeKey(parsed.fromDomain, cleanSubject, cleanBody);
    if (seenDedupe.has(dedupeKey)) {
      stats.deduped += 1;
      continue;
    }
    seenDedupe.add(dedupeKey);

    const split = chooseSplit(dedupeKey, args.trainPct, args.validPct);

    const record: PreparedEmail = {
      id: stableHash(item.file),
      label: item.label,
      sourcePath: item.file,
      split,
      dedupeKey,
      from: {
        raw: parsed.fromRaw,
        address: parsed.fromAddress,
        name: parsed.fromName,
        domain: parsed.fromDomain,
      },
      subject: {
        raw: originalSubject,
        clean: cleanSubject,
      },
      body: {
        raw: parsed.bodyRaw,
        clean: cleanBody,
        length: cleanBody.length,
        urlCount: countUrls(cleanBody),
      },
      flags: {
        hadProviderSpamMarker: providerMarkerCount > 0,
        hadUserEmail: userEmailCount > 0,
        hadUserName: userNameCount > 0,
        hadLeakedPassword: leakedPasswordCount > 0,
        hadConfiguredSpamPhrase:
          configuredPhraseCount > 0 ||
          lowerIncludesAny(originalSubject, replacements.subjectContains) ||
          lowerIncludesAny(parsed.bodyRaw, replacements.bodyContains),
      },
      redactions: {
        userEmailCount,
        userNameCount,
        leakedPasswordCount,
        providerMarkerCount,
        configuredPhraseCount,
      },
      modelText: [
        `from_address=${parsed.fromAddress || "__NONE__"}`,
        `from_domain=${parsed.fromDomain || "__NONE__"}`,
        `from_name=${parsed.fromName || "__NONE__"}`,
        `subject=${cleanSubject || "__EMPTY__"}`,
        `body=${cleanBody || "__EMPTY__"}`,
      ].join("\n"),
    };

    dataset.push(record);

    stats.total += 1;
    stats[item.label] += 1;
    stats[split] += 1;
    stats.redactions.userEmailCount += userEmailCount;
    stats.redactions.userNameCount += userNameCount;
    stats.redactions.leakedPasswordCount += leakedPasswordCount;
    stats.redactions.providerMarkerCount += providerMarkerCount;
    stats.redactions.configuredPhraseCount += configuredPhraseCount;
  }

  const train = dataset.filter((x) => x.split === "train");
  const valid = dataset.filter((x) => x.split === "valid");
  const test = dataset.filter((x) => x.split === "test");

  async function writeJsonl(filePath: string, rows: unknown[]) {
    const content = rows.map((r) => JSON.stringify(r)).join("\n") + "\n";
    await fs.writeFile(filePath, content, "utf8");
  }

  await fs.writeFile(
    path.join(args.outDir, "skipped-files.json"),
    JSON.stringify(skippedFiles, null, 2),
    "utf8",
  );

  await writeJsonl(path.join(args.outDir, "dataset.jsonl"), dataset);
  await writeJsonl(path.join(args.outDir, "train.jsonl"), train);
  await writeJsonl(path.join(args.outDir, "valid.jsonl"), valid);
  await writeJsonl(path.join(args.outDir, "test.jsonl"), test);
  await fs.writeFile(
    path.join(args.outDir, "stats.json"),
    JSON.stringify(stats, null, 2),
    "utf8",
  );

  console.log(`Prepared ${stats.total} emails`);
  console.log(
    `Ham: ${stats.ham}, Spam: ${stats.spam}, Deduped: ${stats.deduped}, Skipped: ${stats.skipped}`,
  );
  console.log(
    `Train: ${stats.train}, Valid: ${stats.valid}, Test: ${stats.test}`,
  );
  console.log(`Output written to ${args.outDir}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
