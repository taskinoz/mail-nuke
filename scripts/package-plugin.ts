#!/usr/bin/env bun
import {
  mkdir,
  readFile,
  readdir,
  stat,
  createWriteStream,
} from "node:fs/promises";
import {
  existsSync,
  createWriteStream as createNodeWriteStream,
} from "node:fs";
import path from "node:path";
import yazl from "yazl";

type Manifest = {
  name?: string;
  version?: string;
  browser_specific_settings?: {
    gecko?: {
      id?: string;
    };
  };
};

const ROOT = process.cwd();
const PLUGIN_DIR = path.join(ROOT, "plugin");
const DIST_DIR = path.join(ROOT, "dist");

const EXCLUDED_NAMES = new Set([".DS_Store", "Thumbs.db"]);

const EXCLUDED_DIRS = new Set([".git", "node_modules", "dist"]);

function slugify(input: string): string {
  return input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

async function readManifest(): Promise<Manifest> {
  const manifestPath = path.join(PLUGIN_DIR, "manifest.json");

  if (!existsSync(manifestPath)) {
    throw new Error(`manifest.json not found at ${manifestPath}`);
  }

  const raw = await readFile(manifestPath, "utf8");
  return JSON.parse(raw) as Manifest;
}

async function walkFiles(dir: string, baseDir = dir): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const files: string[] = [];

  for (const entry of entries) {
    if (EXCLUDED_NAMES.has(entry.name)) continue;

    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(baseDir, fullPath);

    if (entry.isDirectory()) {
      if (EXCLUDED_DIRS.has(entry.name)) continue;
      files.push(...(await walkFiles(fullPath, baseDir)));
      continue;
    }

    if (!entry.isFile()) continue;

    if (entry.name.endsWith(".map") || entry.name.endsWith(".log")) continue;

    files.push(relPath);
  }

  return files.sort();
}

async function validatePluginDir() {
  const required = [
    path.join(PLUGIN_DIR, "manifest.json"),
    path.join(PLUGIN_DIR, "background.js"),
  ];

  for (const file of required) {
    if (!existsSync(file)) {
      throw new Error(`Required file missing: ${file}`);
    }
  }
}

async function packagePlugin() {
  if (!existsSync(PLUGIN_DIR)) {
    throw new Error(`Plugin directory not found: ${PLUGIN_DIR}`);
  }

  await validatePluginDir();

  const manifest = await readManifest();
  const version = manifest.version || "0.0.0";

  const baseName =
    manifest.browser_specific_settings?.gecko?.id ||
    manifest.name ||
    "thunderbird-plugin";

  const outputName = `${slugify(baseName)}-v${version}.xpi`;
  const outputPath = path.join(DIST_DIR, outputName);

  await mkdir(DIST_DIR, { recursive: true });

  const files = await walkFiles(PLUGIN_DIR);
  if (files.length === 0) {
    throw new Error("No files found in plugin directory");
  }

  const zipfile = new yazl.ZipFile();
  const outStream = createNodeWriteStream(outputPath);

  zipfile.outputStream.pipe(outStream);

  for (const relPath of files) {
    const absPath = path.join(PLUGIN_DIR, relPath);
    zipfile.addFile(absPath, relPath.replaceAll("\\", "/"));
  }

  zipfile.end();

  await new Promise<void>((resolve, reject) => {
    outStream.on("close", resolve);
    outStream.on("error", reject);
    zipfile.outputStream.on("error", reject);
  });

  console.log(`Packaged plugin: ${outputPath}`);
  console.log(`Files included: ${files.length}`);
}

packagePlugin().catch((error) => {
  console.error(error);
  process.exit(1);
});
