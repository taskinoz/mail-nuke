from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Iterable
import joblib
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import html2text


MODEL_PATH = Path("models/spam_filter.joblib")

USER_EMAILS: list[str] = []
USER_NAMES: list[str] = []
LEAKED_PASSWORDS: list[str] = []
PROVIDER_PREFIXES: list[str] = ["**SPAM**", "[SPAM]", "SPAM:"]


def load_config() -> None:
    def read_lines(path: str) -> list[str]:
        p = Path(path)
        if not p.exists():
            return []
        return [
            x.strip()
            for x in p.read_text(encoding="utf-8").splitlines()
            if x.strip() and not x.strip().startswith("#")
        ]

    global USER_EMAILS, USER_NAMES, LEAKED_PASSWORDS
    USER_EMAILS = [x.lower() for x in read_lines("config/user-emails.txt")]
    USER_NAMES = read_lines("config/user-names.txt")
    LEAKED_PASSWORDS = read_lines("config/leaked-passwords.txt")


def extract_eml(path: Path) -> tuple[str, str, str]:
    with path.open("rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    subject = str(msg["subject"] or "")
    from_header = str(msg["from"] or "")

    text_body = ""
    html_body = ""

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                continue

            content_type = part.get_content_type()

            try:
                content = part.get_content()
            except Exception:
                continue

            if content_type == "text/plain" and not text_body:
                text_body = str(content)
            elif content_type == "text/html" and not html_body:
                html_body = str(content)
    else:
        try:
            content = msg.get_content()
            if msg.get_content_type() == "text/html":
                html_body = str(content)
            else:
                text_body = str(content)
        except Exception:
            pass

    body = text_body
    if not body and html_body:
        body = html2text.html2text(html_body)

    return from_header, subject, body


def clean_text(text: str) -> str:
    text = text.replace("\u0000", " ")
    text = text.replace("\r", " ")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def strip_quoted_replies(text: str) -> str:
    lines = text.splitlines()
    kept: list[str] = []

    for line in lines:
        trimmed = line.strip()

        if (
            trimmed.startswith(">")
            or re.match(r"^on .+wrote:$", trimmed, flags=re.I)
            or re.match(r"^from:\s", trimmed, flags=re.I)
            or re.match(r"^sent:\s", trimmed, flags=re.I)
            or re.match(r"^subject:\s", trimmed, flags=re.I)
            or re.match(r"^to:\s", trimmed, flags=re.I)
        ):
            break

        kept.append(line)

    return "\n".join(kept)


def replace_all_with_count(text: str, pattern: str, replacement: str) -> tuple[str, int]:
    if not pattern:
        return text, 0
    regex = re.compile(re.escape(pattern), flags=re.I)
    count = 0

    def repl(_: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return replacement

    return regex.sub(repl, text), count


def strip_provider_prefix(subject: str) -> tuple[str, int]:
    count = 0
    updated = subject

    changed = True
    while changed:
        changed = False
        for prefix in PROVIDER_PREFIXES:
            pattern = r"^\s*" + re.escape(prefix) + r"\s*"
            if re.search(pattern, updated, flags=re.I):
                updated = re.sub(
                    pattern,
                    "__PROVIDER_SPAM_MARKER__ ",
                    updated,
                    count=1,
                    flags=re.I,
                )
                count += 1
                changed = True

    return updated, count


def redact(text: str) -> tuple[str, dict[str, int]]:
    counts = {
        "user_email_count": 0,
        "user_name_count": 0,
        "leaked_password_count": 0,
    }

    updated = text

    for email in USER_EMAILS:
        updated, c = replace_all_with_count(updated, email, "__USER_EMAIL__")
        counts["user_email_count"] += c

    for name in USER_NAMES:
        updated, c = replace_all_with_count(updated, name, "__USER_NAME__")
        counts["user_name_count"] += c

    for pw in LEAKED_PASSWORDS:
        updated, c = replace_all_with_count(updated, pw, "__LEAKED_PASSWORD__")
        counts["leaked_password_count"] += c

    return updated, counts


def parse_from_header(from_header: str) -> tuple[str, str, str]:
    name, address = parseaddr(from_header)
    address = address.strip().lower()
    name = name.strip()
    domain = address.split("@", 1)[1] if "@" in address else ""
    return name, address, domain


def build_model_text(from_header: str, subject: str, body: str) -> tuple[str, dict[str, int | bool]]:
    provider_clean_subject, provider_count = strip_provider_prefix(subject)

    body = strip_quoted_replies(body)

    subject_redacted, subject_counts = redact(provider_clean_subject)
    body_redacted, body_counts = redact(body)

    subject_clean = clean_text(subject_redacted)
    body_clean = clean_text(body_redacted)

    from_name, from_address, from_domain = parse_from_header(from_header)

    model_text = "\n".join(
        [
            f"from_address={from_address or '__NONE__'}",
            f"from_domain={from_domain or '__NONE__'}",
            f"from_name={from_name or '__NONE__'}",
            f"subject={subject_clean or '__EMPTY__'}",
            f"body={body_clean or '__EMPTY__'}",
        ]
    )

    meta: dict[str, int | bool] = {
        "provider_marker_count": provider_count,
        "user_email_count": subject_counts["user_email_count"] + body_counts["user_email_count"],
        "user_name_count": subject_counts["user_name_count"] + body_counts["user_name_count"],
        "leaked_password_count": subject_counts["leaked_password_count"] + body_counts["leaked_password_count"],
        "had_provider_marker": provider_count > 0,
        "had_user_email": (subject_counts["user_email_count"] + body_counts["user_email_count"]) > 0,
        "had_user_name": (subject_counts["user_name_count"] + body_counts["user_name_count"]) > 0,
        "had_leaked_password": (subject_counts["leaked_password_count"] + body_counts["leaked_password_count"]) > 0,
    }

    return model_text, meta


def load_model():
    artifact = joblib.load(MODEL_PATH)
    return artifact["pipeline"], artifact["threshold"], artifact["classes"]


def score_text(model_text: str, pipeline, threshold: float, classes: list[str]) -> tuple[str, float]:
    probs = pipeline.predict_proba([model_text])[0]
    spam_idx = classes.index("spam")
    spam_score = float(probs[spam_idx])
    label = "spam" if spam_score >= threshold else "ham"
    return label, spam_score


def infer_expected_label(path: Path) -> str | None:
    parts = [p.lower() for p in path.parts]
    if "spam" in parts or "junk" in parts:
        return "spam"
    if "ham" in parts or "inbox" in parts:
        return "ham"
    return None


def iter_eml_files(folder: Path) -> Iterable[Path]:
    yield from sorted(p for p in folder.rglob("*.eml") if p.is_file())


def score_eml_file(
    eml_path: Path,
    pipeline,
    threshold: float,
    classes: list[str],
) -> dict:
    from_header, subject, body = extract_eml(eml_path)
    model_text, meta = build_model_text(from_header, subject, body)
    label, spam_score = score_text(model_text, pipeline, threshold, classes)
    expected = infer_expected_label(eml_path)

    return {
        "file": str(eml_path),
        "predictedLabel": label,
        "spamScore": round(spam_score, 6),
        "threshold": threshold,
        "expectedLabel": expected,
        "correct": None if expected is None else expected == label,
        "meta": meta,
        "subject": subject,
        "from": from_header,
        "modelText": model_text,
    }


def run_folder_scan(
    folder: Path,
    pipeline,
    threshold: float,
    classes: list[str],
    json_output: bool = False,
    save_path: Path | None = None,
) -> None:
    files = list(iter_eml_files(folder))
    if not files:
        print(f"No .eml files found in {folder}")
        return

    results = [score_eml_file(f, pipeline, threshold, classes) for f in files]

    if save_path:
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in results) + "\n",
            encoding="utf-8",
        )

    if json_output:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return

    counts = Counter(r["predictedLabel"] for r in results)

    labelled = [r for r in results if r["expectedLabel"] is not None]
    correct = sum(1 for r in labelled if r["correct"] is True)
    incorrect = sum(1 for r in labelled if r["correct"] is False)

    false_positives = [
        r for r in labelled
        if r["expectedLabel"] == "ham" and r["predictedLabel"] == "spam"
    ]
    false_negatives = [
        r for r in labelled
        if r["expectedLabel"] == "spam" and r["predictedLabel"] == "ham"
    ]

    print(f"Scanned: {len(results)} files")
    print(f"Predicted ham: {counts.get('ham', 0)}")
    print(f"Predicted spam: {counts.get('spam', 0)}")

    if labelled:
        print(f"Labelled files: {len(labelled)}")
        print(f"Correct: {correct}")
        print(f"Incorrect: {incorrect}")
        print(f"False positives: {len(false_positives)}")
        print(f"False negatives: {len(false_negatives)}")

    print("\nPer-file results:")
    for r in results:
        expected = r["expectedLabel"] or "-"
        mark = "✓" if r["correct"] is True else ("✗" if r["correct"] is False else " ")
        print(
            f"{mark} score={r['spamScore']:.6f} predicted={r['predictedLabel']:<4} "
            f"expected={expected:<4} file={r['file']}"
        )

    if false_positives:
        print("\nTop false positives:")
        for r in sorted(false_positives, key=lambda x: x["spamScore"], reverse=True)[:10]:
            print(f"- {r['spamScore']:.6f} | {r['file']}")
            print(f"  From: {r['from']}")
            print(f"  Subject: {r['subject']}")

    if false_negatives:
        print("\nTop false negatives:")
        for r in sorted(false_negatives, key=lambda x: x["spamScore"])[:10]:
            print(f"- {r['spamScore']:.6f} | {r['file']}")
            print(f"  From: {r['from']}")
            print(f"  Subject: {r['subject']}")

    if save_path:
        print(f"\nSaved scan results to {save_path}")


def main() -> None:
    load_config()
    pipeline, threshold, classes = load_model()

    parser = argparse.ArgumentParser()
    parser.add_argument("--text", help="modelText input")
    parser.add_argument("--eml", help="Path to .eml file")
    parser.add_argument("--folder", help="Path to folder containing .eml files")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON output for --eml or --folder",
    )
    parser.add_argument(
        "--save",
        help="Optional path to save scan results as JSONL in folder mode",
    )

    args = parser.parse_args()

    supplied = [bool(args.text), bool(args.eml), bool(args.folder)]
    if sum(supplied) != 1:
        raise SystemExit("Provide exactly one of --text, --eml, or --folder")

    if args.folder:
        run_folder_scan(
            folder=Path(args.folder),
            pipeline=pipeline,
            threshold=threshold,
            classes=classes,
            json_output=args.json,
            save_path=Path(args.save) if args.save else None,
        )
        return

    if args.eml:
        from_header, subject, body = extract_eml(Path(args.eml))
        model_text, meta = build_model_text(from_header, subject, body)
    else:
        model_text = args.text
        meta = {}

    label, spam_score = score_text(model_text, pipeline, threshold, classes)

    output = {
        "label": label,
        "spamScore": round(spam_score, 6),
        "threshold": threshold,
        "modelText": model_text,
        "meta": meta,
    }

    if args.json:
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(output, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()