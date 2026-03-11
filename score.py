from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
import joblib
from email import policy
from email.parser import BytesParser
import html2text


MODEL_PATH = Path("models/spam_filter.joblib")

USER_EMAILS = []
USER_NAMES = []
LEAKED_PASSWORDS = []

PROVIDER_PREFIXES = ["**SPAM**", "[SPAM]", "SPAM:"]


def load_config():
    def read_lines(path):
        p = Path(path)
        if not p.exists():
            return []
        return [x.strip() for x in p.read_text().splitlines() if x.strip()]

    global USER_EMAILS, USER_NAMES, LEAKED_PASSWORDS

    USER_EMAILS = [x.lower() for x in read_lines("config/user-emails.txt")]
    USER_NAMES = read_lines("config/user-names.txt")
    LEAKED_PASSWORDS = read_lines("config/leaked-passwords.txt")


def extract_eml(path: Path):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    subject = msg["subject"] or ""
    from_header = msg["from"] or ""

    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()

            if content_type == "text/plain":
                body = part.get_content()
                break

            if content_type == "text/html" and not body:
                html = part.get_content()
                body = html2text.html2text(html)

    else:
        body = msg.get_content()

    return from_header, subject, body


def clean_text(text: str):
    text = text.replace("\r", " ")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def redact(text: str):
    for email in USER_EMAILS:
        text = re.sub(re.escape(email), "__USER_EMAIL__", text, flags=re.I)

    for name in USER_NAMES:
        text = re.sub(re.escape(name), "__USER_NAME__", text, flags=re.I)

    for pw in LEAKED_PASSWORDS:
        text = re.sub(re.escape(pw), "__LEAKED_PASSWORD__", text, flags=re.I)

    return text


def strip_provider_prefix(subject: str):
    for p in PROVIDER_PREFIXES:
        if subject.startswith(p):
            subject = subject.replace(p, "__PROVIDER_SPAM_MARKER__", 1)
    return subject


def build_model_text(from_header, subject, body):
    subject = strip_provider_prefix(subject)

    subject = redact(subject)
    body = redact(body)

    subject = clean_text(subject)
    body = clean_text(body)

    domain = ""
    address = ""

    m = re.search(r"<(.+?)>", from_header)
    if m:
        address = m.group(1).lower()

    if "@" in address:
        domain = address.split("@")[1]

    return "\n".join(
        [
            f"from_address={address or '__NONE__'}",
            f"from_domain={domain or '__NONE__'}",
            f"from_name={from_header}",
            f"subject={subject}",
            f"body={body}",
        ]
    )


def score_text(model_text: str):
    artifact = joblib.load(MODEL_PATH)

    pipeline = artifact["pipeline"]
    threshold = artifact["threshold"]
    classes = artifact["classes"]

    probs = pipeline.predict_proba([model_text])[0]

    spam_idx = classes.index("spam")

    spam_score = float(probs[spam_idx])

    label = "spam" if spam_score >= threshold else "ham"

    return label, spam_score, threshold


def main():
    load_config()

    parser = argparse.ArgumentParser()

    parser.add_argument("--text", help="modelText input")
    parser.add_argument("--eml", help="Path to .eml file")

    args = parser.parse_args()

    if not args.text and not args.eml:
        print("Provide either --text or --eml")
        return

    if args.eml:
        eml_path = Path(args.eml)

        from_header, subject, body = extract_eml(eml_path)

        model_text = build_model_text(from_header, subject, body)

    else:
        model_text = args.text

    label, spam_score, threshold = score_text(model_text)

    print(
        json.dumps(
            {
                "label": label,
                "spamScore": round(spam_score, 6),
                "threshold": threshold,
                "modelText": model_text,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()