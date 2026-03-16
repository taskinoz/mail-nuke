from __future__ import annotations

import re
from pathlib import Path
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Any

import html2text
import joblib


ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / "models" / "spam_filter.joblib"
CONFIG_DIR = ROOT / "config"

USER_EMAILS: list[str] = []
USER_NAMES: list[str] = []
LEAKED_PASSWORDS: list[str] = []
PROVIDER_PREFIXES: list[str] = ["**SPAM**", "[SPAM]", "SPAM:"]

_PIPELINE = None
_THRESHOLD = None
_CLASSES = None


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def load_config() -> None:
    global USER_EMAILS, USER_NAMES, LEAKED_PASSWORDS
    USER_EMAILS = [x.lower() for x in read_lines(CONFIG_DIR / "user-emails.txt")]
    USER_NAMES = read_lines(CONFIG_DIR / "user-names.txt")
    LEAKED_PASSWORDS = read_lines(CONFIG_DIR / "leaked-passwords.txt")


def load_model() -> None:
    global _PIPELINE, _THRESHOLD, _CLASSES
    if _PIPELINE is not None:
        return

    artifact = joblib.load(MODEL_PATH)
    _PIPELINE = artifact["pipeline"]
    _THRESHOLD = float(artifact["threshold"])
    _CLASSES = list(artifact["classes"])


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


def extract_message_parts_from_bytes(raw_eml: bytes) -> tuple[str, str, str]:
    msg = BytesParser(policy=policy.default).parsebytes(raw_eml)

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


def build_model_text(from_header: str, subject: str, body: str) -> tuple[str, dict[str, Any]]:
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

    meta = {
        "from_name": from_name,
        "from_address": from_address,
        "from_domain": from_domain,
        "provider_marker_count": provider_count,
        "user_email_count": subject_counts["user_email_count"] + body_counts["user_email_count"],
        "user_name_count": subject_counts["user_name_count"] + body_counts["user_name_count"],
        "leaked_password_count": subject_counts["leaked_password_count"] + body_counts["leaked_password_count"],
        "had_provider_marker": provider_count > 0,
        "had_user_email": (subject_counts["user_email_count"] + body_counts["user_email_count"]) > 0,
        "had_user_name": (subject_counts["user_name_count"] + body_counts["user_name_count"]) > 0,
        "had_leaked_password": (subject_counts["leaked_password_count"] + body_counts["leaked_password_count"]) > 0,
        "subject_clean": subject_clean,
    }

    return model_text, meta


def score_model_text(model_text: str, threshold_override: float | None = None) -> dict[str, Any]:
    load_model()

    assert _PIPELINE is not None
    assert _CLASSES is not None
    assert _THRESHOLD is not None

    probs = _PIPELINE.predict_proba([model_text])[0]
    spam_idx = _CLASSES.index("spam")
    spam_score = float(probs[spam_idx])

    threshold = threshold_override if threshold_override is not None else _THRESHOLD
    label = "spam" if spam_score >= threshold else "ham"

    return {
        "label": label,
        "spamScore": spam_score,
        "threshold": threshold,
    }


def score_raw_email(raw_eml: bytes, threshold_override: float | None = None) -> dict[str, Any]:
    from_header, subject, body = extract_message_parts_from_bytes(raw_eml)
    model_text, meta = build_model_text(from_header, subject, body)
    result = score_model_text(model_text, threshold_override=threshold_override)

    return {
        **result,
        "from_header": from_header,
        "subject": subject,
        "meta": meta,
        "modelText": model_text,
    }


load_config()