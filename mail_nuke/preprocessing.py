from __future__ import annotations

import json
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Any

import html2text

from mail_nuke.database import Database
from mail_nuke.security import SecretCipher


EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.I)
PROVIDER_PREFIXES = ("**SPAM**", "[SPAM]", "SPAM:")


def _literal_replace(text: str, values: list[str], token: str) -> tuple[str, int]:
    cleaned = sorted({value.strip() for value in values if value.strip()}, key=len, reverse=True)
    if not cleaned:
        return text, 0
    expression = re.compile("|".join(re.escape(value) for value in cleaned), re.I)
    return expression.subn(token, text)


def _strip_quoted_replies(text: str) -> str:
    kept = []
    for line in text.splitlines():
        trimmed = line.strip()
        if (
            trimmed.startswith(">")
            or re.match(r"^on .+wrote:$", trimmed, re.I)
            or re.match(r"^(from|sent|subject|to):\s", trimmed, re.I)
        ):
            break
        kept.append(line)
    return "\n".join(kept)


def _body(parsed) -> str:
    text_body = ""
    html_body = ""
    parts = parsed.walk() if parsed.is_multipart() else [parsed]
    for part in parts:
        if part.get_content_disposition() == "attachment":
            continue
        try:
            content = part.get_content()
        except Exception:
            continue
        if part.get_content_type() == "text/plain" and not text_body:
            text_body = str(content)
        elif part.get_content_type() == "text/html" and not html_body:
            html_body = str(content)
    return text_body or (html2text.html2text(html_body) if html_body else "")


def load_group_profile(database: Database, cipher: SecretCipher, group_id: str) -> dict[str, Any]:
    profile = database.get_privacy_profile(group_id)
    if profile is None:
        raise RuntimeError("Model group has no privacy profile")
    ciphertext = profile.pop("known_secrets_ciphertext", None)
    profile["known_secrets"] = json.loads(cipher.decrypt(ciphertext)) if ciphertext else []
    profile["account_emails"] = database.group_email_addresses(group_id)
    return profile


def preprocess_email(raw: bytes, profile: dict[str, Any]) -> dict[str, Any]:
    parsed = BytesParser(policy=policy.default).parsebytes(raw)
    from_header = str(parsed.get("From") or "")
    subject = str(parsed.get("Subject") or "")
    body = _strip_quoted_replies(_body(parsed))

    provider_count = 0
    for prefix in PROVIDER_PREFIXES:
        expression = re.compile(r"^\s*" + re.escape(prefix) + r"\s*", re.I)
        if expression.search(subject):
            subject = expression.sub("__PROVIDER_SPAM_MARKER__ ", subject, count=1)
            provider_count += 1

    emails = list(profile.get("account_emails", [])) + list(profile.get("custom_emails", []))
    subject, subject_email_count = _literal_replace(subject, emails, "__GROUP_ACCOUNT_EMAIL__")
    body, body_email_count = _literal_replace(body, emails, "__GROUP_ACCOUNT_EMAIL__")
    subject, subject_name_count = _literal_replace(subject, profile.get("user_names", []), "__USER_NAME__")
    body, body_name_count = _literal_replace(body, profile.get("user_names", []), "__USER_NAME__")
    subject, subject_secret_count = _literal_replace(subject, profile.get("known_secrets", []), "__KNOWN_SECRET__")
    body, body_secret_count = _literal_replace(body, profile.get("known_secrets", []), "__KNOWN_SECRET__")

    other_email_count = 0
    if profile.get("normalize_other_emails"):
        subject, count = EMAIL_PATTERN.subn("__OTHER_EMAIL__", subject)
        other_email_count += count
        body, count = EMAIL_PATTERN.subn("__OTHER_EMAIL__", body)
        other_email_count += count

    subject = re.sub(r"\s+", " ", subject.replace("\x00", " ")).strip()
    body = re.sub(r"\s+", " ", body.replace("\x00", " ")).strip()
    from_name, from_address = parseaddr(from_header)
    from_domain = from_address.casefold().rsplit("@", 1)[1] if "@" in from_address else ""
    safe_from_address, from_email_count = _literal_replace(
        from_address.casefold(), emails, "__GROUP_ACCOUNT_EMAIL__"
    )
    safe_from_name, from_name_count = _literal_replace(
        from_name.strip(), profile.get("user_names", []), "__USER_NAME__"
    )
    if profile.get("normalize_other_emails"):
        safe_from_address, count = EMAIL_PATTERN.subn("__OTHER_EMAIL__", safe_from_address)
        other_email_count += count
    model_text = "\n".join(
        [
            f"from_address={safe_from_address or '__NONE__'}",
            f"from_domain={from_domain or '__NONE__'}",
            f"from_name={safe_from_name or '__NONE__'}",
            f"subject={subject or '__EMPTY__'}",
            f"body={body or '__EMPTY__'}",
        ]
    )
    return {
        "model_text": model_text,
        "preprocessing_version": int(profile["version"]),
        "privacy_counts": {
            "group_email": subject_email_count + body_email_count + from_email_count,
            "user_name": subject_name_count + body_name_count + from_name_count,
            "known_secret": subject_secret_count + body_secret_count,
            "other_email": other_email_count,
            "provider_marker": provider_count,
        },
    }
