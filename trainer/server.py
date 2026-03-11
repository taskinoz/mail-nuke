from __future__ import annotations

import re
from pathlib import Path
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

import html2text
import joblib
from fastapi import FastAPI
from pydantic import BaseModel


MODEL_PATH = Path("../models/spam_filter.joblib")

USER_EMAILS = []
USER_NAMES = []
LEAKED_PASSWORDS = []

PROVIDER_PREFIXES = ["**SPAM**", "[SPAM]", "SPAM:"]

app = FastAPI()


class ScoreRequest(BaseModel):
    from_header: str | None = None
    subject: str | None = None
    body: str | None = None
    eml: str | None = None


class ScoreResponse(BaseModel):
    label: str
    spamScore: float
    threshold: float


def load_config():

    def read_lines(path):
        p = Path(path)
        if not p.exists():
            return []
        return [x.strip() for x in p.read_text().splitlines() if x.strip()]

    global USER_EMAILS, USER_NAMES, LEAKED_PASSWORDS

    USER_EMAILS = [x.lower() for x in read_lines("../config/user-emails.txt")]
    USER_NAMES = read_lines("../config/user-names.txt")
    LEAKED_PASSWORDS = read_lines("../config/leaked-passwords.txt")


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

    for prefix in PROVIDER_PREFIXES:
        subject = re.sub(
            r"^\s*" + re.escape(prefix) + r"\s*",
            "__PROVIDER_SPAM_MARKER__ ",
            subject,
            flags=re.I,
        )

    return subject


def parse_eml(raw_eml: str):

    msg = BytesParser(policy=policy.default).parsebytes(raw_eml.encode())

    subject = msg["subject"] or ""
    from_header = msg["from"] or ""

    body = ""

    if msg.is_multipart():
        for part in msg.walk():

            if part.get_content_type() == "text/plain":
                body = part.get_content()
                break

            if part.get_content_type() == "text/html" and not body:
                html = part.get_content()
                body = html2text.html2text(html)

    else:
        body = msg.get_content()

    return from_header, subject, body


def build_model_text(from_header, subject, body):

    subject = strip_provider_prefix(subject)

    subject = redact(subject)
    body = redact(body)

    subject = clean_text(subject)
    body = clean_text(body)

    name, address = parseaddr(from_header)

    address = address.lower()
    domain = address.split("@")[1] if "@" in address else ""

    return "\n".join(
        [
            f"from_address={address or '__NONE__'}",
            f"from_domain={domain or '__NONE__'}",
            f"from_name={name or '__NONE__'}",
            f"subject={subject}",
            f"body={body}",
        ]
    )


@app.on_event("startup")
def load_model():

    global pipeline
    global threshold
    global classes

    artifact = joblib.load(MODEL_PATH)

    pipeline = artifact["pipeline"]
    threshold = artifact["threshold"]
    classes = artifact["classes"]

    load_config()

    print("Spam model loaded")


@app.get("/")
def health():
    return {"status": "ok"}


@app.post("/score", response_model=ScoreResponse)
def score(req: ScoreRequest):

    if req.eml:
        from_header, subject, body = parse_eml(req.eml)

    else:
        from_header = req.from_header or ""
        subject = req.subject or ""
        body = req.body or ""

    model_text = build_model_text(from_header, subject, body)

    probs = pipeline.predict_proba([model_text])[0]

    spam_idx = classes.index("spam")

    spam_score = float(probs[spam_idx])

    label = "spam" if spam_score >= threshold else "ham"

    return ScoreResponse(
        label=label,
        spamScore=spam_score,
        threshold=threshold,
    )