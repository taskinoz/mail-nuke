from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from email import policy
from email.parser import BytesParser

import joblib
from dotenv import load_dotenv
from imapclient import IMAPClient
from sklearn.metrics import confusion_matrix

from trainer.model_utils import score_raw_email
from trainer.train import extract_xy, load_jsonl


ROOT = Path(__file__).resolve().parent.parent
MODEL = ROOT / "models" / "spam_filter.joblib"
CANDIDATE = ROOT / "models" / "spam_filter.candidate.joblib"
FEEDBACK_DIR = ROOT / "exports" / "spam" / "feedback"
STATE_FILE = ROOT / "state" / "weekly-retrain.json"
OBSERVED_DIR = ROOT / "state" / "retrain-observed"
OBSERVED_FILE = ROOT / "state" / "retrain-observed.json"


@dataclass(frozen=True)
class Metrics:
    spam_recall: float
    ham_false_positive_rate: float


def read_json(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return fallback


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    except FileNotFoundError:
        return []


def marked_signatures(log_path: Path, marks_path: Path) -> set[tuple[str, str]]:
    if not str(marks_path):
        return set()
    marks = read_json(marks_path, {})
    marked_keys = {key for key, value in marks.items() if value.get("mark") == "false_negative"}
    return {
        (str(row.get("from", "")).casefold(), str(row.get("subject", "")).casefold())
        for row in read_jsonl(log_path)
        if f'{row.get("ts")}__{row.get("uid")}' in marked_keys
    }


def automatically_moved_ids(log_path: Path) -> set[str]:
    return {
        str(row["messageId"]).casefold()
        for row in read_jsonl(log_path)
        if row.get("action") == "moved_to_spam" and row.get("messageId")
    }


def evaluate(artifact_path: Path, threshold: float) -> Metrics:
    artifact = joblib.load(artifact_path)
    test = load_jsonl(ROOT / "prepared" / "test.jsonl")
    x_test, y_test = extract_xy(test)
    probabilities = artifact["pipeline"].predict_proba(x_test)
    spam_index = list(artifact["classes"]).index("spam")
    predictions = ["spam" if score >= threshold else "ham" for score in probabilities[:, spam_index]]
    tn, fp, fn, tp = confusion_matrix(y_test, predictions, labels=["ham", "spam"]).ravel()
    return Metrics(
        spam_recall=tp / (tp + fn) if tp + fn else 0.0,
        ham_false_positive_rate=fp / (fp + tn) if fp + tn else 0.0,
    )


def should_promote(current: Metrics, candidate: Metrics, fp_tolerance: float) -> bool:
    return (
        candidate.spam_recall >= current.spam_recall
        and candidate.ham_false_positive_rate <= current.ham_false_positive_rate + fp_tolerance
    )


def connect() -> IMAPClient:
    client = IMAPClient(
        os.environ["IMAP_HOST"],
        port=int(os.getenv("IMAP_PORT", "993")),
        ssl=os.getenv("IMAP_USE_SSL", "true").casefold() in {"1", "true", "yes", "on"},
        use_uid=True,
    )
    client.login(os.environ["IMAP_USERNAME"], os.environ["IMAP_PASSWORD"])
    return client


def message_id(raw: bytes) -> str:
    message = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
    return str(message["message-id"] or "").strip().casefold()


def folder_messages(client: IMAPClient, folder: str) -> dict[str, tuple[int, bytes]]:
    client.select_folder(folder, readonly=True)
    result: dict[str, tuple[int, bytes]] = {}
    for uid in (int(value) for value in client.search(["ALL"])):
        item = client.fetch([uid], ["RFC822"]).get(uid, {})
        raw = item.get(b"RFC822") or item.get("RFC822")
        if isinstance(raw, bytes):
            identifier = message_id(raw)
            if identifier:
                result[identifier] = (uid, raw)
    return result


def relabel_restored(identifier: str, record: dict[str, Any]) -> bool:
    digest = str(record["digest"])
    observed = OBSERVED_DIR / f"{digest}.eml"
    if not observed.exists():
        return False
    spam_path = FEEDBACK_DIR / f"{digest}.eml"
    ham_dir = ROOT / "exports" / "ham" / "feedback"
    ham_dir.mkdir(parents=True, exist_ok=True)
    ham_path = ham_dir / f"{digest}.eml"
    spam_path.unlink(missing_ok=True)
    shutil.copy2(observed, ham_path)
    record.update({"label": "ham", "message_id": identifier})
    return True


def collect_feedback() -> int:
    log_path = ROOT / os.getenv("ACTION_LOG_PATH", "logs/imap-actions.jsonl")
    marks_value = os.getenv("DASHBOARD_MARKS_FILE", "").strip()
    marks_path = Path(marks_value) if marks_value else Path("__dashboard_disabled__")
    marked = marked_signatures(log_path, marks_path)
    auto_moved = automatically_moved_ids(log_path)
    state = read_json(STATE_FILE, {})
    observed: dict[str, dict[str, Any]] = read_json(OBSERVED_FILE, {})
    client = connect()
    try:
        folder = os.getenv("IMAP_SPAM_FOLDER", "Junk")
        selected = client.select_folder(folder, readonly=True)
        uid_validity = int(selected.get(b"UIDVALIDITY", selected.get("UIDVALIDITY", 0)))
        spam_messages = folder_messages(client, folder)
        changed = 0
        max_uid = max((uid for uid, _ in spam_messages.values()), default=0)
        FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)
        OBSERVED_DIR.mkdir(parents=True, exist_ok=True)
        for identifier, (uid, raw) in spam_messages.items():
            if identifier in observed:
                continue
            scored = score_raw_email(raw, threshold_override=float(os.getenv("SPAM_THRESHOLD", "0.9")))
            signature = (scored["from_header"].casefold(), scored["subject"].casefold())
            digest = hashlib.sha256(raw).hexdigest()
            (OBSERVED_DIR / f"{digest}.eml").write_bytes(raw)
            is_miss = scored["label"] == "ham" or signature in marked
            observed[identifier] = {"digest": digest, "label": "spam" if is_miss else "observed", "uid": uid}
            if is_miss and identifier not in auto_moved:
                (FEEDBACK_DIR / f"{digest}.eml").write_bytes(raw)
                changed += 1

        restored_folder = os.getenv("IMAP_FALSE_POSITIVE_FOLDER", os.getenv("IMAP_SOURCE_FOLDER", "INBOX"))
        inbox_ids = set(folder_messages(client, restored_folder))
        spam_ids = set(spam_messages)
        for identifier in sorted(inbox_ids - spam_ids):
            record = observed.get(identifier)
            if record and record.get("label") != "ham" and relabel_restored(identifier, record):
                changed += 1

        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps({"uid_validity": uid_validity, "last_uid": max_uid}, indent=2), encoding="utf-8")
        OBSERVED_FILE.write_text(json.dumps(observed, indent=2), encoding="utf-8")
        return changed
    finally:
        client.logout()


def main() -> None:
    load_dotenv(ROOT / ".env")
    added = collect_feedback()
    if added == 0:
        print("No new false negatives or restored false positives; keeping the current model.")
        return
    subprocess.run(["bun", "run", "prepare"], cwd=ROOT, check=True)
    subprocess.run(["uv", "run", "python", "-m", "trainer.train", "--output", str(CANDIDATE)], cwd=ROOT, check=True)
    threshold = float(os.getenv("SPAM_THRESHOLD", "0.9"))
    current = evaluate(MODEL, threshold)
    candidate = evaluate(CANDIDATE, threshold)
    tolerance = float(os.getenv("RETRAIN_FP_TOLERANCE", "0.005"))
    print(f"Current: {current}")
    print(f"Candidate: {candidate}")
    if should_promote(current, candidate, tolerance):
        backup = MODEL.with_suffix(".previous.joblib")
        shutil.copy2(MODEL, backup)
        os.replace(CANDIDATE, MODEL)
        print(f"Promoted candidate model; previous model saved to {backup}.")
    else:
        CANDIDATE.unlink(missing_ok=True)
        print("Rejected candidate model because it failed the promotion gates.")


if __name__ == "__main__":
    main()
