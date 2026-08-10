from __future__ import annotations

import gzip
import hashlib
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from uuid import uuid4

from mail_nuke.database import Database
from mail_nuke.imap_service import connect
from mail_nuke.preprocessing import load_group_profile, preprocess_email
from mail_nuke.security import SecretCipher
from mail_nuke.scoring import ModelRuntime


BATCH_SIZE = 50
_MODEL_RUNTIMES: dict[Path, ModelRuntime] = {}


def _model_runtime(data_dir: Path) -> ModelRuntime:
    key = data_dir.resolve()
    if key not in _MODEL_RUNTIMES:
        _MODEL_RUNTIMES[key] = ModelRuntime(key)
    return _MODEL_RUNTIMES[key]


def _value(item: dict, name: str):
    return item.get(name.encode()) or item.get(name)


def _uid_validity(selected: dict) -> int:
    return int(selected.get(b"UIDVALIDITY", selected.get("UIDVALIDITY", 0)))


def parse_message(raw: bytes) -> dict:
    parsed = BytesParser(policy=policy.default).parsebytes(raw)
    identifier = str(parsed.get("Message-ID") or "").strip().casefold()
    digest = hashlib.sha256(raw).hexdigest()
    from_header = str(parsed.get("From") or "")
    address = parseaddr(from_header)[1].casefold()
    sender_domain = address.rsplit("@", 1)[1] if "@" in address else None
    date = parsed.get("Date")
    try:
        received_at = date.datetime.isoformat() if date and date.datetime else None
    except (AttributeError, ValueError):
        received_at = None
    return {
        "message_key": identifier or f"sha256:{digest}",
        "rfc_message_id": identifier or None,
        "content_sha256": digest,
        "from_header": from_header,
        "sender_domain": sender_domain,
        "subject": str(parsed.get("Subject") or ""),
        "received_at": received_at,
    }


def store_raw(data_dir: Path, digest: str, raw: bytes) -> str:
    relative = Path("raw-mail") / digest[:2] / f"{digest}.eml.gz"
    destination = data_dir / relative
    if not destination.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(".tmp")
        with gzip.open(temporary, "wb", compresslevel=6) as output:
            output.write(raw)
        temporary.replace(destination)
    return relative.as_posix()


def run_initial_index(
    database: Database, cipher: SecretCipher, data_dir: Path, job: dict
) -> None:
    account_row = database.get_account(job["account_id"])
    if account_row is None:
        raise RuntimeError("Account no longer exists")
    account = dict(account_row)
    password = cipher.decrypt(account.pop("imap_password_ciphertext"))
    account["imap_use_ssl"] = bool(account["imap_use_ssl"])
    profile = load_group_profile(database, cipher, account["model_group_id"])
    folders = database.indexable_folders(account["id"])
    if not folders:
        raise RuntimeError("Select at least one ham, spam, or monitored folder before indexing")

    client = connect(account, password)
    processed = 0
    try:
        for folder in folders:
            try:
                selected = client.select_folder(folder["path"], readonly=True)
                validity = _uid_validity(selected)
                if folder.get("uid_validity") != validity:
                    database.reset_folder_checkpoint(folder["id"], validity)
                    last_uid = 0
                else:
                    last_uid = int(folder.get("last_indexed_uid") or 0)
                criteria = ["ALL"] if last_uid == 0 else ["UID", f"{last_uid + 1}:*"]
                uids = sorted(int(uid) for uid in client.search(criteria) if int(uid) > last_uid)
                database.update_job_progress(job["id"], processed, processed + len(uids))
                for offset in range(0, len(uids), BATCH_SIZE):
                    batch = uids[offset : offset + BATCH_SIZE]
                    fetched = client.fetch(batch, ["RFC822"])
                    with database.connect() as connection:
                        connection.execute("BEGIN IMMEDIATE")
                        for uid in batch:
                            item = fetched.get(uid, {})
                            raw = _value(item, "RFC822")
                            if not isinstance(raw, bytes):
                                continue
                            message = parse_message(raw)
                            processed_message = preprocess_email(raw, profile)
                            message.update(
                                {
                                    "id": str(uuid4()),
                                    "account_id": account["id"],
                                    "raw_storage_path": store_raw(data_dir, message["content_sha256"], raw),
                                    "effective_label": folder["role"] if folder["role"] in {"ham", "spam"} else None,
                                    "label_source": f"initial_folder:{folder['role']}" if folder["role"] in {"ham", "spam"} else None,
                                    **processed_message,
                                }
                            )
                            database.upsert_indexed_message(
                                message,
                                {
                                    "id": str(uuid4()),
                                    "folder_id": folder["id"],
                                    "uid_validity": validity,
                                    "uid": uid,
                                },
                                connection,
                            )
                            processed += 1
                        connection.commit()
                    database.update_folder_checkpoint(folder["id"], max(batch))
                    database.update_job_progress(job["id"], processed)
                database.update_folder_checkpoint(folder["id"], max(uids, default=last_uid), "completed")
            except Exception as exc:
                database.fail_folder_index(folder["id"], f"{type(exc).__name__}: {exc}")
                raise
    finally:
        client.logout()


def reprocess_group(database: Database, cipher: SecretCipher, data_dir: Path, job: dict) -> None:
    import json

    group_id = json.loads(job.get("context_json") or "{}").get("group_id")
    if not group_id:
        raise RuntimeError("Reprocessing job has no model group")
    profile = load_group_profile(database, cipher, group_id)
    messages = database.group_messages_for_reprocessing(group_id, int(profile["version"]))
    database.update_job_progress(job["id"], 0, len(messages))
    for index, message in enumerate(messages, start=1):
        raw_path = data_dir / message["raw_storage_path"]
        if not raw_path.exists():
            raise RuntimeError(f"Raw source is unavailable for message {message['id']}")
        with gzip.open(raw_path, "rb") as source:
            result = preprocess_email(source.read(), profile)
        database.update_message_preprocessing(
            message["id"], result["model_text"], result["preprocessing_version"], result["privacy_counts"]
        )
        database.update_job_progress(job["id"], index)


def process_next_job(database: Database, cipher: SecretCipher, data_dir: Path) -> bool:
    job = database.claim_next_job()
    if job is None:
        return False
    try:
        if job["kind"] == "initial_index":
            run_initial_index(database, cipher, data_dir, job)
        elif job["kind"] == "reprocess_privacy":
            reprocess_group(database, cipher, data_dir, job)
        elif job["kind"] == "reconcile_account":
            from mail_nuke.reconciliation import reconcile_account

            reconcile_account(database, cipher, data_dir, job, _model_runtime(data_dir))
        elif job["kind"] == "train_model":
            from mail_nuke.training import run_training

            run_training(database, data_dir, job)
        else:
            raise RuntimeError(f"Unsupported job kind: {job['kind']}")
        database.finish_job(job["id"])
    except Exception as exc:
        database.finish_job(job["id"], f"{type(exc).__name__}: {exc}"[:500])
    return True
