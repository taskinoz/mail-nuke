from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from mail_nuke.database import Database
from mail_nuke.imap_service import connect
from mail_nuke.indexer import BATCH_SIZE, _uid_validity, _value, parse_message, store_raw
from mail_nuke.preprocessing import load_group_profile, preprocess_email
from mail_nuke.security import SecretCipher
from mail_nuke.scoring import ModelRuntime


def reconcile_account(
    database: Database, cipher: SecretCipher, data_dir: Path, job: dict,
    runtime: ModelRuntime | None = None,
) -> dict:
    row = database.get_account(job["account_id"])
    if row is None:
        raise RuntimeError("Account no longer exists")
    account = dict(row)
    password = cipher.decrypt(account.pop("imap_password_ciphertext"))
    account["imap_use_ssl"] = bool(account["imap_use_ssl"])
    folders = database.indexable_folders(account["id"])
    if not folders:
        raise RuntimeError("No ham, spam, or monitored folders are configured")
    profile = load_group_profile(database, cipher, account["model_group_id"])
    runtime = runtime or ModelRuntime(data_dir)
    destinations = {
        folder["id"]: folder for folder in database.list_folders(account["id"])
    }
    seen: set[tuple[str, int, int]] = set()
    client = connect(account, password)
    try:
        for folder in folders:
            inference_source = folder["role"] in {"ham", "monitored"}
            can_move = account.get("automation_mode") == "move" and inference_source
            selected = client.select_folder(folder["path"], readonly=not can_move)
            validity = _uid_validity(selected)
            uids = sorted(int(uid) for uid in client.search(["ALL"]))
            for uid in uids:
                seen.add((folder["id"], validity, uid))
            unknown = [
                uid for uid in uids if not database.known_location(folder["id"], validity, uid)
            ]
            for offset in range(0, len(unknown), BATCH_SIZE):
                batch = unknown[offset : offset + BATCH_SIZE]
                fetched = client.fetch(batch, ["RFC822"])
                for uid in batch:
                    raw = _value(fetched.get(uid, {}), "RFC822")
                    if not isinstance(raw, bytes):
                        raise RuntimeError(f"IMAP did not return raw content for UID {uid}")
                    message = parse_message(raw)
                    message.update(
                        {
                            "id": str(uuid4()),
                            "account_id": account["id"],
                            "raw_storage_path": store_raw(data_dir, message["content_sha256"], raw),
                            "effective_label": (
                                None if inference_source and account.get("automation_mode") != "off"
                                else folder["role"] if folder["role"] in {"ham", "spam"} else None
                            ),
                            "label_source": (
                                None if inference_source and account.get("automation_mode") != "off"
                                else f"folder_reconciliation:{folder['role']}"
                                if folder["role"] in {"ham", "spam"} else None
                            ),
                            **preprocess_email(raw, profile),
                        }
                    )
                    message_id = database.upsert_indexed_message(
                        message,
                        {
                            "id": str(uuid4()), "folder_id": folder["id"],
                            "uid_validity": validity, "uid": uid,
                        },
                    )
                    if inference_source and account.get("automation_mode") != "off":
                        result = runtime.score(
                            database, account["model_group_id"], message["model_text"],
                            int(message["preprocessing_version"]),
                        )
                        destination_id = account.get("spam_destination_folder_id")
                        action_status = "not_requested"
                        if result["label"] == "spam":
                            action_status = "pending" if account["automation_mode"] == "move" else "dry_run"
                        prediction_id = str(uuid4())
                        database.create_prediction(
                            {
                                "id": prediction_id, "message_id": message_id, **result,
                                "action_mode": account["automation_mode"],
                                "action_status": action_status,
                                "source_folder_id": folder["id"],
                                "source_uid_validity": validity, "source_uid": uid,
                                "destination_folder_id": destination_id if result["label"] == "spam" else None,
                            }
                        )
                        if action_status == "pending":
                            destination = destinations.get(destination_id)
                            if destination is None or destination["role"] != "spam":
                                error = "Configured Spam destination is unavailable"
                                database.finish_prediction_action(prediction_id, "failed", error)
                                raise RuntimeError(error)
                            try:
                                client.move([uid], destination["path"])
                            except Exception as exc:
                                error = f"{type(exc).__name__}: {exc}"
                                database.finish_prediction_action(prediction_id, "failed", error)
                                raise
                            database.finish_prediction_action(prediction_id, "moved")
                            seen.discard((folder["id"], validity, uid))
        return database.finalize_reconciliation(account["id"], seen)
    finally:
        client.logout()
