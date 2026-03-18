from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from imapclient import IMAPClient

from trainer.model_utils import score_raw_email


ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "logs"
STATE_DIR = ROOT / "state"


@dataclass
class Settings:
    imap_host: str
    imap_port: int
    imap_username: str
    imap_password: str
    imap_use_ssl: bool
    imap_source_folder: str
    imap_spam_folder: str
    imap_poll_seconds: int
    spam_threshold: float
    mark_seen_on_spam: bool
    dry_run: bool
    process_only_unseen: bool
    state_file: Path
    action_log_file: Path

def validate_folder(client, folder_name):
    folders = [name for _, _, name in client.list_folders()]
    if folder_name not in folders:
        raise RuntimeError(f"Folder does not exist: {folder_name}")

def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def load_settings() -> Settings:
    load_dotenv()

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    return Settings(
        imap_host=os.environ["IMAP_HOST"],
        imap_port=int(os.getenv("IMAP_PORT", "993")),
        imap_username=os.environ["IMAP_USERNAME"],
        imap_password=os.environ["IMAP_PASSWORD"],
        imap_use_ssl=env_bool("IMAP_USE_SSL", True),
        imap_source_folder=os.getenv("IMAP_SOURCE_FOLDER", "INBOX"),
        imap_spam_folder=os.getenv("IMAP_SPAM_FOLDER", "Junk"),
        imap_poll_seconds=int(os.getenv("IMAP_POLL_SECONDS", "60")),
        spam_threshold=float(os.getenv("SPAM_THRESHOLD", "0.9")),
        mark_seen_on_spam=env_bool("MARK_SEEN_ON_SPAM", True),
        dry_run=env_bool("DRY_RUN", False),
        process_only_unseen=env_bool("PROCESS_ONLY_UNSEEN", True),
        state_file=STATE_DIR / os.getenv("STATE_FILENAME", "imap-worker-state.json"),
        action_log_file=LOG_DIR / os.getenv("ACTION_LOG_FILENAME", "imap-actions.jsonl"),
    )


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"processed_uids": []}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"processed_uids": []}


def save_state(path: Path, state: dict[str, Any]) -> None:
    processed_uids = state.get("processed_uids", [])
    if len(processed_uids) > 5000:
        processed_uids = processed_uids[-5000:]
    path.write_text(
        json.dumps({"processed_uids": processed_uids}, indent=2),
        encoding="utf-8",
    )


def connect_imap(settings: Settings) -> IMAPClient:
    client = IMAPClient(
        host=settings.imap_host,
        port=settings.imap_port,
        ssl=settings.imap_use_ssl,
        use_uid=True,
    )
    client.login(settings.imap_username, settings.imap_password)
    return client


def search_candidate_uids(client: IMAPClient, settings: Settings) -> list[int]:
    client.select_folder(settings.imap_source_folder)

    if settings.process_only_unseen:
        criteria = ["UNSEEN"]
    else:
        criteria = ["ALL"]

    uids = client.search(criteria)
    return [int(uid) for uid in uids]


def fetch_raw_email(client: IMAPClient, uid: int) -> bytes | None:
    response = client.fetch([uid], ["RFC822"])
    item = response.get(uid)
    if not item:
        return None
    raw = item.get(b"RFC822") or item.get("RFC822")
    if isinstance(raw, bytes):
        return raw
    return None


def mark_seen(client: IMAPClient, uid: int) -> None:
    client.add_flags([uid], [b"\\Seen"])

def remove_seen(client: IMAPClient, uid: int) -> None:
    client.remove_flags([uid], [b"\\Seen"])


def try_move(client: IMAPClient, uid: int, destination_folder: str) -> bool:
    try:
        client.move([uid], destination_folder)
        return True
    except Exception:
        return False


def copy_delete_expunge(client: IMAPClient, uid: int, destination_folder: str) -> None:
    client.copy([uid], destination_folder)
    client.add_flags([uid], [b"\\Deleted"])
    client.expunge()


def ensure_destination_folder(client: IMAPClient, folder_name: str) -> None:
    try:
        client.select_folder(folder_name)
        return
    except Exception:
        pass

    try:
        client.create_folder(folder_name)
    except Exception:
        pass


def process_uid(
    client: IMAPClient,
    uid: int,
    settings: Settings,
    state: dict[str, Any],
) -> None:
    raw_eml = fetch_raw_email(client, uid)
    if not raw_eml:
        append_jsonl(
            settings.action_log_file,
            {
                "ts": utc_now_iso(),
                "uid": uid,
                "action": "skip",
                "reason": "missing_raw_email",
            },
        )
        return

    scored = score_raw_email(raw_eml, threshold_override=settings.spam_threshold)

    action_row = {
        "ts": utc_now_iso(),
        "uid": uid,
        "from": scored["from_header"],
        "subject": scored["subject"],
        "label": scored["label"],
        "spamScore": scored["spamScore"],
        "threshold": scored["threshold"],
        "action": "none",
        "dryRun": settings.dry_run,
    }

    is_spam = scored["label"] == "spam"

    if is_spam:
        if settings.dry_run:
            action_row["action"] = "would_move_to_spam"
        else:
            ensure_destination_folder(client, settings.imap_spam_folder)

            moved = try_move(client, uid, settings.imap_spam_folder)
            if not moved:
                copy_delete_expunge(client, uid, settings.imap_spam_folder)

            action_row["action"] = "moved_to_spam"

            if settings.mark_seen_on_spam:
                try:
                    client.select_folder(settings.imap_spam_folder)
                    mark_seen(client, uid)
                except Exception:
                    pass
    else:
        action_row["action"] = "left_in_place"
        remove_seen(client, uid)

    append_jsonl(settings.action_log_file, action_row)

    processed_uids = state.setdefault("processed_uids", [])
    processed_uids.append(uid)
    save_state(settings.state_file, state)


def main() -> None:
    settings = load_settings()
    state = load_state(settings.state_file)

    print(f"[imap-worker] starting for {settings.imap_username} on {settings.imap_host}")
    print(f"[imap-worker] source={settings.imap_source_folder} spam={settings.imap_spam_folder}")
    print(f"[imap-worker] poll={settings.imap_poll_seconds}s dry_run={settings.dry_run}")

    while True:
        client = None
        try:
            client = connect_imap(settings)

            folders = client.list_folders()
            print("DEBUG: IMAP folders:")
            for flags, delim, name in folders:
                print("IMAP folder:", name)

            validate_folder(client, settings.imap_source_folder)
            client.select_folder(settings.imap_source_folder)

            candidate_uids = search_candidate_uids(client, settings)
            already_processed = set(state.get("processed_uids", []))
            uids_to_process = [uid for uid in candidate_uids if uid not in already_processed]

            if uids_to_process:
                print(f"[imap-worker] processing {len(uids_to_process)} message(s)")
            else:
                print("[imap-worker] no new messages")

            for uid in uids_to_process:
                try:
                    client.select_folder(settings.imap_source_folder)
                    process_uid(client, uid, settings, state)
                except Exception as exc:
                    append_jsonl(
                        settings.action_log_file,
                        {
                            "ts": utc_now_iso(),
                            "uid": uid,
                            "action": "error",
                            "error": str(exc),
                        },
                    )
                    print(f"[imap-worker] error processing UID {uid}: {exc}")

        except Exception as exc:
            print(f"[imap-worker] loop error: {exc}")
        finally:
            try:
                if client is not None:
                    client.logout()
            except Exception:
                pass

        time.sleep(settings.imap_poll_seconds)


if __name__ == "__main__":
    main()