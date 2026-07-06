from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

from dotenv import load_dotenv

from trainer.weekly_retrain import MODEL, ROOT, connect, message_id


def folder_names(value: str) -> list[str]:
    return [name.strip() for name in value.split(",") if name.strip()]


def export_folder(client, folder: str, destination: Path) -> int:
    client.select_folder(folder, readonly=True)
    destination.mkdir(parents=True, exist_ok=True)
    count = 0
    for uid in (int(value) for value in client.search(["ALL"])):
        item = client.fetch([uid], ["RFC822"]).get(uid, {})
        raw = item.get(b"RFC822") or item.get("RFC822")
        if not isinstance(raw, bytes):
            continue
        identifier = message_id(raw)
        digest = hashlib.sha256(identifier.encode("utf-8") if identifier else raw).hexdigest()
        path = destination / f"{digest}.eml"
        if not path.exists():
            path.write_bytes(raw)
            count += 1
    return count


def replace_managed_export(staged: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        shutil.rmtree(destination)
    staged.replace(destination)


def main() -> None:
    load_dotenv(ROOT / ".env")
    ham_folders = folder_names(os.getenv("IMAP_HAM_FOLDERS", os.getenv("IMAP_SOURCE_FOLDER", "INBOX")))
    spam_folders = folder_names(os.getenv("IMAP_SPAM_FOLDERS", os.getenv("IMAP_SPAM_FOLDER", "Junk")))
    if not ham_folders or not spam_folders:
        raise ValueError("At least one ham folder and one spam folder are required")

    staging = ROOT / "state" / "mailbox-export-staging"
    if staging.exists():
        shutil.rmtree(staging)
    ham_stage = staging / "ham"
    spam_stage = staging / "spam"

    client = connect()
    try:
        ham_count = sum(export_folder(client, folder, ham_stage) for folder in ham_folders)
        spam_count = sum(export_folder(client, folder, spam_stage) for folder in spam_folders)
    finally:
        client.logout()

    if ham_count < 2 or spam_count < 2:
        shutil.rmtree(staging, ignore_errors=True)
        raise RuntimeError(f"Refusing to train with only {ham_count} ham and {spam_count} spam messages")

    replace_managed_export(ham_stage, ROOT / "exports" / "ham" / "mailbox")
    replace_managed_export(spam_stage, ROOT / "exports" / "spam" / "mailbox")
    shutil.rmtree(staging, ignore_errors=True)

    subprocess.run(["bun", "run", "prepare"], cwd=ROOT, check=True)
    candidate = ROOT / "models" / "spam_filter.mailbox.joblib"
    subprocess.run(
        ["uv", "run", "python", "-m", "trainer.train", "--output", str(candidate)],
        cwd=ROOT,
        check=True,
    )
    if MODEL.exists():
        shutil.copy2(MODEL, MODEL.with_suffix(".pre-mailbox.joblib"))
    os.replace(candidate, MODEL)
    print(f"Trained from {ham_count} ham and {spam_count} spam mailbox messages.")
    print(f"Installed model at {MODEL}.")


if __name__ == "__main__":
    main()
