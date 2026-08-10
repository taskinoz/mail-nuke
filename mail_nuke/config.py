from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    secret_key: str | None
    reconcile_interval_seconds: int
    training_interval_seconds: int

    @property
    def database_path(self) -> Path:
        return self.data_dir / "mail-nuke.db"

    @property
    def generated_secret_key_path(self) -> Path:
        return self.data_dir / "secret.key"


def load_settings() -> Settings:
    data_dir = Path(os.getenv("MAIL_NUKE_DATA_DIR", "data")).expanduser().resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    secret_key = os.getenv("MAIL_NUKE_SECRET_KEY", "").strip() or None
    reconcile_interval = int(os.getenv("MAIL_NUKE_RECONCILE_INTERVAL_SECONDS", "300"))
    if reconcile_interval < 300:
        raise ValueError("MAIL_NUKE_RECONCILE_INTERVAL_SECONDS must be at least 300")
    training_interval = int(os.getenv("MAIL_NUKE_TRAIN_INTERVAL_SECONDS", "604800"))
    if training_interval < 3600:
        raise ValueError("MAIL_NUKE_TRAIN_INTERVAL_SECONDS must be at least 3600")
    return Settings(
        data_dir=data_dir,
        secret_key=secret_key,
        reconcile_interval_seconds=reconcile_interval,
        training_interval_seconds=training_interval,
    )
