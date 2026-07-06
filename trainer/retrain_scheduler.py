from __future__ import annotations

import os
import time
import traceback

from dotenv import load_dotenv

from trainer.weekly_retrain import ROOT, main as retrain


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    return default if value is None else value.casefold() in {"1", "true", "yes", "on"}


def main() -> None:
    load_dotenv(ROOT / ".env")
    interval = int(os.getenv("RETRAIN_INTERVAL_SECONDS", "604800"))
    if interval < 3600:
        raise ValueError("RETRAIN_INTERVAL_SECONDS must be at least 3600")
    first_delay = 0 if env_bool("RETRAIN_RUN_ON_START", False) else interval
    while True:
        time.sleep(first_delay)
        first_delay = interval
        try:
            retrain()
        except Exception:
            traceback.print_exc()


if __name__ == "__main__":
    main()
