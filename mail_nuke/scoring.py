from __future__ import annotations

from pathlib import Path
from threading import Lock
from typing import Any

import joblib

from mail_nuke.database import Database


class ModelRuntime:
    """Loads active artifacts lazily and swaps them when a group promotes a new version."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self._models: dict[str, tuple[str, dict[str, Any]]] = {}
        self._lock = Lock()

    def _artifact(self, database: Database, group_id: str) -> tuple[dict, dict[str, Any]]:
        active = database.active_model_version(group_id)
        if active is None:
            raise RuntimeError("Model group has no active model")
        with self._lock:
            cached = self._models.get(group_id)
            if cached is None or cached[0] != active["id"]:
                path = (self.data_dir / active["artifact_path"]).resolve()
                model_root = (self.data_dir / "models").resolve()
                if model_root not in path.parents or not path.is_file():
                    raise RuntimeError("Active model artifact is unavailable")
                artifact = joblib.load(path)
                if artifact.get("model_version_id") != active["id"]:
                    raise RuntimeError("Active model artifact identity does not match the database")
                self._models[group_id] = (active["id"], artifact)
            return active, self._models[group_id][1]

    def score(
        self, database: Database, group_id: str, model_text: str, preprocessing_version: int
    ) -> dict:
        active, artifact = self._artifact(database, group_id)
        required_version = int(artifact["privacy_profile_version"])
        if int(preprocessing_version) != required_version:
            raise RuntimeError(
                f"Message privacy version {preprocessing_version} does not match active model version {required_version}"
            )
        classes = list(artifact["classes"])
        spam_index = classes.index("spam")
        score = float(artifact["pipeline"].predict_proba([model_text])[0, spam_index])
        group = database.get_model_group(group_id)
        if group is None:
            raise RuntimeError("Model group no longer exists")
        threshold = group["threshold_override"]
        if threshold is None:
            threshold = active["recommended_threshold"]
        threshold = float(threshold)
        return {
            "model_group_id": group_id,
            "model_version_id": active["id"],
            "score": score,
            "threshold": threshold,
            "label": "spam" if score >= threshold else "ham",
        }
