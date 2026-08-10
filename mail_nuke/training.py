from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from uuid import uuid4

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from mail_nuke.database import Database


def stable_split(content_sha256: str, label_source: str | None) -> str:
    if label_source == "dashboard":
        return "train"
    bucket = int(hashlib.sha256(content_sha256.encode()).hexdigest()[:8], 16) % 100
    if bucket < 70:
        return "train"
    if bucket < 85:
        return "valid"
    return "test"


def build_samples(rows: list[dict]) -> tuple[list[dict], int, int]:
    by_content: dict[str, list[dict]] = {}
    for row in rows:
        by_content.setdefault(row["content_sha256"], []).append(row)
    samples = []
    deduplicated = 0
    ambiguous = 0
    for digest, group in sorted(by_content.items()):
        labels = {row["effective_label"] for row in group}
        if len(labels) != 1:
            ambiguous += len(group)
            continue
        chosen = sorted(
            group,
            key=lambda row: (row.get("label_source") != "dashboard", row["id"]),
        )[0]
        deduplicated += len(group) - 1
        samples.append(
            {
                "message_id": chosen["id"],
                "label": chosen["effective_label"],
                "split": stable_split(digest, chosen.get("label_source")),
                "content_sha256": digest,
            }
        )
    return samples, deduplicated, ambiguous


def metrics_for(labels: list[str], probabilities: np.ndarray, threshold: float) -> dict:
    predictions = np.where(probabilities >= threshold, "spam", "ham")
    labels_array = np.asarray(labels)
    tp = int(np.sum((labels_array == "spam") & (predictions == "spam")))
    fn = int(np.sum((labels_array == "spam") & (predictions == "ham")))
    fp = int(np.sum((labels_array == "ham") & (predictions == "spam")))
    tn = int(np.sum((labels_array == "ham") & (predictions == "ham")))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "threshold": float(threshold), "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "spam_precision": precision, "spam_recall": recall, "spam_f1": f1,
        "ham_false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
    }


def recommend_threshold(labels: list[str], probabilities: np.ndarray) -> tuple[float, dict]:
    candidates = [metrics_for(labels, probabilities, float(value)) for value in np.linspace(0.05, 0.99, 95)]
    safe = [result for result in candidates if result["ham_false_positive_rate"] <= 0.01]
    pool = safe or candidates
    best = max(
        pool,
        key=lambda result: (
            result["spam_recall"], result["spam_precision"], result["spam_f1"],
            -abs(result["threshold"] - 0.9),
        ) if safe else (
            result["spam_f1"], result["spam_precision"], result["spam_recall"],
            -abs(result["threshold"] - 0.9),
        ),
    )
    return float(best["threshold"]), best


def _xy(rows: list[dict], split: str) -> tuple[list[str], list[str]]:
    selected = [row for row in rows if row["split"] == split]
    return [row["model_text"] for row in selected], [row["label"] for row in selected]


def _require_classes(labels: list[str], split: str, minimum_each: int = 1) -> None:
    counts = {label: labels.count(label) for label in ("ham", "spam")}
    if min(counts.values()) < minimum_each:
        raise RuntimeError(
            f"The {split} cohort needs at least {minimum_each} ham and {minimum_each} spam samples; got {counts}"
        )


def run_training(database: Database, data_dir: Path, job: dict) -> dict:
    group_id = json.loads(job.get("context_json") or "{}").get("group_id")
    if not group_id:
        raise RuntimeError("Training job has no model group")
    profile = database.get_privacy_profile(group_id)
    if profile is None:
        raise RuntimeError("Model group has no privacy profile")
    source = database.training_source_messages(group_id, int(profile["version"]))
    samples, deduplicated, ambiguous = build_samples(source)
    generation_id = str(uuid4())
    generation = database.create_dataset_generation(
        generation_id, group_id, int(profile["version"]), samples, deduplicated, ambiguous
    )
    rows = database.dataset_rows(generation_id)
    x_train, y_train = _xy(rows, "train")
    x_valid, y_valid = _xy(rows, "valid")
    x_test, y_test = _xy(rows, "test")
    _require_classes(y_train, "training", 2)
    _require_classes(y_valid, "validation")
    _require_classes(y_test, "test")

    pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True, strip_accents="unicode", ngram_range=(1, 2),
                    min_df=2, max_df=0.98, sublinear_tf=True,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=2000, class_weight="balanced", solver="liblinear",
                    random_state=42,
                ),
            ),
        ]
    )
    pipeline.fit(x_train, y_train)
    spam_index = list(pipeline.classes_).index("spam")
    valid_probabilities = pipeline.predict_proba(x_valid)[:, spam_index]
    threshold, validation_metrics = recommend_threshold(y_valid, valid_probabilities)
    test_probabilities = pipeline.predict_proba(x_test)[:, spam_index]
    test_metrics = metrics_for(y_test, test_probabilities, threshold)
    metrics = {
        "validation": validation_metrics,
        "test": test_metrics,
        "samples": {
            "total": generation["total_samples"], "ham": generation["ham_samples"],
            "spam": generation["spam_samples"], "deduplicated": deduplicated,
            "ambiguous": ambiguous, "train": len(y_train), "valid": len(y_valid), "test": len(y_test),
        },
    }

    version_id = str(uuid4())
    relative = Path("models") / group_id / f"{version_id}.joblib"
    destination = data_dir / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".tmp")
    joblib.dump(
        {
            "pipeline": pipeline, "classes": list(pipeline.classes_),
            "recommended_threshold": threshold, "model_group_id": group_id,
            "model_version_id": version_id, "dataset_generation_id": generation_id,
            "privacy_profile_version": int(profile["version"]), "metrics": metrics,
        },
        temporary,
    )
    os.replace(temporary, destination)
    active = database.active_model_version(group_id)
    promote = active is None
    comparison = None
    if active:
        current_artifact = joblib.load(data_dir / active["artifact_path"])
        current_spam_index = list(current_artifact["classes"]).index("spam")
        current_probabilities = current_artifact["pipeline"].predict_proba(x_test)[:, current_spam_index]
        current_threshold = float(active["recommended_threshold"])
        comparison = metrics_for(y_test, current_probabilities, current_threshold)
        promote = (
            test_metrics["spam_recall"] >= comparison["spam_recall"] - 0.01
            and test_metrics["ham_false_positive_rate"] <= comparison["ham_false_positive_rate"] + 0.005
        )
        metrics["previous_model_test"] = comparison
    database.create_model_version(
        version_id, group_id, generation_id, relative.as_posix(), threshold, metrics, "candidate"
    )
    if promote:
        database.promote_model_version(group_id, version_id)
    else:
        database.reject_model_version(version_id)
    return {"version_id": version_id, "promoted": promote, "metrics": metrics}
