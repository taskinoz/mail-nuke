from __future__ import annotations

import json
from pathlib import Path
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.pipeline import Pipeline


ROOT = Path(".")
DATA_DIR = ROOT / "prepared"
MODEL_DIR = ROOT / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)


def load_jsonl(path: Path) -> pd.DataFrame:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return pd.DataFrame(rows)


def extract_xy(df: pd.DataFrame) -> tuple[pd.Series, pd.Series]:
    x = df["modelText"].fillna("")
    y = df["label"].fillna("")
    return x, y


def main() -> None:
    train_df = load_jsonl(DATA_DIR / "train.jsonl")
    valid_df = load_jsonl(DATA_DIR / "valid.jsonl")
    test_df = load_jsonl(DATA_DIR / "test.jsonl")

    x_train, y_train = extract_xy(train_df)
    x_valid, y_valid = extract_xy(valid_df)
    x_test, y_test = extract_xy(test_df)

    pipeline = Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    strip_accents="unicode",
                    ngram_range=(1, 2),
                    min_df=2,
                    max_df=0.98,
                    sublinear_tf=True,
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    max_iter=2000,
                    class_weight="balanced",
                    solver="liblinear",
                ),
            ),
        ]
    )

    pipeline.fit(x_train, y_train)

    valid_probs = pipeline.predict_proba(x_valid)
    spam_idx = list(pipeline.classes_).index("spam")
    valid_spam_probs = valid_probs[:, spam_idx]

    thresholds = [0.50, 0.60, 0.70, 0.80, 0.90, 0.95, 0.98]
    print("\nValidation threshold sweep:")
    best_threshold = 0.90
    best_precision = -1.0

    for threshold in thresholds:
        preds = ["spam" if p >= threshold else "ham" for p in valid_spam_probs]
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_valid, preds, labels=["spam"], average=None, zero_division=0
        )
        p = precision[0]
        r = recall[0]
        f = f1[0]
        print(f"threshold={threshold:.2f} precision={p:.4f} recall={r:.4f} f1={f:.4f}")

        if p > best_precision:
            best_precision = p
            best_threshold = threshold

    print(f"\nChosen threshold: {best_threshold:.2f}")

    test_probs = pipeline.predict_proba(x_test)
    test_spam_probs = test_probs[:, spam_idx]
    test_preds = ["spam" if p >= best_threshold else "ham" for p in test_spam_probs]

    print("\nTest classification report:")
    print(classification_report(y_test, test_preds, digits=4, zero_division=0))

    print("Confusion matrix [ham, spam]:")
    print(confusion_matrix(y_test, test_preds, labels=["ham", "spam"]))

    artifact = {
        "pipeline": pipeline,
        "threshold": best_threshold,
        "classes": list(pipeline.classes_),
    }
    joblib.dump(artifact, MODEL_DIR / "spam_filter.joblib")

    print(f"\nSaved model to {MODEL_DIR / 'spam_filter.joblib'}")


if __name__ == "__main__":
    main()