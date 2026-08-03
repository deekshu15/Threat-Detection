from __future__ import annotations

from pathlib import Path
import json

import joblib
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.tree import DecisionTreeClassifier
from sklearn.feature_selection import mutual_info_classif
import time
import pandas as pd

# Feature schema
import feature_engineering.feature_selector as selector
from feature_engineering.validator import check_forbidden_training_columns

BASE_DIR = Path(__file__).resolve().parent

MODEL_DIR = BASE_DIR / "saved_models"

MODEL_DIR.mkdir(parents=True, exist_ok=True)


def main():

    print("=" * 60)
    print("Loading Dataset")
    print("=" * 60)

    X_train = np.load(MODEL_DIR / "X_train.npy")
    y_train = np.load(MODEL_DIR / "y_train.npy")

    X_test = np.load(MODEL_DIR / "X_test.npy")
    y_test = np.load(MODEL_DIR / "y_test.npy")

    print("Train:", X_train.shape)
    print("Test :", X_test.shape)

    print()
    print("=" * 60)
    print("Training Random Forest")
    print("=" * 60)

    # -------------------------------------------------
    # Pre-training validations
    # -------------------------------------------------
    feature_names = selector.feature_schema().get("feature_names", [])

    forbidden = check_forbidden_training_columns(feature_names)

    if forbidden:
        raise RuntimeError("Forbidden feature names present: " + ", ".join(forbidden))

    if "Label" in feature_names or "label" in feature_names or "Target" in feature_names:
        raise RuntimeError("Target/Label present in feature names")

    # Drop near-constant features (variance threshold)
    variances = np.var(X_train, axis=0)
    keep_idx = [i for i, v in enumerate(variances) if v > 1e-8]

    if len(keep_idx) < len(feature_names):
        removed = [feature_names[i] for i in range(len(feature_names)) if i not in keep_idx]
        print("Removed near-constant features:", removed)

    # Filter X and feature names
    X_train = X_train[:, keep_idx]
    X_test = X_test[:, keep_idx]
    feature_names = [feature_names[i] for i in keep_idx]

    # Persist active feature list
    with open(MODEL_DIR / "active_features.json", "w") as f:
        json.dump({"feature_names": feature_names}, f, indent=2)

    # Leakage detection: check if any single feature perfectly predicts Target
    flagged = []

    for idx, fname in enumerate(feature_names):

        col = X_train[:, idx].reshape(-1, 1)

        stump = DecisionTreeClassifier(max_depth=1, random_state=42)

        try:
            stump.fit(col, y_train)

            pred = stump.predict(col)

            acc = accuracy_score(y_train, pred)

            if acc >= 0.995:
                flagged.append((fname, float(acc)))

        except Exception:
            continue

    if flagged:
        msg = (
            "Potential Data Leakage Detected. Features with near-perfect single-feature accuracy:\n"
            + "\n".join([f"{f}: {a:.4f}" for f, a in flagged])
        )
        raise RuntimeError(msg)

    # -------------------------------------------------
    # Train
    # -------------------------------------------------
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )

    t0 = time.perf_counter()

    model.fit(X_train, y_train)

    t1 = time.perf_counter()
    training_time_s = t1 - t0

    print()
    print("=" * 60)
    print("Evaluating")
    print("=" * 60)

    predictions = model.predict(X_test)

    # Inference timing (bulk)
    it0 = time.perf_counter()
    _ = model.predict(X_test)
    it1 = time.perf_counter()
    inference_time_s = it1 - it0

    accuracy = accuracy_score(y_test, predictions)

    print(f"Accuracy : {accuracy:.4f}")

    print()
    print(classification_report(y_test, predictions))

    print()
    print(confusion_matrix(y_test, predictions))

    joblib.dump(
        model,
        MODEL_DIR / "risk_classifier.pkl",
    )

    # Feature importances
    try:
        importances = model.feature_importances_
    except Exception:
        importances = [0.0] * len(feature_names)

    fi = list(zip(feature_names, importances))
    fi_sorted = sorted(fi, key=lambda x: x[1], reverse=True)

    df_fi = pd.DataFrame(
        {
            "feature": [f for f, _ in fi_sorted],
            "importance": [v for _, v in fi_sorted],
        }
    )

    df_fi["rank"] = range(1, len(df_fi) + 1)

    df_fi.to_csv(MODEL_DIR / "feature_importance.csv", index=False)

    metadata = {
        "model": "RandomForestClassifier",
        "features": len(feature_names),
        "n_estimators": 200,
        "max_depth": 20,
        "accuracy": float(accuracy),
        "training_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "training_time_s": float(training_time_s),
        "inference_time_s": float(inference_time_s),
    }

    with open(
        MODEL_DIR / "metadata.json",
        "w",
    ) as f:

        json.dump(
            metadata,
            f,
            indent=4,
        )

    # Detailed training report
    report = {
        "accuracy": float(accuracy),
        "classification_report": classification_report(y_test, predictions, output_dict=True),
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
        "feature_importance": df_fi.to_dict(orient="records"),
        "training_time_s": float(training_time_s),
        "inference_time_s": float(inference_time_s),
    }

    with open(MODEL_DIR / "training_report.json", "w") as f:
        json.dump(report, f, indent=4)

    print()
    print("=" * 60)
    print("Saved")
    print("=" * 60)

    print(MODEL_DIR / "risk_classifier.pkl")
    print(MODEL_DIR / "metadata.json")


if __name__ == "__main__":
    main()