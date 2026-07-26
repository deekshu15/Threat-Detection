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

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )

    model.fit(X_train, y_train)

    print()
    print("=" * 60)
    print("Evaluating")
    print("=" * 60)

    predictions = model.predict(X_test)

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

    metadata = {

        "model": "RandomForestClassifier",

        "features": 29,

        "n_estimators": 200,

        "max_depth": 20,

        "accuracy": float(accuracy),

        "training_samples": int(len(X_train)),

        "test_samples": int(len(X_test)),
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

    print()
    print("=" * 60)
    print("Saved")
    print("=" * 60)

    print(MODEL_DIR / "risk_classifier.pkl")
    print(MODEL_DIR / "metadata.json")


if __name__ == "__main__":
    main()