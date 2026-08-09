"""Evaluation helpers for the trained cybersecurity model."""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from aws.lambdas.feature_engineering.feature_selector import feature_schema
from aws.lambdas.ml_engine.training.config import (
    BENCHMARK_REPORT_FILENAME,
    MODEL_PATH,
    PROCESSED_DATASET,
    PROCESSED_DATASET_DIR,
)


def _load_label_encoder():
    encoder_path = PROCESSED_DATASET_DIR / "label_encoder.pkl"
    if not encoder_path.exists():
        raise FileNotFoundError(f"Label encoder not found: {encoder_path}")
    return joblib.load(encoder_path)


class ModelEvaluator:
    """
    Evaluate the trained model.
    """

    @classmethod
    def evaluate(cls):

        model = joblib.load(MODEL_PATH)

        encoder = _load_label_encoder()

        dataframe = pd.read_csv(PROCESSED_DATASET)

        schema = feature_schema()
        feature_columns = schema.get("feature_names", [])
        if not feature_columns:
            raise RuntimeError("No feature schema available for evaluation.")

        X = dataframe[feature_columns]
        y = dataframe["Target"]

        y_encoded = encoder.transform(y)

        predictions = model.predict(X)

        accuracy = accuracy_score(
            y_encoded,
            predictions,
        )

        precision = precision_score(
            y_encoded,
            predictions,
            average="weighted",
            zero_division=0,
        )

        recall = recall_score(
            y_encoded,
            predictions,
            average="weighted",
            zero_division=0,
        )

        f1 = f1_score(
            y_encoded,
            predictions,
            average="weighted",
            zero_division=0,
        )

        target_names = [str(label) for label in encoder.classes_]

        report = classification_report(
            y_encoded,
            predictions,
            target_names=target_names,
            zero_division=0,
        )

        matrix = confusion_matrix(
            y_encoded,
            predictions,
        )

        return {

            "accuracy": accuracy,

            "precision": precision,

            "recall": recall,

            "f1_score": f1,

            "classification_report": report,

            "confusion_matrix": matrix,
        }


def evaluate():

    results = ModelEvaluator.evaluate()

    print("\n========== MODEL EVALUATION ==========\n")

    print(f"Accuracy : {results['accuracy']:.4f}")
    print(f"Precision: {results['precision']:.4f}")
    print(f"Recall   : {results['recall']:.4f}")
    print(f"F1 Score : {results['f1_score']:.4f}")

    print("\nClassification Report\n")
    print(results["classification_report"])

    print("\nConfusion Matrix\n")
    print(results["confusion_matrix"])

    return results


if __name__ == "__main__":
    evaluate()