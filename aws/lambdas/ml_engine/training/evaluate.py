"""
evaluate.py

Evaluate the trained cybersecurity risk classification model.
"""

import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)

from aws.lambdas.ml_engine.training.config import (
    MODEL_PATH,
    LABEL_ENCODER_PATH,
    PROCESSED_DATASET,
)

from aws.lambdas.ml_engine.training.constants import (
    FEATURE_COLUMNS,
    TARGET_COLUMN,
)


class ModelEvaluator:
    """
    Evaluate the trained model.
    """

    @classmethod
    def evaluate(cls):

        model = joblib.load(MODEL_PATH)

        encoder = joblib.load(LABEL_ENCODER_PATH)

        dataframe = pd.read_csv(PROCESSED_DATASET)

        X = dataframe[FEATURE_COLUMNS]

        y = dataframe[TARGET_COLUMN]

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

        report = classification_report(
            y_encoded,
            predictions,
            target_names=encoder.classes_,
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