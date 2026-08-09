from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

from aws.lambdas.ml_engine.training import evaluate


class DummyModel:
    def predict(self, X):
        return np.zeros(len(X), dtype=int)

    def predict_proba(self, X):
        proba = np.zeros((len(X), 2), dtype=float)
        proba[:, 0] = 1.0
        return proba


def test_model_evaluator_returns_metrics(monkeypatch):
    feature_columns = ["f1", "f2"]
    frame = pd.DataFrame(
        {
            "f1": [1.0, 0.0, 1.0, 0.0],
            "f2": [0.0, 1.0, 0.0, 1.0],
            "Target": [0, 1, 0, 1],
        }
    )

    encoder = LabelEncoder().fit([0, 1])

    monkeypatch.setattr(evaluate, "feature_schema", lambda: {"feature_names": feature_columns})
    monkeypatch.setattr(evaluate, "_load_label_encoder", lambda: encoder)
    monkeypatch.setattr(evaluate.joblib, "load", lambda _path: DummyModel())
    monkeypatch.setattr(evaluate.pd, "read_csv", lambda _path: frame)

    results = evaluate.ModelEvaluator.evaluate()

    assert 0.0 <= results["accuracy"] <= 1.0
    assert "classification_report" in results
    assert results["confusion_matrix"].shape == (2, 2)
