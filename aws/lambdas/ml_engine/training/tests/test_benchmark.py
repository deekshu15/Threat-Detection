from __future__ import annotations

import numpy as np
from sklearn.datasets import make_classification

from aws.lambdas.ml_engine.training.config import default_config
from aws.lambdas.ml_engine.training.train_model import _benchmark_models


def test_benchmark_models_returns_ranked_results():
    X, y = make_classification(
        n_samples=240,
        n_features=8,
        n_informative=5,
        n_redundant=0,
        n_classes=3,
        n_clusters_per_class=1,
        random_state=42,
    )

    config = default_config()
    benchmark_df, details, summary = _benchmark_models(X[:160], y[:160], X[160:], y[160:], config)

    assert not benchmark_df.empty
    assert {"model_name", "weighted_f1", "accuracy"}.issubset(set(benchmark_df.columns))
    assert summary["best_model_name"] is not None
    assert "imbalance" in details
