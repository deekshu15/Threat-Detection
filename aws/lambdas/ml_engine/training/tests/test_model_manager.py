from __future__ import annotations

import joblib
import numpy as np
from sklearn.datasets import make_classification
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

from aws.lambdas.ml_engine.training.model_manager import ModelManager


def test_model_manager_round_trip(tmp_path):
    X, y = make_classification(
        n_samples=120,
        n_features=6,
        n_informative=4,
        n_redundant=0,
        random_state=42,
    )

    model = RandomForestClassifier(n_estimators=20, random_state=42)
    model.fit(X, y)

    manager = ModelManager(tmp_path / "models", tmp_path / "production")
    feature_names = [f"feature_{index}" for index in range(X.shape[1])]
    manager.save_active_features(feature_names)
    manager.save_metadata({"feature_count": len(feature_names)})
    manager.save_model(model, filename="best_model.pkl")

    loaded = manager.load_model(expected_features=feature_names)
    predictions = loaded.predict(X[:5])

    assert predictions.shape == (5,)


def test_model_manager_saves_encoder(tmp_path):
    encoder = LabelEncoder().fit([0, 1, 1, 0])
    manager = ModelManager(tmp_path / "models", tmp_path / "production")

    path = manager.save_label_encoder(encoder, promote_to_production=True)

    assert path.exists()
    assert (tmp_path / "production" / "label_encoder.pkl").exists()
    restored = joblib.load(path)
    assert list(restored.classes_) == list(encoder.classes_)
