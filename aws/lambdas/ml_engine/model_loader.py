"""
ML Model Loader

Loads trained models and encoders from disk.

Author:
AI Assisted Threat Detection Dashboard
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional
import json
import logging

import joblib
from sklearn.exceptions import NotFittedError


# ============================================================
# Paths
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

MODEL_DIR = BASE_DIR / "models"

MODEL_PATH = MODEL_DIR / "risk_classifier.pkl"

ENCODER_PATH = MODEL_DIR / "label_encoder.pkl"


# ============================================================
# Loader
# ============================================================

class ModelLoader:

    def __init__(self):

        self._model: Optional[Any] = None

        self._label_encoder: Optional[Any] = None

    # --------------------------------------------------------

    def load_model(self):

        if self._model is None:

            if not MODEL_PATH.exists():

                raise FileNotFoundError(

                    f"Model not found: {MODEL_PATH}"

                )

            self._model = joblib.load(MODEL_PATH)

        return self._model

    # --------------------------------------------------------

    def load_label_encoder(self):

        if self._label_encoder is None:

            if not ENCODER_PATH.exists():

                raise FileNotFoundError(

                    f"Label encoder not found: {ENCODER_PATH}"

                )


            self._label_encoder = joblib.load(ENCODER_PATH)

        return self._label_encoder

    # --------------------------------------------------------

    def validate_startup(self):
        """Validate that model, encoder, and active_features are present and compatible.

        Raises a RuntimeError with a clear message on failure.
        """
        logger = logging.getLogger("ml_engine.model_loader")

        # Ensure files exist
        if not MODEL_PATH.exists():
            raise RuntimeError(f"Model artifact missing: {MODEL_PATH}")

        if not ENCODER_PATH.exists():
            raise RuntimeError(f"Label encoder artifact missing: {ENCODER_PATH}")

        # Active features
        active_path = MODEL_DIR / "active_features.json"
        if not active_path.exists():
            # fallback to training saved copy
            training_active = (
                BASE_DIR / "training" / "saved_models" / "active_features.json"
            )
            if training_active.exists():
                active_path = training_active

        if not active_path.exists():
            raise RuntimeError("active_features.json not found alongside model or training saved_models")

        # Metadata file must exist and report matching feature count
        metadata_path = MODEL_DIR / "metadata.json"
        if not metadata_path.exists():
            raise RuntimeError(f"metadata.json missing from model directory: {metadata_path}")

        # Load artifacts
        try:
            model = joblib.load(MODEL_PATH)
        except Exception as exc:
            raise RuntimeError(f"Failed to load model: {exc}") from exc

        try:
            encoder = joblib.load(ENCODER_PATH)
        except Exception as exc:
            raise RuntimeError(f"Failed to load label encoder: {exc}") from exc

        try:
            active = json.loads(active_path.read_text())
            feature_names = active.get("feature_names")
            if not isinstance(feature_names, list):
                raise RuntimeError("active_features.json has invalid format")
        except Exception as exc:
            raise RuntimeError(f"Failed to read active_features.json: {exc}") from exc

        # Check model input dimensions
        n_features = getattr(model, "n_features_in_", None)
        if n_features is None:
            raise RuntimeError("Model artifact missing attribute 'n_features_in_'")

        if n_features != len(feature_names):
            raise RuntimeError(
                f"Model expects {n_features} features but active_features.json contains {len(feature_names)}"
            )

        # Verify metadata feature count matches active features
        try:
            meta = json.loads(metadata_path.read_text())
            meta_features = int(meta.get("features", -1))
            if meta_features != len(feature_names):
                raise RuntimeError(
                    f"metadata.json reports {meta_features} features but active_features.json contains {len(feature_names)}"
                )
        except Exception as exc:
            raise RuntimeError(f"Failed to validate metadata.json: {exc}") from exc

        # Smoke test: run a single prediction with zeros
        try:
            import numpy as np

            X = np.zeros((1, n_features), dtype=float)
            # Prefer predict_proba if available
            if hasattr(model, "predict_proba"):
                model.predict_proba(X)
            else:
                model.predict(X)
        except NotFittedError as exc:
            raise RuntimeError(f"Model not fitted: {exc}") from exc
        except Exception as exc:
            raise RuntimeError(f"Model smoke-test prediction failed: {exc}") from exc

        logger.info("ModelLoader startup validation succeeded: model=%s features=%d", type(model).__name__, n_features)

    # --------------------------------------------------------

    def reload(self):

        self._model = None

        self._label_encoder = None


# ============================================================
# Singleton
# ============================================================

_loader = ModelLoader()


def get_model():

    return _loader.load_model()


def get_label_encoder():

    return _loader.load_label_encoder()


# Validate at import/startup to fail fast on missing or incompatible artifacts.
try:
    _loader.validate_startup()
except Exception:
    # Re-raise so the importing application can fail loudly; avoid silent failures.
    raise


# ============================================================
# Test
# ============================================================

if __name__ == "__main__":

    try:

        model = get_model()

        encoder = get_label_encoder()

        print(type(model))

        print(type(encoder))

        print()

        print("Model loaded successfully.")

    except Exception as e:

        print(e)