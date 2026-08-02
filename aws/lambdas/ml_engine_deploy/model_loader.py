"""
ML Model Loader

Loads trained models and encoders from disk.

Author:
AI Assisted Threat Detection Dashboard
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import joblib


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