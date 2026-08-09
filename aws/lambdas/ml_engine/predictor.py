"""
Predictor

Loads the trained model and performs inference.
"""

from __future__ import annotations

from typing import Dict, List
import logging

import numpy as np

from .model_loader import (
    get_model,
    get_label_encoder,
)


class Predictor:

    def __init__(self):

        self.model = get_model()

        self.encoder = get_label_encoder()
        self.logger = logging.getLogger("ml_engine.predictor")

    def predict(self, vector):

        X = np.asarray(
            vector,
            dtype=np.float32,
        ).reshape(1, -1)

        try:
            prediction_index = int(self.model.predict(X)[0])
        except Exception as exc:
            self.logger.exception("Prediction failed")
            raise

        # Probabilities (safe fallback)
        probabilities: List[float] = []
        confidence = 0.0
        try:
            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(X)[0]
                probabilities = [float(p) for p in probs]
                confidence = float(max(probabilities))
            else:
                # Fallback: use decision_function if available
                if hasattr(self.model, "decision_function"):
                    scores = self.model.decision_function(X)
                    # Turn scores into softmax-like probabilities
                    exp = np.exp(scores - np.max(scores))
                    probs = (exp / exp.sum(axis=1, keepdims=True))[0]
                    probabilities = [float(p) for p in probs]
                    confidence = float(max(probabilities))
                else:
                    probabilities = []
                    confidence = 0.0
        except Exception:
            self.logger.exception("Probability extraction failed, continuing with empty probabilities")

        try:
            label = self.encoder.inverse_transform([prediction_index])[0]
        except Exception:
            self.logger.exception("Label decoding failed")
            label = str(prediction_index)

        # Build top-3 predictions
        top_predictions = []
        try:
            if probabilities:
                labels = self.encoder.inverse_transform(list(range(len(probabilities))))
                paired = list(zip(labels, probabilities))
                paired.sort(key=lambda t: t[1], reverse=True)
                for lab, prob in paired[:3]:
                    top_predictions.append({"label": lab, "confidence": float(prob)})
        except Exception:
            self.logger.exception("Top predictions construction failed")

        return {
            "prediction": label,
            "prediction_index": prediction_index,
            "confidence": float(confidence),
            "probabilities": probabilities,
            "top_predictions": top_predictions,
            "model_name": getattr(self.model, "__class__", type(self.model)).__name__,
            "feature_count": int(getattr(self.model, "n_features_in_", -1)),
        }


_predictor = Predictor()


def predict(vector):

    return _predictor.predict(vector)


# --------------------------------------------------
# Local Test
# --------------------------------------------------

if __name__ == "__main__":

    sample = [

        10,
        15,
        25,
        5,
        7,
        3,
        1,
        1,
        1,
        1,
        0,
        0,
        50555,
        443,
        14,
        0.98,
        1,
        14,
        4,
        92.4,
        1,
        1,
        0,
        0,
        14,
        2,
        1,
        1.0,
        92.4,

    ]

    from pprint import pprint

    pprint(
        predict(sample)
    )