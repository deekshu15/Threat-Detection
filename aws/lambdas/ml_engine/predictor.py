"""
Predictor

Loads the trained model and performs inference.
"""

from __future__ import annotations

from typing import Dict

import numpy as np

from .model_loader import (
    get_model,
    get_label_encoder,
)


class Predictor:

    def __init__(self):

        self.model = get_model()

        self.encoder = get_label_encoder()

    def predict(self, vector):

        X = np.asarray(
            vector,
            dtype=np.float32,
        ).reshape(1, -1)

        prediction = self.model.predict(X)[0]

        probabilities = self.model.predict_proba(X)[0]

        confidence = float(
            probabilities.max()
        )

        label = self.encoder.inverse_transform(
            [prediction]
        )[0]

        return {

            "prediction": label,

            "prediction_index": int(prediction),

            "confidence": confidence,

            "probabilities": probabilities.tolist(),

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