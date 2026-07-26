"""
ML Engine Preprocessor

Converts validated features into a NumPy vector
that can be passed directly to the trained model.
"""

from __future__ import annotations

from typing import Dict, List

import numpy as np

from .validator import validate_features


# ==========================================================
# Feature Order
# ==========================================================

FEATURE_COLUMNS = [

    "hour",
    "minute",
    "day",
    "weekday",
    "month",

    "severity_encoded",
    "protocol_encoded",

    "src_internal",
    "dest_internal",
    "src_private",
    "dest_private",
    "src_loopback",
    "dest_loopback",

    "src_port",
    "dest_port",

    "event_category_encoded",

    "cvss_normalized",

    "ioc_flag",

    "mitre_weight",

    "asset_score",

    "threat_score",

    "rolling_event_count",

    "high_risk_event_count",

    "failed_login_count",

    "successful_login_count",

    "user_risk",

    "host_risk",

    "attack_frequency",

    "average_threat_score",

]


# ==========================================================
# Preprocessor
# ==========================================================

class FeaturePreprocessor:

    """
    Converts feature dictionaries into
    ML-ready NumPy vectors.
    """

    def preprocess(
        self,
        features: Dict,
    ) -> np.ndarray:

        validated = validate_features(
            features
        )

        vector = [

            validated[column]

            for column in FEATURE_COLUMNS

        ]

        return np.array(
            vector,
            dtype=np.float32,
        ).reshape(1, -1)


# ==========================================================
# Singleton
# ==========================================================

_preprocessor = FeaturePreprocessor()


def preprocess(
    features: Dict,
) -> np.ndarray:

    return _preprocessor.preprocess(
        features
    )


# ==========================================================
# Test
# ==========================================================

if __name__ == "__main__":

    sample = {

        feature: 1

        for feature in FEATURE_COLUMNS

    }

    vector = preprocess(sample)

    print(vector)

    print()

    print("Shape:", vector.shape)

    print("Dtype:", vector.dtype)