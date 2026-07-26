"""
ML Engine Validator

Validates engineered feature payloads before inference.

Author:
AI Assisted Threat Detection Dashboard
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


# ============================================================
# Required Features
# ============================================================

REQUIRED_FEATURES = [

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


# ============================================================
# Dataclass
# ============================================================

@dataclass(slots=True)
class ValidatedFeatures:

    values: Dict[str, float]


# ============================================================
# Validator
# ============================================================

class FeatureValidator:

    """
    Validates feature dictionaries
    before model inference.
    """

    def validate(
        self,
        features: Dict[str, Any],
    ) -> ValidatedFeatures:

        if not isinstance(features, dict):
            raise ValueError(
                "Features must be a dictionary."
            )

        validated = {}

        missing = []

        for feature in REQUIRED_FEATURES:

            if feature not in features:
                missing.append(feature)
                continue

            value = features[feature]

            if isinstance(value, bool):
                value = int(value)

            try:
                validated[feature] = float(value)

            except Exception:

                raise ValueError(
                    f"Feature '{feature}' "
                    f"must be numeric."
                )

        if missing:

            raise ValueError(

                "Missing required features: "

                + ", ".join(missing)

            )

        return ValidatedFeatures(
            validated
        )


# ============================================================
# Singleton
# ============================================================

_validator = FeatureValidator()


def validate_features(
    features: Dict[str, Any],
) -> Dict[str, float]:

    return _validator.validate(
        features
    ).values


# ============================================================
# Test
# ============================================================

if __name__ == "__main__":

    sample = {

        feature: 1

        for feature in REQUIRED_FEATURES

    }

    result = validate_features(sample)

    print(result)