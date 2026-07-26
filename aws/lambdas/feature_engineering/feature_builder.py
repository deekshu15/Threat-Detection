"""
feature_builder.py

Feature Builder

Responsibilities
----------------
1. Validate enriched security events.
2. Encode categorical values.
3. Extract numerical features.
4. Produce ML-ready feature vector.
"""

from typing import Dict

from aws.lambdas.feature_engineering.validator import validate_event

from aws.lambdas.feature_engineering.encoders import (
    FeatureEncoder,
)


class FeatureBuilder:
    """
    Builds machine-learning feature vectors from enriched events.
    """

    @classmethod
    def build(cls, event: Dict) -> Dict:
        """
        Build feature vector.

        Parameters
        ----------
        event : dict
            Enriched security event.

        Returns
        -------
        dict
            Original event with a 'features' section.
        """

        validate_event(event)

        threat = event["threat_intelligence"]
        mitre = event["mitre"]

        encoded = FeatureEncoder.encode_event(
            source=event["source"],
            technique=mitre["technique"],
            asset=threat["asset_criticality"],
            known_attack=threat["known_attack"],
        )

        features = {

            # -----------------------------
            # Encoded Features
            # -----------------------------
            "source_id":
                encoded["source_id"],

            "technique_id":
                encoded["technique_id"],

            "asset_score":
                encoded["asset_score"],

            "known_attack":
                encoded["known_attack"],

            # -----------------------------
            # Numerical Features
            # -----------------------------
            "severity_score":
                threat["severity_score"],

            "risk_weight":
                threat["risk_weight"],
        }

        result = event.copy()
        result["features"] = features

        return result


def build_features(event: Dict) -> Dict:
    """
    Convenience wrapper.
    """

    return FeatureBuilder.build(event)