import copy

import pytest

from aws.lambdas.feature_engineering.feature_builder import (
    build_features,
)


EVENT = {

    "source": "windows",

    "mitre": {
        "technique": "T1110"
    },

    "threat_intelligence": {

        "severity_score": 75,

        "risk_weight": 80,

        "asset_criticality": "High",

        "known_attack": True,
    },
}


def test_build_features():

    result = build_features(copy.deepcopy(EVENT))

    assert "features" in result

    features = result["features"]

    assert features["source_id"] == 1
    assert features["technique_id"] == 1110
    assert features["asset_score"] == 3
    assert features["known_attack"] == 1
    assert features["severity_score"] == 75
    assert features["risk_weight"] == 80


def test_original_event_preserved():

    result = build_features(copy.deepcopy(EVENT))

    assert result["source"] == "windows"
    assert result["mitre"]["technique"] == "T1110"


def test_invalid_event():

    with pytest.raises(ValueError):
        build_features({})