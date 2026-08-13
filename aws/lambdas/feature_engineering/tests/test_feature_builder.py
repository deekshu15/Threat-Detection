import copy

import pytest

from aws.lambdas.feature_engineering.feature_builder import (
    build_features,
)
from aws.lambdas.feature_engineering.validator import (
    MissingFieldError,
)


EVENT = {
    "event_id": "evt-001",
    "timestamp": "2026-01-15T12:00:00Z",
    "src_ip": "192.168.1.100",
    "dest_ip": "10.0.0.5",
    "severity": "High",
    "protocol": "TCP",
    "event_category": "Credential Attack",
    "asset_criticality": "High",
    "threat_score": 75.0,
    "cvss_score": 9.1,
    "matched_ioc": True,
    "mitre_technique_id": "T1110",
    "mitre_tactic": "Credential Access",
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

    with pytest.raises(MissingFieldError):
        build_features({})