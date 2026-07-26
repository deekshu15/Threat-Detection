import pytest

from aws.lambdas.feature_engineering.validator import (
    validate_event,
)


VALID_EVENT = {

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


def test_valid_event():
    validate_event(VALID_EVENT)


def test_missing_source():

    event = VALID_EVENT.copy()

    del event["source"]

    with pytest.raises(ValueError):
        validate_event(event)


def test_missing_mitre():

    event = VALID_EVENT.copy()

    del event["mitre"]

    with pytest.raises(ValueError):
        validate_event(event)


def test_missing_threat():

    event = VALID_EVENT.copy()

    del event["threat_intelligence"]

    with pytest.raises(ValueError):
        validate_event(event)


def test_missing_technique():

    event = VALID_EVENT.copy()

    event["mitre"] = {}

    with pytest.raises(ValueError):
        validate_event(event)


def test_missing_asset():

    event = VALID_EVENT.copy()

    event["threat_intelligence"] = {
        "severity_score": 75,
        "risk_weight": 80,
        "known_attack": True,
    }

    with pytest.raises(ValueError):
        validate_event(event)