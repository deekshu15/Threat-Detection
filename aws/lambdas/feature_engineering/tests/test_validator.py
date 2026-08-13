import pytest

from aws.lambdas.feature_engineering.validator import (
    validate_event,
    MissingFieldError,
)


VALID_EVENT = {
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
}


def test_valid_event():
    validate_event(VALID_EVENT)


def test_missing_event_id():

    event = VALID_EVENT.copy()

    del event["event_id"]

    with pytest.raises(MissingFieldError):
        validate_event(event)


def test_missing_timestamp():

    event = VALID_EVENT.copy()

    del event["timestamp"]

    with pytest.raises(MissingFieldError):
        validate_event(event)


def test_missing_src_ip():

    event = VALID_EVENT.copy()

    del event["src_ip"]

    with pytest.raises(MissingFieldError):
        validate_event(event)


def test_missing_dest_ip():

    event = VALID_EVENT.copy()

    del event["dest_ip"]

    with pytest.raises(MissingFieldError):
        validate_event(event)


def test_missing_severity():

    event = VALID_EVENT.copy()

    del event["severity"]

    with pytest.raises(MissingFieldError):
        validate_event(event)


def test_missing_threat_score():

    event = VALID_EVENT.copy()

    del event["threat_score"]

    with pytest.raises(MissingFieldError):
        validate_event(event)