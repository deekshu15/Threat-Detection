import pytest

from aws.lambdas.recommendation_engine.validator import (
    validate_incident,
)


def test_validator_success(sample_incident):

    incident = validate_incident(
        sample_incident
    )

    assert incident.incident_id == "INC-1001"


def test_invalid_severity(sample_incident):

    sample_incident["severity"] = "ABC"

    with pytest.raises(ValueError):

        validate_incident(sample_incident)


def test_invalid_priority(sample_incident):

    sample_incident["priority"] = "P10"

    with pytest.raises(ValueError):

        validate_incident(sample_incident)


def test_negative_events(sample_incident):

    sample_incident["total_events"] = -5

    with pytest.raises(ValueError):

        validate_incident(sample_incident)


def test_confidence_clamped(sample_incident):

    sample_incident["confidence"] = 5

    result = validate_incident(sample_incident)

    assert result.confidence == 1.0