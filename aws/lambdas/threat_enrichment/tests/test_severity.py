"""
Unit Tests for severity.py
"""

import pytest

from aws.lambdas.threat_enrichment.severity import(
    SeverityCalculator,
    calculate_severity,
)


def test_valid_severity():
    assert SeverityCalculator.is_valid("Low") is True
    assert SeverityCalculator.is_valid("Medium") is True
    assert SeverityCalculator.is_valid("High") is True
    assert SeverityCalculator.is_valid("Critical") is True


def test_invalid_severity():
    assert SeverityCalculator.is_valid("Unknown") is False
    assert SeverityCalculator.is_valid("") is False
    assert SeverityCalculator.is_valid(None) is False


def test_severity_scores():

    assert SeverityCalculator.get_score("Low") == 25

    assert SeverityCalculator.get_score("Medium") == 50

    assert SeverityCalculator.get_score("High") == 75

    assert SeverityCalculator.get_score("Critical") == 100


def test_risk_weights():

    assert SeverityCalculator.get_risk_weight("Low") == 20

    assert SeverityCalculator.get_risk_weight("Medium") == 50

    assert SeverityCalculator.get_risk_weight("High") == 80

    assert SeverityCalculator.get_risk_weight("Critical") == 100


def test_default_score():

    assert SeverityCalculator.get_score("ABC") == 50


def test_default_risk_weight():

    assert SeverityCalculator.get_risk_weight("ABC") == 50


def test_calculate_severity():

    event = {
        "severity": "High"
    }

    result = calculate_severity(event)

    assert result["severity"] == "High"

    assert result["severity_score"] == 75

    assert result["risk_weight"] == 80


def test_missing_severity():

    event = {}

    result = calculate_severity(event)

    assert result["severity"] == "Medium"

    assert result["severity_score"] == 50

    assert result["risk_weight"] == 50