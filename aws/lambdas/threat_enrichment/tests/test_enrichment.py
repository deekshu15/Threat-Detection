"""
Unit Tests for enrichment.py
"""

import pytest

from aws.lambdas.threat_enrichment.enrichment import (
    enrich_event,
    ThreatEnrichment,
)


def sample_event():

    return {

        "timestamp": "2026-07-20T10:30:00Z",

        "source": "windows",

        "severity": "High",

        "event_type": 4625,

        "mitre": {

            "technique": "T1110",

            "tactic": "Credential Access"

        }

    }


def test_event_validation():

    event = sample_event()

    ThreatEnrichment.validate_event(event)


def test_missing_required_field():

    event = sample_event()

    del event["source"]

    with pytest.raises(ValueError):

        ThreatEnrichment.validate_event(event)


def test_invalid_mitre():

    event = sample_event()

    event["mitre"] = "invalid"

    with pytest.raises(ValueError):

        ThreatEnrichment.validate_event(event)


def test_known_attack():

    event = sample_event()

    assert ThreatEnrichment.determine_known_attack(event) is True


def test_unknown_attack():

    event = sample_event()

    event["mitre"] = {}

    assert ThreatEnrichment.determine_known_attack(event) is False


def test_enrichment():

    event = sample_event()

    enriched = enrich_event(event)

    assert "threat_intelligence" in enriched

    ti = enriched["threat_intelligence"]

    assert ti["attack_category"] == "Credential Attack"

    assert ti["asset_type"] == "Windows Server"

    assert ti["asset_criticality"] == "High"

    assert ti["severity_score"] == 75

    assert ti["risk_weight"] == 80

    assert ti["known_attack"] is True


def test_unknown_source():

    event = sample_event()

    event["source"] = "abc"

    enriched = enrich_event(event)

    ti = enriched["threat_intelligence"]

    assert ti["asset_type"] == "Unknown Asset"

    assert ti["asset_criticality"] == "Medium"


def test_unknown_technique():

    event = sample_event()

    event["mitre"]["technique"] = "T9999"

    enriched = enrich_event(event)

    ti = enriched["threat_intelligence"]

    assert ti["attack_category"] == "Unknown"


def test_original_event_not_modified():

    event = sample_event()

    original = event.copy()

    enrich_event(event)

    assert event == original