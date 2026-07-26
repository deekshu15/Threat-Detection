import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from utils.schema import SecurityEvent, VulnerabilityEvent


# ---------- SecurityEvent ----------

def test_security_event_required_fields_are_set():
    """The 3 required fields should be stored exactly as passed in."""
    event = SecurityEvent(
        event_id="1",
        timestamp="2026-07-10 14:30:00",
        source="windows",
    )
    assert event.event_id == "1"
    assert event.timestamp == "2026-07-10 14:30:00"
    assert event.source == "windows"


def test_security_event_optional_fields_default_to_none():
    """Optional fields should default to None when not provided."""
    event = SecurityEvent(
        event_id="1",
        timestamp="2026-07-10 14:30:00",
        source="windows",
    )
    assert event.hostname is None
    assert event.username is None
    assert event.src_ip is None
    assert event.dst_ip is None
    assert event.protocol is None
    assert event.event_type is None
    assert event.severity is None
    assert event.raw_message is None
    assert event.ingestion_time is None


def test_security_event_optional_fields_can_be_set():
    """Optional fields should store the values passed in, not silently ignore them."""
    event = SecurityEvent(
        event_id="1",
        timestamp="2026-07-10 14:30:00",
        source="windows",
        hostname="DESKTOP-01",
        username="Administrator",
        severity="High",
    )
    assert event.hostname == "DESKTOP-01"
    assert event.username == "Administrator"
    assert event.severity == "High"


def test_security_event_to_dict_contains_all_fields():
    """to_dict() should produce a dictionary with every field, correctly matching the object's values."""
    event = SecurityEvent(
        event_id="1",
        timestamp="2026-07-10 14:30:00",
        source="windows",
        hostname="DESKTOP-01",
        username="Administrator",
        severity="High",
    )
    result = event.to_dict()

    assert isinstance(result, dict)
    assert result["event_id"] == "1"
    assert result["timestamp"] == "2026-07-10 14:30:00"
    assert result["source"] == "windows"
    assert result["hostname"] == "DESKTOP-01"
    assert result["username"] == "Administrator"
    assert result["severity"] == "High"
    # Fields never set should still appear in the dict, as None
    assert result["src_ip"] is None
    assert result["dst_ip"] is None


# ---------- VulnerabilityEvent ----------

def test_vulnerability_event_required_fields_are_set():
    """event_id and timestamp are required and should store correctly."""
    event = VulnerabilityEvent(
        event_id="CVE-2026-0001",
        timestamp="2026-01-01T00:00:00.000",
    )
    assert event.event_id == "CVE-2026-0001"
    assert event.timestamp == "2026-01-01T00:00:00.000"


def test_vulnerability_event_defaults_are_correct():
    """All the optional fields have specific, meaningful defaults - not just None - so check them exactly."""
    event = VulnerabilityEvent(
        event_id="CVE-2026-0001",
        timestamp="2026-01-01T00:00:00.000",
    )
    assert event.source == "cve"
    assert event.event_type == "vulnerability"
    assert event.severity == "UNKNOWN"
    assert event.cvss_score == 0.0
    assert event.cwe == ""
    assert event.vendor == ""
    assert event.product == ""
    assert event.description == ""
    assert event.references == []


def test_vulnerability_event_references_default_is_independent_per_instance():
    """
    This is a classic Python gotcha: mutable defaults (like a list) must use
    field(default_factory=list), not a shared list, or every instance would
    accidentally share and corrupt the same list. Confirm that's not happening.
    """
    event1 = VulnerabilityEvent(event_id="CVE-1", timestamp="2026-01-01")
    event2 = VulnerabilityEvent(event_id="CVE-2", timestamp="2026-01-02")

    event1.references.append("https://example.com/one")

    assert event1.references == ["https://example.com/one"]
    assert event2.references == [], "event2's references list was accidentally shared with event1's!"


def test_vulnerability_event_to_dict_contains_all_fields():
    """to_dict() should correctly serialize every field, including the references list."""
    event = VulnerabilityEvent(
        event_id="CVE-2026-0001",
        timestamp="2026-01-01T00:00:00.000",
        severity="HIGH",
        cvss_score=7.5,
        cwe="CWE-79",
        vendor="TestVendor",
        product="TestProduct",
        description="Test description.",
        references=["https://example.com/advisory"],
    )
    result = event.to_dict()

    assert isinstance(result, dict)
    assert result["event_id"] == "CVE-2026-0001"
    assert result["severity"] == "HIGH"
    assert result["cvss_score"] == 7.5
    assert result["cwe"] == "CWE-79"
    assert result["vendor"] == "TestVendor"
    assert result["product"] == "TestProduct"
    assert result["description"] == "Test description."
    assert result["references"] == ["https://example.com/advisory"]