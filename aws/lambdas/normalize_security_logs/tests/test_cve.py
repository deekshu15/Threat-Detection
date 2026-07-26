import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from processors.cve_processor import CVEProcessor


# ---------- helpers: small hand-crafted sample data ----------

def make_cve_data(**overrides):
    """Builds a minimal NVD-style CVE dict, with fields overridable for each test."""
    base = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-0001",
                    "published": "2026-01-01T00:00:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "Test vulnerability description."}
                    ],
                    "affected": [
                        {"affectedData": [{"vendor": "TestVendor", "product": "TestProduct"}]}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseSeverity": "HIGH", "baseScore": 7.5}}
                        ]
                    },
                    "weaknesses": [
                        {"description": [{"value": "CWE-79"}]}
                    ],
                    "references": [
                        {"url": "https://example.com/advisory"}
                    ],
                }
            }
        ]
    }
    base["vulnerabilities"][0]["cve"].update(overrides)
    return base


# ---------- core extraction tests ----------

def test_normalize_extracts_all_fields_correctly():
    """When all fields are present, every value should be extracted correctly."""
    processor = CVEProcessor()
    records = processor.normalize(make_cve_data())

    assert len(records) == 1
    record = records[0]

    assert record.event_id == "CVE-2026-0001"
    assert record.timestamp == "2026-01-01T00:00:00.000"
    assert record.severity == "HIGH"
    assert record.cvss_score == 7.5
    assert record.cwe == "CWE-79"
    assert record.vendor == "TestVendor"
    assert record.product == "TestProduct"
    assert record.description == "Test vulnerability description."
    assert record.references == ["https://example.com/advisory"]


def test_normalize_returns_empty_list_for_no_vulnerabilities():
    """An empty vulnerabilities list should produce an empty result, not an error."""
    processor = CVEProcessor()
    records = processor.normalize({"vulnerabilities": []})
    assert records == []


# ---------- default/fallback behavior tests ----------

def test_normalize_defaults_description_when_no_english_entry():
    """If there's no English description, description should default to empty string, not crash."""
    processor = CVEProcessor()
    data = make_cve_data(descriptions=[{"lang": "fr", "value": "Une description en français."}])
    records = processor.normalize(data)
    assert records[0].description == ""


def test_normalize_defaults_severity_and_score_when_no_cvss_metrics():
    """If cvssMetricV31 is missing, severity should default to UNKNOWN and score to 0.0."""
    processor = CVEProcessor()
    data = make_cve_data(metrics={})
    records = processor.normalize(data)
    assert records[0].severity == "UNKNOWN"
    assert records[0].cvss_score == 0.0


def test_normalize_defaults_cwe_when_no_weaknesses():
    """If weaknesses is missing/empty, cwe should default to empty string."""
    processor = CVEProcessor()
    data = make_cve_data(weaknesses=[])
    records = processor.normalize(data)
    assert records[0].cwe == ""


def test_normalize_defaults_vendor_and_product_when_no_affected_data():
    """If affected/affectedData is missing, vendor and product should default to empty strings."""
    processor = CVEProcessor()
    data = make_cve_data(affected=[])
    records = processor.normalize(data)
    assert records[0].vendor == ""
    assert records[0].product == ""


def test_normalize_handles_empty_references():
    """An empty references list should produce an empty list, not crash."""
    processor = CVEProcessor()
    data = make_cve_data(references=[])
    records = processor.normalize(data)
    assert records[0].references == []


# ---------- real dataset sanity check ----------

REAL_DATASET = (
    Path(__file__).resolve().parents[4]
    / "datasets"
    / "raw"
    / "cve"
    / "nvdcve-2.0-recent.json"
)


@pytest.mark.skipif(not REAL_DATASET.exists(), reason="Real CVE dataset file not found")
def test_normalize_runs_successfully_on_real_dataset():
    """Sanity check: the processor should run on the real dataset without crashing,
    and every record should have the basic fields populated with correct types."""
    with open(REAL_DATASET, "r", encoding="utf-8") as f:
        data = json.load(f)

    processor = CVEProcessor()
    records = processor.normalize(data)

    assert len(records) > 0, "Expected at least one CVE record from the real dataset"

    for record in records:
        assert record.event_id, "event_id should never be empty"
        assert isinstance(record.cvss_score, (int, float))
        assert isinstance(record.references, list)