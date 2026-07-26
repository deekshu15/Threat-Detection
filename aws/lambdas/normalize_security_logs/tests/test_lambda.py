import sys
from pathlib import Path

import pandas as pd
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

import lambda_function
from lambda_function import lambda_handler
from config import Config


# ---------- helpers ----------

def make_windows_df():
    return pd.DataFrame({
        "EventRecordID": [101],
        "SystemTime": ["2026-07-10 14:30:00"],
        "Computer": ["DESKTOP-01"],
        "User": ["Administrator"],
        "SourceIp": ["192.168.1.10"],
        "DestinationIp": ["192.168.1.20"],
        "Protocol": ["TCP"],
        "EventID": [4624],
        "Level": [3],
        "{Event_NS}EventXML": ["<Event>...</Event>"],
    })


def make_s3_event(key, bucket="ai-threat-raw-logs-deekshitha"):
    return {
        "Records": [
            {"s3": {"bucket": {"name": bucket}, "object": {"key": key}}}
        ]
    }


# ---------- success path: CSV (Windows) ----------

def test_lambda_handler_success_for_windows_csv(monkeypatch):
    """A valid Windows CSV event should process successfully and return statusCode 200."""
    monkeypatch.setattr(lambda_function.s3_helper, "read_csv", lambda bucket, key: make_windows_df())

    uploaded = {}
    def fake_upload_parquet(dataframe, bucket, key):
        uploaded["dataframe"] = dataframe
        uploaded["bucket"] = bucket
        uploaded["key"] = key
    monkeypatch.setattr(lambda_function.s3_helper, "upload_parquet", fake_upload_parquet)

    event = make_s3_event("windows/windows_events.csv")
    response = lambda_handler(event, None)

    assert response["statusCode"] == 200
    assert response["body"]["rows"] == 1
    assert uploaded["bucket"] == Config.PROCESSED_BUCKET
    assert uploaded["dataframe"].iloc[0]["source"] == "windows"


def test_lambda_handler_generates_correct_output_key(monkeypatch):
    """Output key should use Config.NORMALIZED_PREFIX + original filename (no extension) + .parquet"""
    monkeypatch.setattr(lambda_function.s3_helper, "read_csv", lambda bucket, key: make_windows_df())

    uploaded = {}
    monkeypatch.setattr(
        lambda_function.s3_helper, "upload_parquet",
        lambda dataframe, bucket, key: uploaded.update(key=key)
    )

    event = make_s3_event("windows/windows_events.csv")
    lambda_handler(event, None)

    assert uploaded["key"] == f"{Config.NORMALIZED_PREFIX}windows_events.parquet"


# ---------- success path: JSON (CVE) ----------

def test_lambda_handler_success_for_cve_json(monkeypatch):
    """
    A CVE JSON event should also succeed. This specifically confirms the
    DataFrame-wrapped-dict behavior we verified separately actually works
    end-to-end through the real lambda_handler, not just in isolation.
    """
    sample_cve_data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-0001",
                    "published": "2026-01-01",
                    "descriptions": [{"lang": "en", "value": "test"}],
                    "affected": [],
                    "metrics": {},
                    "weaknesses": [],
                    "references": [],
                }
            }
        ]
    }
    monkeypatch.setattr(lambda_function.s3_helper, "read_json", lambda bucket, key: sample_cve_data)

    uploaded = {}
    monkeypatch.setattr(
        lambda_function.s3_helper, "upload_parquet",
        lambda dataframe, bucket, key: uploaded.update(dataframe=dataframe)
    )

    event = make_s3_event("cve/nvdcve-2.0-2026.json")
    response = lambda_handler(event, None)

    assert response["statusCode"] == 200
    assert response["body"]["rows"] == 1


# ---------- error handling ----------

def test_lambda_handler_returns_500_for_unsupported_extension(monkeypatch):
    """A file extension that's neither .csv, .json, nor .parquet should fail gracefully with 500."""
    event = make_s3_event("windows/weird_file.txt")
    response = lambda_handler(event, None)

    assert response["statusCode"] == 500
    assert "Unsupported file type" in response["body"]


def test_lambda_handler_returns_500_for_malformed_event():
    """An event missing the expected 'Records' structure should not crash - it should return 500."""
    response = lambda_handler({}, None)
    assert response["statusCode"] == 500


def test_lambda_handler_returns_500_for_unrecognized_dataset_path(monkeypatch):
    """A path DatasetDetector can't classify should be caught and returned as a 500, not raised."""
    monkeypatch.setattr(lambda_function.s3_helper, "read_csv", lambda bucket, key: make_windows_df())
    event = make_s3_event("mystery_folder/unknown.csv")
    response = lambda_handler(event, None)
    assert response["statusCode"] == 500


def test_lambda_handler_returns_500_when_data_fails_validation(monkeypatch):
    """If the data doesn't match what the detected processor requires, that should surface as a 500, not crash the Lambda runtime itself."""
    bad_df = pd.DataFrame({"SomeUnrelatedColumn": [1, 2, 3]})
    monkeypatch.setattr(lambda_function.s3_helper, "read_csv", lambda bucket, key: bad_df)
    event = make_s3_event("windows/windows_events.csv")
    response = lambda_handler(event, None)
    assert response["statusCode"] == 500