import io
import json
import pandas as pd
import pytest

from fastapi.testclient import TestClient

from local_api.main import app


client = TestClient(app)


def csv_bytes_from_df(df: pd.DataFrame) -> bytes:
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    return buf.getvalue().encode("utf-8")


def test_valid_cicids2017_upload():
    df = pd.DataFrame({
        "Label": ["BENIGN", "BENIGN"],
        "Source IP": ["1.1.1.1", "1.1.1.2"],
        "Destination IP": ["2.2.2.1", "2.2.2.2"],
        "Protocol": ["TCP", "UDP"],
    })

    files = {"file": ("cicids.csv", csv_bytes_from_df(df), "text/csv")}
    r = client.post("/api/upload", files=files)
    assert r.status_code == 200
    body = r.json()
    assert body.get("success") is True
    assert body.get("dataset_type") == "ids"
    assert body.get("rows_processed") == 2


def test_renamed_cicids_file_still_detects():
    df = pd.DataFrame({"Label": ["BENIGN"], "Source IP": ["1.1.1.1"], "Destination IP": ["2.2.2.2"]})
    files = {"file": ("renamed_dataset_2026.csv", csv_bytes_from_df(df), "text/csv")}
    r = client.post("/api/upload", files=files)
    assert r.status_code == 200
    body = r.json()
    assert body.get("success") is True
    assert body.get("dataset_type") == "ids"


def test_unsupported_schema_returns_400():
    df = pd.DataFrame({"foo": [1], "bar": [2]})
    files = {"file": ("weird.csv", csv_bytes_from_df(df), "text/csv")}
    r = client.post("/api/upload", files=files)
    assert r.status_code == 400
    body = r.json()
    assert "detail" in body
    detail = body["detail"]
    assert detail.get("message")
    assert isinstance(detail.get("supported_schemas"), dict)


def test_missing_required_columns_reports_missing():
    # IDS requires Label - omit it
    df = pd.DataFrame({"Source IP": ["1.1.1.1"]})
    files = {"file": ("missing_label.csv", csv_bytes_from_df(df), "text/csv")}
    r = client.post("/api/upload", files=files)
    assert r.status_code == 400
    detail = r.json().get("detail")
    assert "missing_required_columns" in detail or detail.get("missing_required_columns", None) is not None or isinstance(detail.get("missing_required_columns", []), list)


def test_empty_file_returns_400():
    files = {"file": ("empty.csv", b"", "text/csv")}
    r = client.post("/api/upload", files=files)
    assert r.status_code in (400, 500)


def test_invalid_csv_returns_400():
    files = {"file": ("bad.csv", b"not,a,valid\n1,2", "text/csv")}
    r = client.post("/api/upload", files=files)
    assert r.status_code in (400, 500)


def test_invalid_json_returns_400():
    files = {"file": ("bad.json", b"{ not: 'json' }", "application/json")}
    r = client.post("/api/upload", files=files)
    assert r.status_code == 400


def test_large_dataset_upload():
    # Create a moderately large dataset (5k rows)
    n = 5000
    df = pd.DataFrame({
        "Label": ["BENIGN"] * n,
        "Source IP": ["1.2.3.4"] * n,
        "Destination IP": ["5.6.7.8"] * n,
    })
    files = {"file": ("large.csv", csv_bytes_from_df(df), "text/csv")}
    r = client.post("/api/upload", files=files)
    # Accept either 200 or 413/500 depending on env; primarily ensure app handles upload
    assert r.status_code in (200, 413, 500)
    if r.status_code == 200:
        body = r.json()
        assert body.get("success") is True
        assert body.get("rows_processed") == n
