import sys
from pathlib import Path

import pandas as pd
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from processors.ids_processor import IDSProcessor


# ---------- helper: minimal valid IDS-style DataFrame ----------

def make_ids_df(**overrides):
    """Builds a DataFrame with the columns IDSProcessor expects, overridable per test."""
    base = {
        "Timestamp": ["2026-07-10 14:30:00"],
        "Source IP": ["10.0.0.5"],
        "Destination IP": ["10.0.0.6"],
        "Protocol": ["TCP"],
        "Label": ["BENIGN"],
    }
    base.update(overrides)
    return pd.DataFrame(base)


EXPECTED_COLUMNS = [
    "event_id", "timestamp", "source", "hostname", "username",
    "src_ip", "dst_ip", "protocol", "event_type", "severity", "raw_message",
]


# ---------- core mapping tests ----------

def test_normalize_maps_present_columns_correctly():
    """When all optional columns are present, they should be used directly."""
    processor = IDSProcessor()
    result = processor.normalize(make_ids_df())

    row = result.iloc[0]
    assert row["src_ip"] == "10.0.0.5"
    assert row["dst_ip"] == "10.0.0.6"
    assert row["protocol"] == "TCP"
    assert row["event_type"] == "BENIGN"
    assert row["source"] == "ids"
    assert row["hostname"] == "Unknown"
    assert row["username"] == "Unknown"


def test_normalize_output_has_correct_columns():
    """Output should contain exactly the expected schema columns."""
    processor = IDSProcessor()
    result = processor.normalize(make_ids_df())
    assert set(result.columns) == set(EXPECTED_COLUMNS)


def test_normalize_event_id_is_sequential():
    """event_id should be auto-generated as 1, 2, 3... matching row position, not read from data."""
    processor = IDSProcessor()
    df = make_ids_df(
        **{
            "Timestamp": ["2026-07-10 14:30:00", "2026-07-10 14:31:00", "2026-07-10 14:32:00"],
            "Source IP": ["10.0.0.5", "10.0.0.5", "10.0.0.5"],
            "Destination IP": ["10.0.0.6", "10.0.0.6", "10.0.0.6"],
            "Protocol": ["TCP", "TCP", "TCP"],
            "Label": ["BENIGN", "BENIGN", "BENIGN"],
        }
    )
    result = processor.normalize(df)
    assert result["event_id"].tolist() == [1, 2, 3]


# ---------- fallback logic for missing optional columns ----------

def test_normalize_defaults_src_ip_when_column_missing():
    """If 'Source IP' isn't present, src_ip should default to 'N/A'."""
    processor = IDSProcessor()
    df = make_ids_df().drop(columns=["Source IP"])
    result = processor.normalize(df)
    assert result.iloc[0]["src_ip"] == "N/A"


def test_normalize_defaults_dst_ip_when_column_missing():
    """If 'Destination IP' isn't present, dst_ip should default to 'N/A'."""
    processor = IDSProcessor()
    df = make_ids_df().drop(columns=["Destination IP"])
    result = processor.normalize(df)
    assert result.iloc[0]["dst_ip"] == "N/A"


def test_normalize_defaults_protocol_when_column_missing():
    """If 'Protocol' isn't present, protocol should default to 'Unknown'."""
    processor = IDSProcessor()
    df = make_ids_df().drop(columns=["Protocol"])
    result = processor.normalize(df)
    assert result.iloc[0]["protocol"] == "Unknown"


def test_normalize_defaults_timestamp_when_column_missing():
    """If 'Timestamp' isn't present, timestamp should default to NaT (missing), not crash."""
    processor = IDSProcessor()
    df = make_ids_df().drop(columns=["Timestamp"])
    result = processor.normalize(df)
    assert pd.isna(result.iloc[0]["timestamp"])


# ---------- severity mapping ----------

def test_normalize_maps_benign_label_to_low_severity():
    """A 'BENIGN' label should map to Low severity."""
    processor = IDSProcessor()
    result = processor.normalize(make_ids_df(Label=["BENIGN"]))
    assert result.iloc[0]["severity"] == "Low"


def test_normalize_maps_benign_label_case_insensitively():
    """Severity mapping should be case-insensitive - 'benign', 'Benign', 'BENIGN' should all map to Low."""
    processor = IDSProcessor()
    for label in ["benign", "Benign", "BENIGN"]:
        result = processor.normalize(make_ids_df(Label=[label]))
        assert result.iloc[0]["severity"] == "Low", f"Failed for label variant: {label}"


def test_normalize_maps_attack_label_to_high_severity():
    """Any non-benign label (e.g. an actual attack type) should map to High severity."""
    processor = IDSProcessor()
    result = processor.normalize(make_ids_df(Label=["DDoS"]))
    assert result.iloc[0]["severity"] == "High"


# ---------- validation behavior ----------

def test_normalize_raises_on_empty_dataframe():
    """An empty DataFrame should raise ValueError."""
    processor = IDSProcessor()
    with pytest.raises(ValueError):
        processor.normalize(pd.DataFrame())


def test_normalize_raises_when_label_column_missing():
    """The 'Label' column is required (it drives event_type and severity) - missing it should raise."""
    processor = IDSProcessor()
    df = make_ids_df().drop(columns=["Label"])
    with pytest.raises(ValueError):
        processor.normalize(df)


def test_normalize_strips_whitespace_from_column_names():
    """Column names with accidental leading/trailing spaces should still be recognized after stripping."""
    processor = IDSProcessor()
    df = make_ids_df()
    df.columns = [f" {col} " for col in df.columns]  # add stray spaces to every column name
    result = processor.normalize(df)
    assert result.iloc[0]["event_type"] == "BENIGN"


# ---------- real dataset sanity check ----------

IDS_FOLDER = (
    Path(__file__).resolve().parents[4]
    / "datasets"
    / "raw"
    / "ids"
)


@pytest.mark.skipif(not IDS_FOLDER.exists(), reason="Real IDS dataset folder not found")
def test_normalize_runs_successfully_on_real_dataset():
    """Sanity check: run against the first real CSV found in the IDS dataset folder."""
    csv_files = sorted(IDS_FOLDER.glob("*.csv"))
    if not csv_files:
        pytest.skip("No CSV files found in IDS dataset folder")

    df = pd.read_csv(csv_files[0], low_memory=False)
    processor = IDSProcessor()
    result = processor.normalize(df)

    assert len(result) == len(df)
    assert set(result.columns) == set(EXPECTED_COLUMNS)
    assert result["severity"].isin(["Low", "High"]).all()