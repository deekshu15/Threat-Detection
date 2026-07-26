import sys
from pathlib import Path

import pandas as pd
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from processors.windows_processor import WindowsProcessor


# ---------- helper: minimal valid Windows-style DataFrame ----------

def make_windows_df(**overrides):
    """Builds a DataFrame with every column the mapping requires, overridable per test."""
    base = {
        "EventRecordID": [101],
        "SystemTime": ["2026-07-10 14:30:00"],
        "Computer": ["DESKTOP-01"],
        "User": ["Administrator"],
        "SourceIp": ["192.168.1.10"],
        "DestinationIp": ["192.168.1.20"],
        "Protocol": ["TCP"],
        "EventID": [4624],
        "Level": [3],  # maps to "High"
        "{Event_NS}EventXML": ["<Event>...</Event>"],
    }
    base.update(overrides)
    return pd.DataFrame(base)


EXPECTED_COLUMNS = [
    "event_id", "timestamp", "source", "hostname", "username",
    "src_ip", "dst_ip", "protocol", "event_type", "severity", "raw_message",
]


# ---------- core mapping tests ----------

def test_normalize_maps_columns_correctly():
    """Each schema field should pull from the correct original Windows column."""
    processor = WindowsProcessor()
    result = processor.normalize(make_windows_df())

    row = result.iloc[0]
    assert row["event_id"] == 101
    assert row["hostname"] == "DESKTOP-01"
    assert row["username"] == "Administrator"
    assert row["src_ip"] == "192.168.1.10"
    assert row["dst_ip"] == "192.168.1.20"
    assert row["protocol"] == "TCP"
    assert row["event_type"] == 4624
    assert row["source"] == "windows"


def test_normalize_output_has_correct_columns_in_order():
    """Output should always have exactly these 11 columns, in this order."""
    processor = WindowsProcessor()
    result = processor.normalize(make_windows_df())
    assert result.columns.tolist() == EXPECTED_COLUMNS


# ---------- severity mapping ----------

def test_normalize_maps_known_severity_level():
    """Level 3 should map to 'High', per SEVERITY_MAP."""
    processor = WindowsProcessor()
    result = processor.normalize(make_windows_df(Level=[3]))
    assert result.iloc[0]["severity"] == "High"


def test_normalize_maps_unknown_severity_level_to_unknown():
    """A Level value not in SEVERITY_MAP (e.g. 99) should default to 'Unknown', not crash."""
    processor = WindowsProcessor()
    result = processor.normalize(make_windows_df(Level=[99]))
    assert result.iloc[0]["severity"] == "Unknown"


# ---------- username fallback logic ----------

def test_normalize_username_falls_back_to_target_user_name():
    """When User is null but TargetUserName is present, username should use TargetUserName."""
    processor = WindowsProcessor()
    df = make_windows_df(User=[None])
    df["TargetUserName"] = ["FallbackUser"]
    result = processor.normalize(df)
    assert result.iloc[0]["username"] == "FallbackUser"


def test_normalize_username_prefers_user_over_target_user_name():
    """When both User and TargetUserName are present, User should win."""
    processor = WindowsProcessor()
    df = make_windows_df(User=["PrimaryUser"])
    df["TargetUserName"] = ["FallbackUser"]
    result = processor.normalize(df)
    assert result.iloc[0]["username"] == "PrimaryUser"


# ---------- timestamp handling ----------

def test_normalize_converts_valid_timestamp():
    """A valid timestamp string should be converted to an actual datetime."""
    processor = WindowsProcessor()
    result = processor.normalize(make_windows_df(SystemTime=["2026-07-10 14:30:00"]))
    assert pd.notna(result.iloc[0]["timestamp"])
    assert isinstance(result.iloc[0]["timestamp"], pd.Timestamp)


def test_normalize_handles_invalid_timestamp_gracefully():
    """An unparseable timestamp should become NaT (missing), not crash the whole process."""
    processor = WindowsProcessor()
    result = processor.normalize(make_windows_df(SystemTime=["not-a-real-date"]))
    assert pd.isna(result.iloc[0]["timestamp"])


# ---------- validation behavior ----------

def test_normalize_raises_on_empty_dataframe():
    """An empty DataFrame should raise ValueError via validate_not_empty."""
    processor = WindowsProcessor()
    empty_df = pd.DataFrame()
    with pytest.raises(ValueError):
        processor.normalize(empty_df)


def test_normalize_raises_when_required_mapping_column_missing():
    """If a column the mapping depends on (e.g. Computer) is missing, validation should raise."""
    processor = WindowsProcessor()
    df = make_windows_df()
    df = df.drop(columns=["Computer"])
    with pytest.raises(ValueError):
        processor.normalize(df)


# ---------- real dataset sanity check ----------

REAL_DATASET = (
    Path(__file__).resolve().parents[4]
    / "datasets"
    / "raw"
    / "windows"
    / "windows_events.csv"
)


@pytest.mark.skipif(not REAL_DATASET.exists(), reason="Real Windows dataset file not found")
def test_normalize_runs_successfully_on_real_dataset():
    """Sanity check: the processor should run end-to-end on the real dataset without crashing."""
    df = pd.read_csv(REAL_DATASET, low_memory=False)
    processor = WindowsProcessor()
    result = processor.normalize(df)

    assert len(result) == len(df), "Row count should be preserved through normalization"
    assert result.columns.tolist() == EXPECTED_COLUMNS
    assert (result["source"] == "windows").all()