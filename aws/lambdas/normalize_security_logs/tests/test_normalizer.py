import sys
from pathlib import Path

import pandas as pd
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from processors.normalize import Normalizer
from processors.windows_processor import WindowsProcessor
from processors.ids_processor import IDSProcessor


# ---------- helper: minimal valid Windows-style DataFrame ----------

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


def make_ids_df():
    return pd.DataFrame({
        "Timestamp": ["2026-07-10 14:30:00"],
        "Source IP": ["10.0.0.5"],
        "Destination IP": ["10.0.0.6"],
        "Protocol": ["TCP"],
        "Label": ["BENIGN"],
    })


# ---------- end-to-end routing tests ----------

def test_normalize_dataframe_routes_windows_path_to_windows_processor():
    """A path containing 'windows' should end up processed by WindowsProcessor's logic."""
    result = Normalizer.normalize_dataframe(make_windows_df(), "windows/windows_events.csv")
    assert result.iloc[0]["source"] == "windows"
    assert result.iloc[0]["hostname"] == "DESKTOP-01"


def test_normalize_dataframe_routes_ids_path_to_ids_processor():
    """A path containing 'ids' should end up processed by IDSProcessor's logic."""
    result = Normalizer.normalize_dataframe(make_ids_df(), "ids/Friday-WorkingHours.csv")
    assert result.iloc[0]["source"] == "ids"
    assert result.iloc[0]["src_ip"] == "10.0.0.5"


def test_normalize_dataframe_returns_correct_processor_output_shape():
    """The output should match what the underlying processor alone would produce."""
    df = make_windows_df()
    via_normalizer = Normalizer.normalize_dataframe(df, "windows/windows_events.csv")
    via_processor_directly = WindowsProcessor().normalize(make_windows_df())
    assert via_normalizer.columns.tolist() == via_processor_directly.columns.tolist()
    assert len(via_normalizer) == len(via_processor_directly)


# ---------- error propagation ----------

def test_normalize_dataframe_raises_for_unrecognized_path():
    """An unrecognized dataset path should raise ValueError - propagated from DatasetDetector."""
    with pytest.raises(ValueError):
        Normalizer.normalize_dataframe(make_windows_df(), "mystery_folder/unknown.csv")


def test_normalize_dataframe_raises_when_data_does_not_match_detected_type():
    """
    If the path says 'windows' but the actual DataFrame is IDS-shaped data
    (missing the columns WindowsProcessor requires), validation should still
    catch the mismatch and raise, rather than silently producing garbage output.
    """
    mismatched_df = make_ids_df()  # IDS-shaped data
    with pytest.raises(ValueError):
        Normalizer.normalize_dataframe(mismatched_df, "windows/windows_events.csv")


# ---------- real dataset sanity check ----------

REAL_DATASET_PATH = (
    Path(__file__).resolve().parents[4]
    / "datasets"
    / "raw"
    / "windows"
    / "windows_events.csv"
)


@pytest.mark.skipif(not REAL_DATASET_PATH.exists(), reason="Real Windows dataset file not found")
def test_normalize_dataframe_runs_successfully_on_real_dataset():
    """Full end-to-end sanity check: detect -> select processor -> normalize, on real data."""
    df = pd.read_csv(REAL_DATASET_PATH, low_memory=False)
    result = Normalizer.normalize_dataframe(df, dataset_path="windows/windows_events.csv")

    assert len(result) == len(df)
    assert (result["source"] == "windows").all()
    assert result.isnull().sum().sum() >= 0  # sanity: this should never error out even if there are nulls