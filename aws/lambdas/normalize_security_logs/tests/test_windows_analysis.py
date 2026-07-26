import os
from pathlib import Path

import pandas as pd
import pytest

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(
    BASE_DIR, "..", "..", "..", "..", "datasets", "raw", "windows", "windows_events.csv"
)

REQUIRED_COLUMNS = [
    "EventRecordID",
    "SystemTime",
    "Computer",
    "EventID",
    "Level",
]

OPTIONAL_BUT_EXPECTED_COLUMNS = [
    "User",
    "TargetUserName",
    "SourceIp",
    "DestinationIp",
    "Protocol",
    "{Event_NS}EventXML",
]


@pytest.fixture(scope="module")
def windows_df():
    """Load the real dataset once and reuse it across all tests in this file (faster than reloading per test)."""
    if not os.path.exists(DATA_PATH):
        pytest.skip("Real Windows dataset file not found")
    return pd.read_csv(DATA_PATH, low_memory=False)


def test_dataset_file_exists():
    """The raw Windows dataset file should exist at the expected path."""
    assert os.path.exists(DATA_PATH), f"Dataset not found at {DATA_PATH}"


def test_dataset_is_not_empty(windows_df):
    """The dataset should contain at least one row - an empty export would be a real problem."""
    assert len(windows_df) > 0


def test_dataset_has_required_columns_for_normalization(windows_df):
    """
    These columns are directly required by windows_mapping.json / WindowsProcessor.validate().
    If any of these disappear in a future data export, normalization would break -
    this test catches that immediately, before it becomes a confusing downstream error.
    """
    missing = [col for col in REQUIRED_COLUMNS if col not in windows_df.columns]
    assert not missing, f"Missing columns required for normalization: {missing}"


def test_optional_enrichment_columns_presence(windows_df):
    """
    These columns aren't strictly required by every event, but the processor has
    special handling for them (e.g. username fallback). Report which are present,
    without failing the test - this is informational, not a strict requirement.
    """
    present = [col for col in OPTIONAL_BUT_EXPECTED_COLUMNS if col in windows_df.columns]
    print(f"\nOptional columns present in dataset: {present}")
    # No assertion here on purpose - this test always passes, it's a visibility check.
    # If you'd rather this actually enforce at least one enrichment column exists, uncomment:
    # assert len(present) > 0, "None of the expected optional enrichment columns are present"


def test_key_columns_are_not_entirely_null(windows_df):
    """
    A column that's 100% null usually signals a broken export or schema mismatch,
    even if the column technically 'exists'. Check the required columns specifically.
    """
    for column in REQUIRED_COLUMNS:
        non_null_count = windows_df[column].notna().sum()
        assert non_null_count > 0, f"Column '{column}' exists but is entirely null"