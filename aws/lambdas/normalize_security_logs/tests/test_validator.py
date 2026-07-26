import sys
from pathlib import Path

import pandas as pd
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from utils.validator import DatasetValidator


# ---------- validate_file_type ----------

def test_valid_file_type_passes():
    """A supported extension (.csv) should validate successfully."""
    assert DatasetValidator.validate_file_type("evtx_data.csv") is True


def test_invalid_file_type_raises():
    """An unsupported extension should raise ValueError, not pass silently."""
    with pytest.raises(ValueError):
        DatasetValidator.validate_file_type("malware.exe")


# ---------- validate_dataset_source ----------

def test_valid_dataset_source_passes():
    """A known dataset source (windows) should validate successfully."""
    assert DatasetValidator.validate_dataset_source("windows") is True


def test_invalid_dataset_source_raises():
    """An unknown dataset source should raise ValueError."""
    with pytest.raises(ValueError):
        DatasetValidator.validate_dataset_source("not_a_real_source")


# ---------- validate_not_empty ----------

def test_non_empty_dataframe_passes():
    """A DataFrame with rows should validate successfully."""
    df = pd.DataFrame({
        "EventID": [4624],
        "TimeCreated": ["2026-07-10"],
        "Computer": ["SERVER01"]
    })
    assert DatasetValidator.validate_not_empty(df) is True


def test_empty_dataframe_raises():
    """An empty DataFrame should raise ValueError, since normalizing nothing is a real bug."""
    empty_df = pd.DataFrame()
    with pytest.raises(ValueError):
        DatasetValidator.validate_not_empty(empty_df)


# ---------- validate_required_columns ----------

def test_all_required_columns_present_passes():
    """When all required columns exist, validation should pass."""
    df = pd.DataFrame({
        "EventID": [4624],
        "TimeCreated": ["2026-07-10"],
        "Computer": ["SERVER01"]
    })
    assert DatasetValidator.validate_required_columns(
        df, ["EventID", "TimeCreated", "Computer"]
    ) is True


def test_missing_required_column_raises():
    """When a required column is missing, validation should raise ValueError."""
    df = pd.DataFrame({
        "EventID": [4624],
        "TimeCreated": ["2026-07-10"]
        # "Computer" column is missing on purpose
    })
    with pytest.raises(ValueError):
        DatasetValidator.validate_required_columns(
            df, ["EventID", "TimeCreated", "Computer"]
        )