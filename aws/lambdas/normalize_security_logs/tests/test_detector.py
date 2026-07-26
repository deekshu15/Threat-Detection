import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from processors.detector import DatasetDetector


# ---------- correct detection per known dataset type ----------

@pytest.mark.parametrize(
    "s3_key, expected_type",
    [
        ("windows/evtx_data.csv", "windows"),
        ("ids/Friday-WorkingHours.csv", "ids"),
        ("linux/auth.log", "linux"),
        ("firewall/firewall_logs.csv", "firewall"),
        ("cve/nvdcve-2.0-2026.json", "cve"),
        ("threat_feeds/otx.json", "threat_feeds"),
        ("incident_records/incidents.csv", "incident_records"),
    ],
)
def test_detect_identifies_correct_type(s3_key, expected_type):
    """Each known path pattern should be detected as its correct dataset type."""
    assert DatasetDetector.detect(s3_key) == expected_type


# ---------- case insensitivity ----------

def test_detect_is_case_insensitive():
    """Detection should work regardless of upper/lower case in the path."""
    assert DatasetDetector.detect("WINDOWS/EVTX_DATA.CSV") == "windows"
    assert DatasetDetector.detect("Ids/Friday.csv") == "ids"


# ---------- unknown dataset ----------

def test_detect_raises_for_unrecognized_path():
    """A path with no matching keyword should raise ValueError, not return None silently."""
    with pytest.raises(ValueError):
        DatasetDetector.detect("random_folder/mystery_file.csv")


def test_detect_error_message_includes_filename():
    """The error message should include the actual filename, to help debugging which file failed."""
    with pytest.raises(ValueError, match="mystery_file.csv"):
        DatasetDetector.detect("random_folder/mystery_file.csv")


# ---------- real behavior: substring matching and check order ----------

def test_detect_matches_on_substring_not_exact_folder():
    """
    This confirms real (if slightly risky) behavior: detection uses 'in path',
    not an exact folder match. A key that merely CONTAINS 'windows' anywhere
    will match, even outside an actual /windows/ folder.
    """
    assert DatasetDetector.detect("archive/old_windows_backup.csv") == "windows"


def test_detect_priority_when_multiple_keywords_present():
    """
    If a path happens to contain multiple keywords, the FIRST matching check in
    the if/elif chain wins. Windows is checked before linux, so a path containing
    both should resolve to 'windows'. This documents real, current priority order -
    if the if/elif order in detector.py ever changes, this test will catch it.
    """
    result = DatasetDetector.detect("windows_and_linux_combined_export.csv")
    assert result == "windows"