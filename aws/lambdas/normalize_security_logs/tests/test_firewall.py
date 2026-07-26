import sys
from pathlib import Path

import pandas as pd
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from processors.firewall_processor import FirewallProcessor


# ---------- helper: minimal valid firewall-style DataFrame ----------

def make_firewall_df(**overrides):
    """Builds a DataFrame with the columns FirewallProcessor expects, overridable per test."""
    base = {
        "Timestamp": ["2026-07-10 14:30:00"],
        "Hostname": ["FW-EDGE-01"],
        "Username": ["admin"],
        "Source IP": ["203.0.113.5"],
        "Destination IP": ["10.0.0.1"],
        "Protocol": ["TCP"],
        "Action": ["BLOCK"],
        "Severity": ["High"],
        "Message": ["Blocked inbound connection on port 443"],
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
    processor = FirewallProcessor()
    result = processor.normalize(make_firewall_df())

    row = result.iloc[0]
    assert row["hostname"] == "FW-EDGE-01"
    assert row["username"] == "admin"
    assert row["src_ip"] == "203.0.113.5"
    assert row["dst_ip"] == "10.0.0.1"
    assert row["protocol"] == "TCP"
    assert row["event_type"] == "BLOCK"
    assert row["severity"] == "High"
    assert row["raw_message"] == "Blocked inbound connection on port 443"
    assert row["source"] == "firewall"


def test_normalize_output_has_correct_columns():
    """Output should contain exactly the expected schema columns."""
    processor = FirewallProcessor()
    result = processor.normalize(make_firewall_df())
    assert set(result.columns) == set(EXPECTED_COLUMNS)


def test_normalize_event_id_is_sequential():
    """event_id should be auto-generated as 1, 2, 3... matching row position."""
    processor = FirewallProcessor()
    df = make_firewall_df(
        **{
            "Timestamp": ["2026-07-10 14:30:00", "2026-07-10 14:31:00"],
            "Hostname": ["FW-01", "FW-01"],
            "Username": ["admin", "admin"],
            "Source IP": ["203.0.113.5", "203.0.113.6"],
            "Destination IP": ["10.0.0.1", "10.0.0.2"],
            "Protocol": ["TCP", "UDP"],
            "Action": ["BLOCK", "ALLOW"],
            "Severity": ["High", "Low"],
            "Message": ["msg1", "msg2"],
        }
    )
    result = processor.normalize(df)
    assert result["event_id"].tolist() == [1, 2]


# ---------- fallback logic for missing optional columns ----------

def test_normalize_defaults_hostname_when_column_missing():
    """If 'Hostname' isn't present, hostname should default to 'Unknown'."""
    processor = FirewallProcessor()
    df = make_firewall_df().drop(columns=["Hostname"])
    result = processor.normalize(df)
    assert result.iloc[0]["hostname"] == "Unknown"


def test_normalize_defaults_username_when_column_missing():
    """If 'Username' isn't present, username should default to 'Unknown'."""
    processor = FirewallProcessor()
    df = make_firewall_df().drop(columns=["Username"])
    result = processor.normalize(df)
    assert result.iloc[0]["username"] == "Unknown"


def test_normalize_defaults_src_ip_when_column_missing():
    """If 'Source IP' isn't present, src_ip should default to 'N/A'."""
    processor = FirewallProcessor()
    df = make_firewall_df().drop(columns=["Source IP"])
    result = processor.normalize(df)
    assert result.iloc[0]["src_ip"] == "N/A"


def test_normalize_defaults_dst_ip_when_column_missing():
    """If 'Destination IP' isn't present, dst_ip should default to 'N/A'."""
    processor = FirewallProcessor()
    df = make_firewall_df().drop(columns=["Destination IP"])
    result = processor.normalize(df)
    assert result.iloc[0]["dst_ip"] == "N/A"


def test_normalize_defaults_protocol_when_column_missing():
    """If 'Protocol' isn't present, protocol should default to 'Unknown'."""
    processor = FirewallProcessor()
    df = make_firewall_df().drop(columns=["Protocol"])
    result = processor.normalize(df)
    assert result.iloc[0]["protocol"] == "Unknown"


def test_normalize_defaults_event_type_when_action_missing():
    """If 'Action' isn't present, event_type should default to 'Unknown'."""
    processor = FirewallProcessor()
    df = make_firewall_df().drop(columns=["Action"])
    result = processor.normalize(df)
    assert result.iloc[0]["event_type"] == "Unknown"


def test_normalize_defaults_severity_to_medium_when_column_missing():
    """If 'Severity' isn't present, severity should default to 'Medium' - notably different
    from IDSProcessor, which computes severity from the label rather than defaulting it."""
    processor = FirewallProcessor()
    df = make_firewall_df().drop(columns=["Severity"])
    result = processor.normalize(df)
    assert result.iloc[0]["severity"] == "Medium"


def test_normalize_defaults_raw_message_to_none_when_column_missing():
    """If 'Message' isn't present, raw_message should default to None."""
    processor = FirewallProcessor()
    df = make_firewall_df().drop(columns=["Message"])
    result = processor.normalize(df)
    assert result.iloc[0]["raw_message"] is None


def test_normalize_defaults_timestamp_when_column_missing():
    """If 'Timestamp' isn't present, timestamp should default to NaT, not crash."""
    processor = FirewallProcessor()
    df = make_firewall_df().drop(columns=["Timestamp"])
    result = processor.normalize(df)
    assert pd.isna(result.iloc[0]["timestamp"])


# ---------- validation behavior ----------

def test_normalize_raises_on_empty_dataframe():
    """An empty DataFrame should raise ValueError."""
    processor = FirewallProcessor()
    with pytest.raises(ValueError):
        processor.normalize(pd.DataFrame())


def test_normalize_strips_whitespace_from_column_names():
    """Column names with stray leading/trailing spaces should still be recognized after stripping."""
    processor = FirewallProcessor()
    df = make_firewall_df()
    df.columns = [f" {col} " for col in df.columns]
    result = processor.normalize(df)
    assert result.iloc[0]["event_type"] == "BLOCK"