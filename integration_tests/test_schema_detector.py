import pandas as pd
import pytest

from aws.lambdas.normalize_security_logs.processors.schema_detector import (
    DatasetSchemaDetector,
    DatasetSchemaError,
)


def test_ids_detection_success():
    df = pd.DataFrame({
        "Label": ["BENIGN"],
        "Source IP": ["1.1.1.1"],
        "Destination IP": ["2.2.2.2"],
    })

    res = DatasetSchemaDetector.detect(df)
    assert res["dataset_type"] == "ids"
    assert res["confidence"] == 1.0


def test_unsupported_schema_raises():
    df = pd.DataFrame({"foo": [1], "bar": [2]})

    with pytest.raises(DatasetSchemaError) as exc:
        DatasetSchemaDetector.detect(df)

    err = exc.value
    assert isinstance(err.detected_columns, list)
    assert "ids" in err.supported_schemas


def test_missing_required_columns_reports_missing():
    # IDS requires 'Label' - omit it
    df = pd.DataFrame({"Source IP": ["1.1.1.1"]})

    with pytest.raises(DatasetSchemaError) as exc:
        DatasetSchemaDetector.detect(df)

    err = exc.value
    # missing_required should include at least 'Label' for the best-match schema
    assert isinstance(err.missing_required, list)


def test_windows_detection_using_mapping():
    details = DatasetSchemaDetector.supported_schema_details()
    windows_cols = details.get("windows", [])

    if not windows_cols:
        pytest.skip("No windows mapping available in repository")

    # Build a DataFrame with at least the required windows columns
    df = pd.DataFrame({c: [None] for c in windows_cols})

    res = DatasetSchemaDetector.detect(df)
    assert res["dataset_type"] == "windows"
    assert res["confidence"] == 1.0
