from __future__ import annotations

import numpy as np
import pytest

from aws.lambdas.ml_engine.training.pipeline_validation import (
    PipelineValidationError,
    sanitize_constant_features,
    detect_label_leakage,
    validate_feature_matrix,
)


def test_validate_feature_matrix_rejects_duplicates():
    with pytest.raises(PipelineValidationError):
        validate_feature_matrix(np.ones((4, 2)), ["a", "a"])


def test_sanitize_constant_features_removes_constant_columns():
    X_train = np.column_stack([
        np.ones(4),
        np.array([0.0, 1.0, 0.0, 1.0]),
    ])
    X_test = np.column_stack([
        np.ones(2),
        np.array([1.0, 0.0]),
    ])

    result = sanitize_constant_features(X_train, X_test, ["constant", "variable"])

    assert result.constant_features == ["constant"]
    assert result.feature_names == ["variable"]
    assert result.X_train.shape == (4, 1)
    assert result.X_test.shape == (2, 1)


def test_validate_feature_matrix_rejects_nan_values():
    with pytest.raises(PipelineValidationError):
        validate_feature_matrix(np.array([[1.0, np.nan], [2.0, 3.0]]), ["a", "b"])


def test_validate_feature_matrix_rejects_infinite_values():
    with pytest.raises(PipelineValidationError):
        validate_feature_matrix(np.array([[1.0, np.inf], [2.0, 3.0]]), ["a", "b"])


def test_detect_label_leakage_flags_perfect_feature():
    y = np.array([0, 0, 1, 1])
    X = np.column_stack([y, np.array([0, 1, 0, 1])])

    with pytest.raises(PipelineValidationError):
        detect_label_leakage(X, y, ["leaky", "noise"], threshold=0.99)
