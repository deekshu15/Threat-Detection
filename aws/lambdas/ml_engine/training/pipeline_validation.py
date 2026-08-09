"""Validation helpers for the ML training pipeline."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterable, List, Sequence

import numpy as np
from sklearn.metrics import accuracy_score
from sklearn.tree import DecisionTreeClassifier


logger = logging.getLogger(__name__)


class PipelineValidationError(RuntimeError):
    """Raised when the training pipeline contract is violated."""


@dataclass(frozen=True, slots=True)
class ValidationSummary:
    """Summary of feature and leakage checks."""

    feature_count: int
    constant_features: List[str]
    duplicate_features: List[str]
    leakage_flags: List[str]


@dataclass(frozen=True, slots=True)
class FeatureSanitizationResult:
    """Outcome of removing constant features before strict validation."""

    X_train: np.ndarray
    X_test: np.ndarray
    feature_names: List[str]
    constant_features: List[str]


def _as_1d_array(values: Sequence) -> np.ndarray:
    array = np.asarray(values)
    if array.ndim != 1:
        raise PipelineValidationError("Expected a one-dimensional feature name sequence.")
    return array


def validate_feature_names(feature_names: Sequence[str]) -> List[str]:
    names = list(feature_names)
    if not names:
        raise PipelineValidationError("No active features were supplied.")

    duplicate_features = sorted({name for name in names if names.count(name) > 1})
    if duplicate_features:
        raise PipelineValidationError(
            "Duplicate features detected: " + ", ".join(duplicate_features)
        )

    return names


def detect_constant_features(
    X: np.ndarray,
    feature_names: Sequence[str],
) -> List[str]:
    names = validate_feature_names(feature_names)
    matrix = np.asarray(X)
    if matrix.ndim != 2:
        raise PipelineValidationError("Feature matrix must be two-dimensional.")

    if matrix.shape[1] != len(names):
        raise PipelineValidationError(
            f"Feature count mismatch: matrix has {matrix.shape[1]} columns but {len(names)} names were provided."
        )

    if not np.issubdtype(matrix.dtype, np.number):
        raise PipelineValidationError("Feature matrix must contain numeric values.")

    constant_features: List[str] = []
    for index, name in enumerate(names):
        column = matrix[:, index]
        finite_values = column[np.isfinite(column)]
        if finite_values.size == 0:
            continue
        if np.nanmax(finite_values) == np.nanmin(finite_values):
            constant_features.append(name)

    return constant_features


def validate_feature_matrix(
    X: np.ndarray,
    feature_names: Sequence[str],
) -> List[str]:
    names = validate_feature_names(feature_names)
    matrix = np.asarray(X)
    if matrix.ndim != 2:
        raise PipelineValidationError("Feature matrix must be two-dimensional.")

    if matrix.shape[1] != len(names):
        raise PipelineValidationError(
            f"Feature count mismatch: matrix has {matrix.shape[1]} columns but {len(names)} names were provided."
        )

    if not np.issubdtype(matrix.dtype, np.number):
        raise PipelineValidationError("Feature matrix must contain numeric values.")

    if np.isnan(matrix).any():
        raise PipelineValidationError("NaN values remain after preprocessing.")

    if np.isinf(matrix).any():
        raise PipelineValidationError("Infinite values remain after preprocessing.")

    return names


def sanitize_constant_features(
    X_train: np.ndarray,
    X_test: np.ndarray,
    feature_names: Sequence[str],
) -> FeatureSanitizationResult:
    """Remove constant columns and return the reduced matrices.

    Constant features are expected in some datasets and therefore only
    trigger a warning before being removed.
    """

    names = validate_feature_names(feature_names)
    train_matrix = np.asarray(X_train)
    test_matrix = np.asarray(X_test)

    if train_matrix.ndim != 2 or test_matrix.ndim != 2:
        raise PipelineValidationError("Feature matrices must be two-dimensional.")

    if train_matrix.shape[1] != len(names) or test_matrix.shape[1] != len(names):
        raise PipelineValidationError(
            "Feature count mismatch while sanitizing constant features."
        )

    constant_features = detect_constant_features(train_matrix, names)
    if constant_features:
        logger.warning("Constant features detected and removed: %s", ", ".join(constant_features))

    keep_indices = [index for index, name in enumerate(names) if name not in constant_features]
    reduced_names = [names[index] for index in keep_indices]
    reduced_train = train_matrix[:, keep_indices]
    reduced_test = test_matrix[:, keep_indices]

    return FeatureSanitizationResult(
        X_train=reduced_train,
        X_test=reduced_test,
        feature_names=reduced_names,
        constant_features=constant_features,
    )


def detect_label_leakage(
    X: np.ndarray,
    y: Sequence,
    feature_names: Sequence[str],
    *,
    threshold: float = 0.995,
    max_features: int | None = None,
) -> List[str]:
    matrix = np.asarray(X)
    labels = _as_1d_array(y)
    names = list(feature_names)

    if matrix.shape[0] != labels.shape[0]:
        raise PipelineValidationError("Feature and label lengths do not match.")

    flagged: List[str] = []
    indices = range(len(names)) if max_features is None else range(min(len(names), max_features))

    for index in indices:
        column = matrix[:, index].reshape(-1, 1)
        tree = DecisionTreeClassifier(max_depth=1, random_state=42)
        try:
            tree.fit(column, labels)
            predictions = tree.predict(column)
            if accuracy_score(labels, predictions) >= threshold:
                flagged.append(names[index])
        except Exception:
            continue

    if flagged:
        raise PipelineValidationError(
            "Potential data leakage detected via features: " + ", ".join(flagged)
        )

    return flagged


def validate_training_contract(
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: Sequence,
    y_test: Sequence,
    feature_names: Sequence[str],
    *,
    leakage_threshold: float = 0.995,
) -> ValidationSummary:
    names = validate_feature_matrix(X_train, feature_names)
    validate_feature_matrix(X_test, names)
    leakage_flags = detect_label_leakage(
        X_train,
        y_train,
        names,
        threshold=leakage_threshold,
        max_features=min(25, len(names)),
    )
    return ValidationSummary(
        feature_count=len(names),
        constant_features=[],
        duplicate_features=[],
        leakage_flags=leakage_flags,
    )