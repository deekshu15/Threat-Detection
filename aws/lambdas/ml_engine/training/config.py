"""Training configuration for the ML pipeline.

The values in this module are the single source of truth for the
training pipeline, benchmark settings, output paths, and optional
imbalance handling.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Tuple

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parents[3]

DATASET_DIR = BASE_DIR / "datasets"
RAW_DATASET_DIR = DATASET_DIR / "raw"
PROCESSED_DATASET_DIR = DATASET_DIR / "processed"

MODEL_OUTPUT_DIR = BASE_DIR / "saved_models"
EXPLAINABILITY_DIR = MODEL_OUTPUT_DIR / "explainability"
EVALUATION_DIR = MODEL_OUTPUT_DIR / "evaluation"
LOG_DIR = BASE_DIR / "logs"

PRODUCTION_MODEL_DIR = BASE_DIR.parent / "models"

RAW_DATASET = RAW_DATASET_DIR / "cybersecurity_dataset.csv"
PROCESSED_DATASET = PROCESSED_DATASET_DIR / "processed_dataset.csv"

MODEL_PATH = PRODUCTION_MODEL_DIR / "risk_classifier.pkl"
LABEL_ENCODER_PATH = PRODUCTION_MODEL_DIR / "label_encoder.pkl"

MODEL_FILENAME = "risk_classifier.pkl"
BEST_MODEL_FILENAME = "best_model.pkl"
MODEL_METADATA_FILENAME = "metadata.json"
LABEL_ENCODER_FILENAME = "label_encoder.pkl"
ACTIVE_FEATURES_FILENAME = "active_features.json"
BENCHMARK_RESULTS_FILENAME = "benchmark_results.csv"
BENCHMARK_REPORT_FILENAME = "benchmark_report.json"
BEST_PARAMS_FILENAME = "best_params.json"
CROSS_VALIDATION_FILENAME = "cross_validation.json"
FEATURE_IMPORTANCE_FILENAME = "feature_importance.csv"
TRAINING_REPORT_FILENAME = "training_report.json"
LOG_FILE = LOG_DIR / "training.log"


@dataclass(frozen=True, slots=True)
class BenchmarkConfig:
    random_state: int = 42
    test_size: float = 0.20
    n_iter: int = 12
    cv_folds: int = 5
    scoring: str = "f1_weighted"
    n_jobs: int = -1
    max_samples_for_reporting: int = 250_000
    validation_curve_samples: int = 75_000
    learning_curve_sizes: Tuple[float, ...] = (0.1, 0.3, 0.5, 0.7, 1.0)
    feature_importance_samples: int = 50_000
    permutation_importance_repeats: int = 5
    num_learning_curve_points: int = 5


@dataclass(frozen=True, slots=True)
class ImbalanceConfig:
    enable_smote: bool = False
    enable_borderline_smote: bool = False
    enable_random_oversampling: bool = False
    enable_balanced_random_forest: bool = False
    enable_class_weight_search: bool = True
    sampling_strategy: str = "auto"
    class_weight_options: Tuple[str | Dict[str, float] | None, ...] = (
        None,
        "balanced",
        "balanced_subsample",
    )


@dataclass(frozen=True, slots=True)
class TrainingConfig:
    benchmark: BenchmarkConfig = field(default_factory=BenchmarkConfig)
    imbalance: ImbalanceConfig = field(default_factory=ImbalanceConfig)
    random_forest_param_distributions: Dict[str, Tuple | list] = field(
        default_factory=lambda: {
            "n_estimators": [100, 150, 200, 300, 400],
            "max_depth": [None, 10, 15, 20, 25, 30],
            "min_samples_split": [2, 4, 6, 8, 10],
            "min_samples_leaf": [1, 2, 4, 6],
            "max_features": ["sqrt", "log2", 0.5, 0.7],
            "bootstrap": [True, False],
        }
    )


def default_config() -> TrainingConfig:
    """Return the default training configuration."""

    return TrainingConfig()


def ensure_directories() -> None:
    """Create all training output directories if they do not exist."""

    for directory in (
        DATASET_DIR,
        RAW_DATASET_DIR,
        PROCESSED_DATASET_DIR,
        MODEL_OUTPUT_DIR,
        EXPLAINABILITY_DIR,
        EVALUATION_DIR,
        LOG_DIR,
        PRODUCTION_MODEL_DIR,
    ):
        directory.mkdir(parents=True, exist_ok=True)


ensure_directories()