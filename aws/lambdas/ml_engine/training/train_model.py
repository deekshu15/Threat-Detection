"""End-to-end ML training pipeline for threat detection.

The pipeline keeps the inference contract stable while adding model
benchmarking, hyperparameter tuning, imbalance experiments, cross
validation, explainability, and evaluation artifact generation.
"""

from __future__ import annotations

import json
import logging
import math
import importlib.util
import importlib
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import numpy as np
import pandas as pd

from sklearn.base import clone
from sklearn.calibration import CalibrationDisplay
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    accuracy_score,
    auc,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold, learning_curve, validation_curve
from sklearn.preprocessing import label_binarize
from sklearn.utils.class_weight import compute_class_weight

try:  # Optional dependencies.
    from xgboost import XGBClassifier  # type: ignore
except Exception:  # pragma: no cover - optional dependency.
    XGBClassifier = None

try:  # Optional dependencies.
    from lightgbm import LGBMClassifier  # type: ignore
except Exception:  # pragma: no cover - optional dependency.
    LGBMClassifier = None

try:  # Optional dependencies.
    from catboost import CatBoostClassifier  # type: ignore
except Exception:  # pragma: no cover - optional dependency.
    CatBoostClassifier = None

try:  # Optional dependencies.
    from imblearn.over_sampling import BorderlineSMOTE, RandomOverSampler, SMOTE  # type: ignore
    from imblearn.ensemble import BalancedRandomForestClassifier  # type: ignore
except Exception:  # pragma: no cover - optional dependency.
    BorderlineSMOTE = None
    RandomOverSampler = None
    SMOTE = None
    BalancedRandomForestClassifier = None

if importlib.util.find_spec("matplotlib") is not None:
    matplotlib = importlib.import_module("matplotlib")
    matplotlib.use("Agg")
    plt = importlib.import_module("matplotlib.pyplot")
else:  # pragma: no cover - plotting is optional.
    plt = None

if importlib.util.find_spec("seaborn") is not None:
    sns = importlib.import_module("seaborn")
else:  # pragma: no cover - plotting is optional.
    sns = None

from aws.lambdas.feature_engineering.feature_selector import feature_schema
from aws.lambdas.feature_engineering.validator import check_forbidden_training_columns
from aws.lambdas.ml_engine.training.config import (
    ACTIVE_FEATURES_FILENAME,
    BENCHMARK_REPORT_FILENAME,
    BENCHMARK_RESULTS_FILENAME,
    BEST_MODEL_FILENAME,
    BEST_PARAMS_FILENAME,
    CROSS_VALIDATION_FILENAME,
    EVALUATION_DIR,
    EXPLAINABILITY_DIR,
    FEATURE_IMPORTANCE_FILENAME,
    LABEL_ENCODER_FILENAME,
    LOG_FILE,
    MODEL_FILENAME,
    MODEL_METADATA_FILENAME,
    MODEL_OUTPUT_DIR,
    PROCESSED_DATASET_DIR,
    PRODUCTION_MODEL_DIR,
    TRAINING_REPORT_FILENAME,
    TrainingConfig,
    default_config,
    ensure_directories,
)
from aws.lambdas.ml_engine.training.model_manager import ModelManager
from aws.lambdas.ml_engine.training.pipeline_validation import (
    PipelineValidationError,
    detect_label_leakage,
    sanitize_constant_features,
    validate_feature_matrix,
)


LOGGER = logging.getLogger("training")


@dataclass(slots=True)
class BenchmarkResult:
    model_name: str
    status: str
    accuracy: float | None = None
    precision: float | None = None
    recall: float | None = None
    f1_score: float | None = None
    macro_f1: float | None = None
    weighted_f1: float | None = None
    training_time_s: float | None = None
    inference_time_s: float | None = None
    details: str | None = None


def _setup_logging() -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    if LOGGER.handlers:
        return

    LOGGER.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    LOGGER.addHandler(file_handler)
    LOGGER.addHandler(stream_handler)


def _load_arrays(model_dir: Path) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    LOGGER.info("Loading feature arrays from %s", model_dir)
    return (
        np.load(model_dir / "X_train.npy"),
        np.load(model_dir / "y_train.npy"),
        np.load(model_dir / "X_test.npy"),
        np.load(model_dir / "y_test.npy"),
    )


def _sanitize_features(
    X_train: np.ndarray,
    X_test: np.ndarray,
    feature_names: Sequence[str],
) -> Tuple[np.ndarray, np.ndarray, List[str], List[str]]:
    sanitized = sanitize_constant_features(X_train, X_test, feature_names)
    validate_feature_matrix(sanitized.X_train, sanitized.feature_names)
    validate_feature_matrix(sanitized.X_test, sanitized.feature_names)
    return (
        sanitized.X_train,
        sanitized.X_test,
        sanitized.feature_names,
        sanitized.constant_features,
    )


def _subsample_for_speed(
    X: np.ndarray,
    y: np.ndarray,
    max_samples: int,
    random_state: int,
) -> Tuple[np.ndarray, np.ndarray]:
    if len(X) <= max_samples:
        return X, y

    rng = np.random.default_rng(random_state)
    indices = np.arange(len(X))
    chosen = rng.choice(indices, size=max_samples, replace=False)
    chosen.sort()
    return X[chosen], y[chosen]


def _make_estimator(name: str, random_state: int = 42, class_weight: Any = None):
    if name == "RandomForest":
        return RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            random_state=random_state,
            n_jobs=-1,
            class_weight=class_weight,
        )
    if name == "ExtraTrees":
        return ExtraTreesClassifier(
            n_estimators=250,
            max_depth=None,
            random_state=random_state,
            n_jobs=-1,
            class_weight=class_weight,
        )
    if name == "XGBoost" and XGBClassifier is not None:
        return XGBClassifier(
            n_estimators=250,
            max_depth=8,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_lambda=1.0,
            objective="multi:softprob",
            eval_metric="mlogloss",
            tree_method="hist",
            random_state=random_state,
            n_jobs=-1,
        )
    if name == "LightGBM" and LGBMClassifier is not None:
        return LGBMClassifier(
            n_estimators=250,
            learning_rate=0.05,
            max_depth=-1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=random_state,
            n_jobs=-1,
        )
    if name == "CatBoost" and CatBoostClassifier is not None:
        return CatBoostClassifier(
            iterations=250,
            learning_rate=0.05,
            depth=8,
            loss_function="MultiClass",
            random_seed=random_state,
            verbose=False,
        )
    raise ValueError(f"Unsupported model requested: {name}")


def _available_model_specs() -> List[Tuple[str, str]]:
    specs = [("RandomForest", "tree"), ("ExtraTrees", "tree")]
    if XGBClassifier is not None:
        specs.append(("XGBoost", "boosting"))
    if LGBMClassifier is not None:
        specs.append(("LightGBM", "boosting"))
    if CatBoostClassifier is not None:
        specs.append(("CatBoost", "boosting"))
    return specs


def _evaluate_model(
    model: Any,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> Dict[str, Any]:
    inference_start = time.perf_counter()
    predictions = model.predict(X_test)
    inference_time_s = time.perf_counter() - inference_start

    report = classification_report(y_test, predictions, output_dict=True, zero_division=0)
    return {
        "predictions": predictions,
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision": float(precision_score(y_test, predictions, average="weighted", zero_division=0)),
        "recall": float(recall_score(y_test, predictions, average="weighted", zero_division=0)),
        "f1_score": float(f1_score(y_test, predictions, average="weighted", zero_division=0)),
        "macro_f1": float(f1_score(y_test, predictions, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_test, predictions, average="weighted", zero_division=0)),
        "inference_time_s": float(inference_time_s),
        "classification_report": report,
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
    }


def _benchmark_models(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    config: TrainingConfig,
) -> Tuple[pd.DataFrame, Dict[str, Any], Dict[str, Any]]:
    benchmark_rows: List[BenchmarkResult] = []
    benchmark_details: Dict[str, Any] = {}
    imbalance_details: Dict[str, Any] = {}

    classes = np.unique(y_train)
    class_weight_map = {
        str(label): float(weight)
        for label, weight in zip(
            classes,
            compute_class_weight(class_weight="balanced", classes=classes, y=y_train),
        )
    }

    for model_name, family in _available_model_specs():
        try:
            model = _make_estimator(model_name, random_state=config.benchmark.random_state)
        except Exception as exc:
            benchmark_rows.append(
                BenchmarkResult(model_name=model_name, status="skipped", details=str(exc))
            )
            continue

        train_start = time.perf_counter()
        model.fit(X_train, y_train)
        training_time_s = time.perf_counter() - train_start

        evaluation = _evaluate_model(model, X_test, y_test)
        row = BenchmarkResult(
            model_name=model_name,
            status="ok",
            accuracy=evaluation["accuracy"],
            precision=evaluation["precision"],
            recall=evaluation["recall"],
            f1_score=evaluation["f1_score"],
            macro_f1=evaluation["macro_f1"],
            weighted_f1=evaluation["weighted_f1"],
            training_time_s=float(training_time_s),
            inference_time_s=evaluation["inference_time_s"],
        )
        benchmark_rows.append(row)
        benchmark_details[model_name] = {
            **evaluation,
            "training_time_s": float(training_time_s),
            "family": family,
        }

    imbalance_options: List[Tuple[str, Optional[Any]]] = [("class_weight_none", None)]
    if config.imbalance.enable_class_weight_search:
        imbalance_options.extend(
            [
                ("class_weight_balanced", "balanced"),
                ("class_weight_balanced_subsample", "balanced_subsample"),
            ]
        )

    if config.imbalance.enable_balanced_random_forest and BalancedRandomForestClassifier is not None:
        imbalance_options.append(("balanced_random_forest", "balanced_rf"))

    resamplers: List[Tuple[str, Optional[Any]]] = []
    if config.imbalance.enable_smote and SMOTE is not None:
        resamplers.append(("smote", SMOTE(random_state=config.benchmark.random_state)))
    if config.imbalance.enable_borderline_smote and BorderlineSMOTE is not None:
        resamplers.append(("borderline_smote", BorderlineSMOTE(random_state=config.benchmark.random_state)))
    if config.imbalance.enable_random_oversampling and RandomOverSampler is not None:
        resamplers.append(("random_oversampling", RandomOverSampler(random_state=config.benchmark.random_state)))

    best_imbalance_score = -math.inf
    for strategy_name, resampler in resamplers:
        try:
            X_resampled, y_resampled = resampler.fit_resample(X_train, y_train)
            model = _make_estimator("RandomForest", random_state=config.benchmark.random_state)
            model.fit(X_resampled, y_resampled)
            evaluation = _evaluate_model(model, X_test, y_test)
            imbalance_details[strategy_name] = {
                **evaluation,
                "samples_after_resampling": int(len(X_resampled)),
            }
            best_imbalance_score = max(best_imbalance_score, evaluation["weighted_f1"])
        except Exception as exc:
            imbalance_details[strategy_name] = {"status": "failed", "error": str(exc)}

    for strategy_name, class_weight in imbalance_options:
        try:
            if class_weight == "balanced_rf":
                model = BalancedRandomForestClassifier(
                    n_estimators=200,
                    random_state=config.benchmark.random_state,
                    n_jobs=-1,
                )
            else:
                model = _make_estimator(
                    "RandomForest",
                    random_state=config.benchmark.random_state,
                    class_weight=class_weight,
                )
            model.fit(X_train, y_train)
            evaluation = _evaluate_model(model, X_test, y_test)
            imbalance_details[strategy_name] = {
                **evaluation,
                "class_weight": class_weight,
            }
            best_imbalance_score = max(best_imbalance_score, evaluation["weighted_f1"])
        except Exception as exc:
            imbalance_details[strategy_name] = {"status": "failed", "error": str(exc)}

    benchmark_df = pd.DataFrame([asdict(result) for result in benchmark_rows])
    benchmark_df.sort_values(
        by=["status", "weighted_f1", "accuracy"],
        ascending=[True, False, False],
        inplace=True,
        na_position="last",
    )
    benchmark_df.reset_index(drop=True, inplace=True)
    benchmark_df["rank"] = np.arange(1, len(benchmark_df) + 1)

    benchmark_summary = {
        "best_model_name": benchmark_df.iloc[0]["model_name"] if not benchmark_df.empty else None,
        "best_weighted_f1": float(benchmark_df.iloc[0]["weighted_f1"]) if not benchmark_df.empty and pd.notna(benchmark_df.iloc[0]["weighted_f1"]) else None,
        "class_weight_map": class_weight_map,
    }

    benchmark_details["imbalance"] = imbalance_details
    benchmark_details["benchmark_summary"] = benchmark_summary
    return benchmark_df, benchmark_details, benchmark_summary


def _random_search_random_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    config: TrainingConfig,
) -> Tuple[Any, Dict[str, Any], float]:
    estimator = _make_estimator("RandomForest", random_state=config.benchmark.random_state)
    search = RandomizedSearchCV(
        estimator=estimator,
        param_distributions=config.random_forest_param_distributions,
        n_iter=config.benchmark.n_iter,
        scoring=config.benchmark.scoring,
        cv=StratifiedKFold(
            n_splits=config.benchmark.cv_folds,
            shuffle=True,
            random_state=config.benchmark.random_state,
        ),
        random_state=config.benchmark.random_state,
        n_jobs=config.benchmark.n_jobs,
        verbose=1,
    )
    start = time.perf_counter()
    search.fit(X_train, y_train)
    elapsed = time.perf_counter() - start
    return search.best_estimator_, search.best_params_, float(elapsed)


def _cross_validate_model(
    model: Any,
    X: np.ndarray,
    y: np.ndarray,
    config: TrainingConfig,
) -> Dict[str, Any]:
    cv = StratifiedKFold(
        n_splits=config.benchmark.cv_folds,
        shuffle=True,
        random_state=config.benchmark.random_state,
    )

    fold_metrics = {
        "accuracy": [],
        "precision": [],
        "recall": [],
        "f1": [],
    }

    for train_index, valid_index in cv.split(X, y):
        fitted = clone(model)
        fitted.fit(X[train_index], y[train_index])
        predictions = fitted.predict(X[valid_index])
        fold_metrics["accuracy"].append(accuracy_score(y[valid_index], predictions))
        fold_metrics["precision"].append(precision_score(y[valid_index], predictions, average="weighted", zero_division=0))
        fold_metrics["recall"].append(recall_score(y[valid_index], predictions, average="weighted", zero_division=0))
        fold_metrics["f1"].append(f1_score(y[valid_index], predictions, average="weighted", zero_division=0))

    return {
        "folds": config.benchmark.cv_folds,
        "mean_accuracy": float(np.mean(fold_metrics["accuracy"])),
        "mean_precision": float(np.mean(fold_metrics["precision"])),
        "mean_recall": float(np.mean(fold_metrics["recall"])),
        "mean_f1": float(np.mean(fold_metrics["f1"])),
        "std_accuracy": float(np.std(fold_metrics["accuracy"])),
        "std_precision": float(np.std(fold_metrics["precision"])),
        "std_recall": float(np.std(fold_metrics["recall"])),
        "std_f1": float(np.std(fold_metrics["f1"])),
    }


def _save_plot(path: Path) -> None:
    if plt is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(path, dpi=180, bbox_inches="tight")
    plt.close()


def _export_explainability(
    model: Any,
    X_test: np.ndarray,
    y_test: np.ndarray,
    feature_names: Sequence[str],
    config: TrainingConfig,
) -> pd.DataFrame:
    explainability_dir = EXPLAINABILITY_DIR
    explainability_dir.mkdir(parents=True, exist_ok=True)

    sample_X, sample_y = _subsample_for_speed(
        X_test,
        y_test,
        config.benchmark.feature_importance_samples,
        config.benchmark.random_state,
    )

    importances: List[float]
    if hasattr(model, "feature_importances_"):
        importances = list(getattr(model, "feature_importances_"))
    else:
        importances = [0.0] * len(feature_names)

    importance_frame = pd.DataFrame(
        {
            "feature": list(feature_names),
            "model_importance": importances,
        }
    )

    try:
        perm = permutation_importance(
            model,
            sample_X,
            sample_y,
            scoring="f1_weighted",
            n_repeats=config.benchmark.permutation_importance_repeats,
            random_state=config.benchmark.random_state,
            n_jobs=config.benchmark.n_jobs,
        )
        importance_frame["permutation_importance_mean"] = perm.importances_mean
        importance_frame["permutation_importance_std"] = perm.importances_std
    except Exception as exc:
        LOGGER.warning("Permutation importance unavailable: %s", exc)
        importance_frame["permutation_importance_mean"] = np.nan
        importance_frame["permutation_importance_std"] = np.nan

    importance_frame.sort_values(
        by=["permutation_importance_mean", "model_importance"],
        ascending=[False, False],
        inplace=True,
        na_position="last",
    )
    importance_frame.to_csv(explainability_dir / FEATURE_IMPORTANCE_FILENAME, index=False)

    if plt is not None:
        top = importance_frame.head(20).iloc[::-1]
        plt.figure(figsize=(10, 8))
        if sns is not None:
            sns.barplot(data=top, x="permutation_importance_mean", y="feature", color="#1756a9")
        else:
            plt.barh(top["feature"], top["permutation_importance_mean"])
        plt.title("Top Permutation Importances")
        plt.xlabel("Importance")
        plt.ylabel("Feature")
        _save_plot(explainability_dir / "feature_importance_bar.png")

    if importlib.util.find_spec("shap") is not None:
        try:
            shap = importlib.import_module("shap")
            shap_sample, _ = _subsample_for_speed(
                X_test,
                y_test,
                min(config.benchmark.feature_importance_samples, 10_000),
                config.benchmark.random_state,
            )
            explainer = shap.TreeExplainer(model)
            shap_values = explainer.shap_values(shap_sample)
            if isinstance(shap_values, list):
                stacked = np.stack([np.abs(values) for values in shap_values], axis=0)
                mean_abs_values = stacked.mean(axis=0)
                shap_matrix = mean_abs_values.mean(axis=0)
            else:
                shap_matrix = np.abs(shap_values).mean(axis=0)

            shap_frame = pd.DataFrame(
                {
                    "feature": list(feature_names),
                    "mean_abs_shap": shap_matrix,
                }
            ).sort_values("mean_abs_shap", ascending=False)
            shap_frame.to_csv(explainability_dir / "shap_values_summary.csv", index=False)

            if plt is not None:
                plt.figure(figsize=(10, 8))
                top_shap = shap_frame.head(20).iloc[::-1]
                if sns is not None:
                    sns.barplot(data=top_shap, x="mean_abs_shap", y="feature", color="#4c8d2b")
                else:
                    plt.barh(top_shap["feature"], top_shap["mean_abs_shap"])
                plt.title("SHAP Summary")
                plt.xlabel("Mean |SHAP|")
                plt.ylabel("Feature")
                _save_plot(explainability_dir / "shap_summary.png")

            top_feature = shap_frame.iloc[0]["feature"]
            feature_index = list(feature_names).index(top_feature)
            if plt is not None:
                plt.figure(figsize=(10, 8))
                shap.dependence_plot(
                    feature_index,
                    shap_values,
                    shap_sample,
                    feature_names=list(feature_names),
                    show=False,
                )
                _save_plot(explainability_dir / "shap_dependence.png")
        except Exception as exc:
            LOGGER.warning("SHAP explainability unavailable: %s", exc)

    return importance_frame


def _export_evaluation_artifacts(
    model: Any,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    feature_names: Sequence[str],
    config: TrainingConfig,
) -> Dict[str, Any]:
    evaluation_dir = EVALUATION_DIR
    evaluation_dir.mkdir(parents=True, exist_ok=True)

    evaluation = _evaluate_model(model, X_test, y_test)
    predictions = evaluation["predictions"]
    probabilities = model.predict_proba(X_test)

    if plt is not None:
        # Confusion matrix
        matrix = confusion_matrix(y_test, predictions)
        plt.figure(figsize=(10, 8))
        if sns is not None:
            sns.heatmap(matrix, annot=False, cmap="Blues", fmt="d")
        else:
            plt.imshow(matrix, cmap="Blues")
            plt.colorbar()
        plt.title("Confusion Matrix")
        plt.xlabel("Predicted")
        plt.ylabel("Actual")
        _save_plot(evaluation_dir / "confusion_matrix.png")

        # ROC curve
        classes = np.unique(np.concatenate([y_train, y_test]))
        y_test_bin = label_binarize(y_test, classes=classes)
        plt.figure(figsize=(10, 8))
        for index, class_label in enumerate(classes):
            fpr, tpr, _ = roc_curve(y_test_bin[:, index], probabilities[:, index])
            roc_auc = auc(fpr, tpr)
            plt.plot(fpr, tpr, label=f"Class {class_label} (AUC={roc_auc:.3f})")
        plt.plot([0, 1], [0, 1], linestyle="--", color="gray")
        plt.title("ROC Curves")
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate")
        plt.legend(loc="lower right")
        _save_plot(evaluation_dir / "roc_curves.png")

        # Precision-recall curve
        plt.figure(figsize=(10, 8))
        for index, class_label in enumerate(classes):
            precision, recall, _ = precision_recall_curve(y_test_bin[:, index], probabilities[:, index])
            plt.plot(recall, precision, label=f"Class {class_label}")
        plt.title("Precision-Recall Curves")
        plt.xlabel("Recall")
        plt.ylabel("Precision")
        plt.legend(loc="lower left")
        _save_plot(evaluation_dir / "precision_recall_curves.png")

        # Class distribution
        plt.figure(figsize=(8, 6))
        train_counts = pd.Series(y_train).value_counts().sort_index()
        test_counts = pd.Series(y_test).value_counts().sort_index()
        distribution = pd.DataFrame({"train": train_counts, "test": test_counts}).fillna(0)
        distribution.plot(kind="bar", figsize=(10, 6))
        plt.title("Class Distribution")
        plt.xlabel("Class")
        plt.ylabel("Count")
        _save_plot(evaluation_dir / "class_distribution.png")

        # Learning curve
        sample_X, sample_y = _subsample_for_speed(
            X_train,
            y_train,
            config.benchmark.validation_curve_samples,
            config.benchmark.random_state,
        )
        train_sizes, train_scores, valid_scores = learning_curve(
            clone(model),
            sample_X,
            sample_y,
            train_sizes=np.linspace(0.1, 1.0, config.benchmark.num_learning_curve_points),
            cv=StratifiedKFold(n_splits=min(5, config.benchmark.cv_folds), shuffle=True, random_state=config.benchmark.random_state),
            scoring="f1_weighted",
            n_jobs=config.benchmark.n_jobs,
        )
        plt.figure(figsize=(10, 8))
        plt.plot(train_sizes, train_scores.mean(axis=1), label="Training")
        plt.plot(train_sizes, valid_scores.mean(axis=1), label="Validation")
        plt.title("Learning Curve")
        plt.xlabel("Training Samples")
        plt.ylabel("Weighted F1")
        plt.legend()
        _save_plot(evaluation_dir / "learning_curve.png")

        # Validation curve on max_depth where supported
        try:
            train_scores_v, valid_scores_v = validation_curve(
                _make_estimator("RandomForest", random_state=config.benchmark.random_state),
                sample_X,
                sample_y,
                param_name="max_depth",
                param_range=[5, 10, 15, 20, 25],
                cv=StratifiedKFold(n_splits=min(5, config.benchmark.cv_folds), shuffle=True, random_state=config.benchmark.random_state),
                scoring="f1_weighted",
                n_jobs=config.benchmark.n_jobs,
            )
            plt.figure(figsize=(10, 8))
            plt.plot([5, 10, 15, 20, 25], train_scores_v.mean(axis=1), label="Training")
            plt.plot([5, 10, 15, 20, 25], valid_scores_v.mean(axis=1), label="Validation")
            plt.title("Validation Curve")
            plt.xlabel("max_depth")
            plt.ylabel("Weighted F1")
            plt.legend()
            _save_plot(evaluation_dir / "validation_curve.png")
        except Exception as exc:
            LOGGER.warning("Validation curve unavailable: %s", exc)

        # Calibration curve
        try:
            plt.figure(figsize=(10, 8))
            CalibrationDisplay.from_predictions(
                y_test,
                predictions,
                n_bins=10,
                name="Calibration",
            )
            plt.title("Calibration Curve")
            _save_plot(evaluation_dir / "calibration_curve.png")
        except Exception as exc:
            LOGGER.warning("Calibration curve unavailable: %s", exc)

    evaluation.pop("predictions", None)
    evaluation["confusion_matrix"] = confusion_matrix(y_test, predictions).tolist()
    return evaluation


def _save_reports(
    benchmark_df: pd.DataFrame,
    benchmark_details: Dict[str, Any],
    benchmark_summary: Dict[str, Any],
    cross_validation_summary: Dict[str, Any],
    evaluation_summary: Dict[str, Any],
    model_name: str,
    training_time_s: float,
    best_params: Dict[str, Any],
    active_features: Sequence[str],
    manager: ModelManager,
) -> None:
    benchmark_df.to_csv(MODEL_OUTPUT_DIR / BENCHMARK_RESULTS_FILENAME, index=False)
    with (MODEL_OUTPUT_DIR / BENCHMARK_REPORT_FILENAME).open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "summary": benchmark_summary,
                "details": benchmark_details,
            },
            handle,
            indent=2,
            default=str,
        )

    with (MODEL_OUTPUT_DIR / CROSS_VALIDATION_FILENAME).open("w", encoding="utf-8") as handle:
        json.dump(cross_validation_summary, handle, indent=2, default=str)

    with (MODEL_OUTPUT_DIR / BEST_PARAMS_FILENAME).open("w", encoding="utf-8") as handle:
        json.dump(best_params, handle, indent=2, default=str)

    manager.save_active_features(active_features, filename=ACTIVE_FEATURES_FILENAME)
    manager.save_metadata(
        {
            "model": model_name,
            "feature_count": len(active_features),
            "best_params": best_params,
            "training_time_s": training_time_s,
            "benchmark_best_model_name": benchmark_summary.get("best_model_name"),
            "benchmark_best_weighted_f1": benchmark_summary.get("best_weighted_f1"),
            "evaluation": evaluation_summary,
        },
        filename=MODEL_METADATA_FILENAME,
    )

    with (MODEL_OUTPUT_DIR / TRAINING_REPORT_FILENAME).open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "model": model_name,
                "benchmark_summary": benchmark_summary,
                "cross_validation": cross_validation_summary,
                "evaluation": evaluation_summary,
                "feature_count": len(active_features),
                "best_params": best_params,
                "training_time_s": training_time_s,
            },
            handle,
            indent=2,
            default=str,
        )


def main(config: TrainingConfig | None = None) -> Dict[str, Any]:
    """Run the full training workflow and return a summary dictionary."""

    _setup_logging()
    ensure_directories()
    config = config or default_config()
    manager = ModelManager(MODEL_OUTPUT_DIR, PRODUCTION_MODEL_DIR)

    LOGGER.info("Training started")
    start_time = time.perf_counter()

    X_train, y_train, X_test, y_test = _load_arrays(MODEL_OUTPUT_DIR)
    LOGGER.info("Train shape: %s | Test shape: %s", X_train.shape, X_test.shape)

    feature_names = feature_schema().get("feature_names", [])
    forbidden = check_forbidden_training_columns(feature_names)
    if forbidden:
        raise PipelineValidationError("Forbidden feature names present: " + ", ".join(forbidden))

    if any(name.lower() in {"label", "target"} for name in feature_names):
        raise PipelineValidationError("Target or label column leaked into feature names.")

    X_train, X_test, active_features, removed_features = _sanitize_features(
        X_train,
        X_test,
        feature_names,
    )

    LOGGER.info("Active features after sanitization: %s", ", ".join(active_features))
    if removed_features:
        LOGGER.warning("Constant features removed from training: %s", ", ".join(removed_features))

    detect_label_leakage(
        X_train,
        y_train,
        active_features,
        threshold=0.995,
        max_features=min(25, len(active_features)),
    )

    benchmark_train, benchmark_target = _subsample_for_speed(
        X_train,
        y_train,
        config.benchmark.max_samples_for_reporting,
        config.benchmark.random_state,
    )

    benchmark_df, benchmark_details, benchmark_summary = _benchmark_models(
        benchmark_train,
        benchmark_target,
        X_test,
        y_test,
        config,
    )

    tuned_model, best_params, tuning_time_s = _random_search_random_forest(
        benchmark_train,
        benchmark_target,
        config,
    )

    # Compare tuned Random Forest against the benchmark winner and keep
    # the stronger model for persistence.
    tuned_evaluation = _evaluate_model(tuned_model, X_test, y_test)
    best_benchmark_model_name = benchmark_summary.get("best_model_name")
    if best_benchmark_model_name:
        candidate_model = _make_estimator(best_benchmark_model_name, random_state=config.benchmark.random_state)
        candidate_model.fit(benchmark_train, benchmark_target)
        candidate_evaluation = _evaluate_model(candidate_model, X_test, y_test)
    else:
        candidate_model = tuned_model
        candidate_evaluation = tuned_evaluation

    if tuned_evaluation["weighted_f1"] >= candidate_evaluation["weighted_f1"]:
        final_model = tuned_model
        final_model_name = "RandomForestClassifier"
        final_evaluation = tuned_evaluation
    else:
        final_model = candidate_model
        final_model_name = type(candidate_model).__name__
        final_evaluation = candidate_evaluation

    final_model_start = time.perf_counter()
    final_model.fit(X_train, y_train)
    final_training_time_s = time.perf_counter() - final_model_start

    final_evaluation = _evaluate_model(final_model, X_test, y_test)
    if benchmark_summary.get("best_model_name") == "RandomForest":
        final_model_name = "RandomForestClassifier"

    cross_validation_summary = _cross_validate_model(final_model, benchmark_train, benchmark_target, config)
    feature_importance = _export_explainability(final_model, X_test, y_test, active_features, config)
    evaluation_summary = _export_evaluation_artifacts(
        final_model,
        X_train,
        y_train,
        X_test,
        y_test,
        active_features,
        config,
    )

    metadata = {
        "model": final_model_name,
        "feature_count": len(active_features),
        "accuracy": final_evaluation["accuracy"],
        "precision": final_evaluation["precision"],
        "recall": final_evaluation["recall"],
        "f1_score": final_evaluation["f1_score"],
        "macro_f1": final_evaluation["macro_f1"],
        "weighted_f1": final_evaluation["weighted_f1"],
        "training_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "removed_features": removed_features,
        "best_params": best_params,
        "benchmark_best_model": benchmark_summary.get("best_model_name"),
        "benchmark_best_weighted_f1": benchmark_summary.get("best_weighted_f1"),
        "training_time_s": float(final_training_time_s),
        "inference_time_s": float(final_evaluation["inference_time_s"]),
    }

    manager.save_model(
        final_model,
        filename=BEST_MODEL_FILENAME,
        metadata=metadata,
        promote_to_production=False,
    )
    manager.save_model(
        final_model,
        filename=MODEL_FILENAME,
        metadata=metadata,
        promote_to_production=True,
    )
    manager.save_label_encoder(joblib.load(PROCESSED_DATASET_DIR / LABEL_ENCODER_FILENAME))

    _save_reports(
        benchmark_df=benchmark_df,
        benchmark_details=benchmark_details,
        benchmark_summary=benchmark_summary,
        cross_validation_summary=cross_validation_summary,
        evaluation_summary=evaluation_summary,
        model_name=final_model_name,
        training_time_s=float(final_training_time_s),
        best_params=best_params,
        active_features=active_features,
        manager=manager,
    )

    total_time = time.perf_counter() - start_time
    LOGGER.info("Training completed in %.2fs", total_time)

    summary = {
        "metadata": metadata,
        "benchmark": benchmark_summary,
        "cross_validation": cross_validation_summary,
        "evaluation": evaluation_summary,
        "feature_importance_rows": int(len(feature_importance)),
        "total_time_s": float(total_time),
    }

    with (MODEL_OUTPUT_DIR / "summary.json").open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, default=str)

    return summary


if __name__ == "__main__":
    main()