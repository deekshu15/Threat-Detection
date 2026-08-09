# AI-Assisted-Threat-Detection-Dashboard

AI-Assisted Threat Detection Dashboard is a CICIDS2017-based threat scoring and response platform with a Python ML training pipeline, AWS-backed services, and a dashboard front end.

The production inference path remains unchanged. All of the work in this update stays inside the ML training pipeline under aws/lambdas/ml_engine/training.

## Training Pipeline

The training flow is:

1. Load and clean CICIDS2017 CSVs.
2. Encode labels and create train/test partitions.
3. Build feature vectors through the shared feature-engineering pipeline.
4. Validate the feature contract and detect leakage.
5. Benchmark multiple models on the same split and feature set.
6. Tune Random Forest with RandomizedSearchCV.
7. Generate cross-validation, explainability, and evaluation artifacts.
8. Persist the selected model, active feature list, metadata, and label encoder.

## Generated Artifacts

Training outputs are written under aws/lambdas/ml_engine/training/saved_models.

Key files include:

- benchmark_results.csv
- benchmark_report.json
- best_model.pkl
- best_params.json
- cross_validation.json
- feature_importance.csv
- evaluation/
- explainability/
- metadata.json
- active_features.json
- training_report.json

## Adding Models

The benchmark layer is implemented in aws/lambdas/ml_engine/training/train_model.py.

To add a new model:

1. Extend the estimator factory in train_model.py.
2. Add the model to the benchmark spec list.
3. Ensure predict_proba is available for downstream evaluation and calibration.
4. Re-run the training tests in aws/lambdas/ml_engine/training/tests.

## Detailed Guide

See TRAINING_PIPELINE.md for the end-to-end training steps and artifact overview.