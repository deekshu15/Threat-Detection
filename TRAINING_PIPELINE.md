# Training Pipeline

Overview
--------
This document describes the training pipeline for the AI-Assisted Threat Detection Dashboard. The training pipeline ingests raw CICIDS2017 CSVs, preprocesses the data, engineers flow/temporal/network/behavioral/statistical features, builds training datasets, trains a RandomForest classifier, and exports model artifacts and evaluation reports.

Key Principles
--------------
- No label leakage: ground-truth `Label` is never present during feature engineering for training. Train/test partitions are written without `Label`.
- Deterministic feature engineering: all features derive only from raw flow attributes or past events (chronological processing).
- Stateful components (behavioral/statistical) are reset between partitions.

Files of interest
-----------------
- `aws/lambdas/ml_engine/training/preprocess.py` — loads CSVs, cleans, encodes `Label` → `Target`, writes `train.parquet`/`test.parquet` without `Label`.
- `aws/lambdas/ml_engine/training/event_generator.py` — converts each DataFrame row into an event dict; raw flow columns (excluding `Label`) are preserved for flow feature extraction.
- `aws/lambdas/feature_engineering/flow_features.py` — new: computes flow-derived features (duration, packets/sec, bytes/sec, avg packet size, forward/backward counts/ratios, TCP flag counts, etc.).
- `aws/lambdas/feature_engineering/feature_pipeline.py` — pipeline now integrates flow features alongside network/temporal/behavioral/statistical features and exposes `reset_pipeline()`.
- `aws/lambdas/ml_engine/training/training_dataset_builder.py` — builds X/y arrays; ensures chronological ordering when timestamp present and checks for forbidden columns.
- `aws/lambdas/ml_engine/training/train_model.py` — trains RandomForest, performs leakage detection, drops near-constant features, writes `risk_classifier.pkl`, `feature_importance.csv`, `training_report.json`, and `active_features.json`.

Feature List (final)
--------------------
Temporal:
- hour, minute, day, weekday, month, quarter, is_weekend, is_business_hours

Network:
- protocol_encoded, src_internal, dest_internal, src_private, dest_private, src_loopback, dest_loopback, same_subnet, network_direction, ip_version, src_port_category, dest_port_category, src_well_known, dest_well_known, privileged_src_port, privileged_dest_port, src_port, dest_port

Behavioral:
- user_event_count, host_event_count

Statistical:
- rolling_event_count

Flow-derived:
- flow_duration_seconds, total_packets, total_bytes, fwd_packets, bwd_packets, fwd_bytes, bwd_bytes, packets_per_second, bytes_per_second, avg_packet_size, fwd_bwd_packet_ratio, fwd_bwd_byte_ratio, fwd_packet_len_mean, bwd_packet_len_mean, flow_iat_mean, packet_length_mean, packet_length_std, inter_arrival_time_mean, tcp_syn_count, tcp_ack_count, tcp_rst_count, tcp_fin_count, tcp_psh_count, tcp_urg_count

Running the pipeline (quick)
---------------------------
1. Create virtualenv and install deps:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r aws/lambdas/ml_engine/training/requirements.txt
```

2. Preprocess and build datasets:

```powershell
python aws/lambdas/ml_engine/training/preprocess.py
python aws/lambdas/ml_engine/training/training_dataset_builder.py
```

3. Train model:

```powershell
python aws/lambdas/ml_engine/training/train_model.py
```

Artifacts produced
------------------
- `aws/lambdas/ml_engine/training/datasets/processed/train.parquet`
- `aws/lambdas/ml_engine/training/datasets/processed/test.parquet`
- `aws/lambdas/ml_engine/training/saved_models/X_train.npy`, `y_train.npy`, etc.
- `aws/lambdas/ml_engine/training/saved_models/risk_classifier.pkl`
- `aws/lambdas/ml_engine/training/saved_models/feature_importance.csv`
- `aws/lambdas/ml_engine/training/saved_models/training_report.json`
- `aws/lambdas/ml_engine/training/saved_models/active_features.json`

Notes & Next Steps
------------------
- Consider switching to a time-based (temporal) train/test split for production when behavioral/statistical features are used.
- Replace singleton in-memory behavioral/statistics with deterministic windowed aggregations if parallel processing is required.
- Optionally add hyperparameter tuning (GridSearch/RandomSearch) and LightGBM/XGBoost comparison.

