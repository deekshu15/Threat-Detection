"""
Feature Engineering Configuration

Centralized configuration for the Feature Engineering
pipeline.

Author:
AI Threat Detection Dashboard
"""

from __future__ import annotations

from pathlib import Path

# ==========================================================
# Project Paths
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent

PROJECT_ROOT = BASE_DIR.parent

DATA_DIR = PROJECT_ROOT / "datasets"

MODEL_DIR = PROJECT_ROOT / "models"

CACHE_DIR = PROJECT_ROOT / "cache"

LOG_DIR = PROJECT_ROOT / "logs"

# ==========================================================
# Pipeline Configuration
# ==========================================================

PIPELINE_NAME = "Feature Engineering"

PIPELINE_VERSION = "1.0"

ENABLE_VALIDATION = True

ENABLE_CACHING = True

ENABLE_NORMALIZATION = True

ENABLE_STATISTICAL_FEATURES = True

ENABLE_BEHAVIORAL_FEATURES = True

ENABLE_NETWORK_FEATURES = True

ENABLE_TEMPORAL_FEATURES = True

# ==========================================================
# Feature Windows
# ==========================================================

ROLLING_WINDOW_MINUTES = 5

ATTACK_HISTORY_WINDOW = 60

USER_ACTIVITY_WINDOW = 30

HOST_ACTIVITY_WINDOW = 30

MAX_HISTORY_EVENTS = 10000

# ==========================================================
# Normalization
# ==========================================================

CVSS_MAX_SCORE = 10.0

THREAT_SCORE_MAX = 100.0

RISK_SCORE_MAX = 100.0

# ==========================================================
# Internal Networks
# ==========================================================

INTERNAL_NETWORKS = [

    "10.0.0.0/8",

    "172.16.0.0/12",

    "192.168.0.0/16",

    "127.0.0.0/8",

]

# ==========================================================
# Behavioral Risk
# ==========================================================

FAILED_LOGIN_THRESHOLD = 5

PRIVILEGE_ESCALATION_THRESHOLD = 2

IOC_THRESHOLD = 3

HIGH_RISK_EVENT_THRESHOLD = 10

# ==========================================================
# Statistical Features
# ==========================================================

ENABLE_MOVING_AVERAGE = True

ENABLE_STANDARD_DEVIATION = True

ENABLE_EVENT_FREQUENCY = True

ENABLE_ATTACK_FREQUENCY = True

ENABLE_USER_BASELINE = True

ENABLE_HOST_BASELINE = True

# ==========================================================
# Cache
# ==========================================================

CACHE_MAX_USERS = 50000

CACHE_MAX_HOSTS = 50000

CACHE_MAX_EVENTS = 100000

# ==========================================================
# Logging
# ==========================================================

LOG_LEVEL = "INFO"

LOG_FEATURE_COUNT = True

LOG_PIPELINE_TIME = True

# ==========================================================
# Feature Selection
# ==========================================================

DROP_UNUSED_COLUMNS = True

REMOVE_NULL_COLUMNS = True

FILL_NUMERIC_NULLS = 0

FILL_CATEGORICAL_NULLS = "UNKNOWN"

# ==========================================================
# Training
# ==========================================================

TRAIN_TEST_SPLIT = 0.2

RANDOM_STATE = 42

SHUFFLE_DATASET = True

EXPORT_FEATURES = True

FEATURE_EXPORT_FORMAT = "parquet"

# ==========================================================
# Performance
# ==========================================================

MAX_BATCH_SIZE = 5000

MULTI_THREADING = True

NUM_WORKERS = 4

# ==========================================================
# Output
# ==========================================================

OUTPUT_FEATURE_FILE = "engineered_features.parquet"

OUTPUT_METADATA_FILE = "feature_metadata.json"