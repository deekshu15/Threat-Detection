"""
constants.py

Constants used during model training.
"""

# ==========================================================
# Target Labels
# ==========================================================

LOW = "Low"
MEDIUM = "Medium"
HIGH = "High"
CRITICAL = "Critical"

# ==========================================================
# Feature Columns
# IMPORTANT:
# Must exactly match the inference pipeline.
# ==========================================================

FEATURE_COLUMNS = [
    "source_id",
    "technique_id",
    "asset_score",
    "known_attack",
    "severity_score",
    "risk_weight",
]

# ==========================================================
# Target Column
# ==========================================================

TARGET_COLUMN = "risk_level"

# ==========================================================
# Dataset Split
# ==========================================================

TEST_SIZE = 0.20

RANDOM_STATE = 42

# ==========================================================
# Model Names
# ==========================================================

MODEL_FILENAME = "risk_classifier.pkl"

LABEL_ENCODER_FILENAME = "label_encoder.pkl"