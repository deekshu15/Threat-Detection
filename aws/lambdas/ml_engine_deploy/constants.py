"""
constants.py

Constants used throughout the ML Engine.
"""

# ==========================================================
# Prediction Labels
# ==========================================================

LOW = "Low"
MEDIUM = "Medium"
HIGH = "High"
CRITICAL = "Critical"

# ==========================================================
# Model Files
# ==========================================================

MODEL_FILE = "risk_classifier.pkl"
LABEL_ENCODER_FILE = "label_encoder.pkl"

# ==========================================================
# Prediction Defaults
# ==========================================================

DEFAULT_CONFIDENCE = 0.0
UNKNOWN_RISK = "Unknown"

# ==========================================================
# Feature Order
#
# IMPORTANT:
# This order MUST match the order used during model training.
# ==========================================================

FEATURE_COLUMNS = [

    "source_id",

    "technique_id",

    "asset_score",

    "known_attack",

    "severity_score",

    "risk_weight",
]