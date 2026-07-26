"""
config.py

Configuration for ML Engine.
"""

from pathlib import Path

# ==========================================================
# Base Directory
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent

# ==========================================================
# Model Directory
# ==========================================================

MODEL_DIR = BASE_DIR / "models"

# ==========================================================
# Model Paths
# ==========================================================

MODEL_PATH = MODEL_DIR / "risk_classifier.pkl"

LABEL_ENCODER_PATH = MODEL_DIR / "label_encoder.pkl"

# ==========================================================
# Prediction Settings
# ==========================================================

ENABLE_PROBABILITY = True

ROUND_CONFIDENCE = 4