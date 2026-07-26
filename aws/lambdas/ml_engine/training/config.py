"""
config.py

Configuration used during training.
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

DATASET_DIR = BASE_DIR / "datasets"

RAW_DATASET_DIR = DATASET_DIR / "raw"

PROCESSED_DATASET_DIR = DATASET_DIR / "processed"

MODEL_OUTPUT_DIR = BASE_DIR / "saved_models"

RAW_DATASET = RAW_DATASET_DIR / "cybersecurity_dataset.csv"

PROCESSED_DATASET = (
    PROCESSED_DATASET_DIR / "processed_dataset.csv"
)

MODEL_PATH = MODEL_OUTPUT_DIR / "risk_classifier.pkl"

LABEL_ENCODER_PATH = (
    MODEL_OUTPUT_DIR / "label_encoder.pkl"
)