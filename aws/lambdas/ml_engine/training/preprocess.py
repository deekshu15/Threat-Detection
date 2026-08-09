"""
Training Dataset Preprocessor

Prepares CICIDS2017 for ML training.

Pipeline

1. Load merged dataset
2. Strip column names
3. Remove duplicates
4. Replace ±inf with NaN
5. Fill missing numeric values
6. Normalize attack labels
7. Encode labels
8. Train/Test split
9. Save processed datasets
"""

from __future__ import annotations

import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from .dataset_loader import load_dataset


# ==========================================================
# Paths
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent

PROCESSED_DIR = BASE_DIR / "datasets" / "processed"

PROCESSED_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

logger = logging.getLogger(__name__)


# ==========================================================
# Preprocessor
# ==========================================================

class DatasetPreprocessor:

    def preprocess(self):

        logger.info("Loading dataset")

        df = load_dataset()

        logger.info("Original shape: %s", df.shape)

        # ---------------------------------------------
        # Strip whitespace
        # ---------------------------------------------

        df.columns = df.columns.str.strip()

        # ---------------------------------------------
        # Remove duplicates
        # ---------------------------------------------

        duplicates = df.duplicated().sum()

        logger.info("Duplicate rows: %s", duplicates)

        df = df.drop_duplicates()

        # ---------------------------------------------
        # Replace infinities
        # ---------------------------------------------

        df = df.replace(
            [np.inf, -np.inf],
            np.nan,
        )

        # ---------------------------------------------
        # Fill numeric NaNs
        # ---------------------------------------------

        numeric = df.select_dtypes(
            include=np.number
        ).columns

        df[numeric] = df[numeric].fillna(
            df[numeric].median()
        )

        # ---------------------------------------------
        # Fill categorical NaNs
        # ---------------------------------------------

        categorical = df.select_dtypes(
            exclude=np.number
        ).columns

        df[categorical] = df[categorical].fillna(
            "Unknown"
        )

        # ---------------------------------------------
        # Normalize labels
        # ---------------------------------------------

        df["Label"] = (
            df["Label"]
            .astype(str)
            .str.replace("�", "-", regex=False)
            .str.replace("Sql", "SQL", regex=False)
            .str.strip()
        )

        # ---------------------------------------------
        # Encode labels
        # ---------------------------------------------

        encoder = LabelEncoder()

        df["Target"] = encoder.fit_transform(
            df["Label"]
        )

        # ---------------------------------------------
        # Split
        # ---------------------------------------------

        train_df, test_df = train_test_split(

            df,

            test_size=0.20,

            random_state=42,

            stratify=df["Target"],

        )

        logger.info("Train shape: %s", train_df.shape)
        logger.info("Test shape: %s", test_df.shape)

        # ---------------------------------------------
        # Save
        # ---------------------------------------------

        # Save a full processed dataset CSV for evaluation and auditing
        # purposes (contains the original Label). This file is NOT used
        # by the training dataset builder to avoid leakage.
        full_processed = df.copy()
        full_processed.to_csv(
            PROCESSED_DIR / "processed_dataset.csv",
            index=False,
        )

        # Save train/test partitions WITHOUT the original Label column
        # to ensure the training pipeline cannot accidentally access
        # the ground-truth labels during feature generation.
        train_df_no_label = train_df.drop(columns=["Label"], errors="ignore")
        test_df_no_label = test_df.drop(columns=["Label"], errors="ignore")

        train_df_no_label.to_parquet(
            PROCESSED_DIR / "train.parquet",
            index=False,
        )

        test_df_no_label.to_parquet(
            PROCESSED_DIR / "test.parquet",
            index=False,
        )

        # Save the label encoder for later decoding/evaluation
        joblib.dump(
            encoder,
            PROCESSED_DIR / "label_encoder.pkl",
        )

        logger.info("Saved %s", PROCESSED_DIR / "processed_dataset.csv")
        logger.info("Saved %s", PROCESSED_DIR / "train.parquet")
        logger.info("Saved %s", PROCESSED_DIR / "test.parquet")
        logger.info("Saved %s", PROCESSED_DIR / "label_encoder.pkl")
        logger.info("Finished preprocessing")

        return train_df, test_df


# ==========================================================
# Singleton
# ==========================================================

_processor = DatasetPreprocessor()


def preprocess():

    return _processor.preprocess()


# ==========================================================
# Test
# ==========================================================

if __name__ == "__main__":

    preprocess()