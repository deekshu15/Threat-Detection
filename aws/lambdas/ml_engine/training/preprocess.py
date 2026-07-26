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


# ==========================================================
# Preprocessor
# ==========================================================

class DatasetPreprocessor:

    def preprocess(self):

        print("=" * 60)
        print("Loading Dataset")
        print("=" * 60)

        df = load_dataset()

        print()

        print("Original Shape:", df.shape)

        # ---------------------------------------------
        # Strip whitespace
        # ---------------------------------------------

        df.columns = df.columns.str.strip()

        # ---------------------------------------------
        # Remove duplicates
        # ---------------------------------------------

        duplicates = df.duplicated().sum()

        print("Duplicate Rows:", duplicates)

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

        print()

        print("Train:", train_df.shape)

        print("Test :", test_df.shape)

        # ---------------------------------------------
        # Save
        # ---------------------------------------------

        train_df.to_parquet(
            PROCESSED_DIR / "train.parquet",
            index=False,
        )

        test_df.to_parquet(
            PROCESSED_DIR / "test.parquet",
            index=False,
        )

        joblib.dump(

            encoder,

            PROCESSED_DIR / "label_encoder.pkl",

        )

        print()

        print("Saved:")

        print(PROCESSED_DIR / "train.parquet")

        print(PROCESSED_DIR / "test.parquet")

        print(PROCESSED_DIR / "label_encoder.pkl")

        print()

        print("Finished.")

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