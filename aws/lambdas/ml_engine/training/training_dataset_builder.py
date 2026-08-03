from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from .event_generator import generate_event

# Import the feature pipeline module so we can reset stateful components
import feature_engineering.feature_pipeline as pipeline

# Validator check for forbidden training columns
from feature_engineering.validator import (
    check_forbidden_training_columns,
)


BASE_DIR = Path(__file__).resolve().parent

PROCESSED_DIR = BASE_DIR / "datasets" / "processed"

OUTPUT_DIR = BASE_DIR / "saved_models"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def build_dataset(parquet_file, prefix):

    df = pd.read_parquet(parquet_file)
    # Safety: ensure no forbidden label-derived columns exist in the
    # training partition. This prevents accidental leakage.
    forbidden = check_forbidden_training_columns(list(df.columns))

    if forbidden:
        raise RuntimeError(
            "Forbidden training columns present: " + ", ".join(forbidden)
        )
    # If a timestamp column exists, ensure chronological ordering so that
    # behavioural/statistical features reflect past events only (no peeking)
    ts_col = None
    for cand in ("timestamp", "Timestamp", "time", "Time"):
        if cand in df.columns:
            ts_col = cand
            break

    if ts_col is not None:
        try:
            df[ts_col] = pd.to_datetime(df[ts_col])
            df = df.sort_values(by=ts_col, ascending=True).reset_index(drop=True)
        except Exception:
            print("Warning: failed to parse/sort timestamps; proceeding without chronological ordering.")
    X = []

    y = []

    total = len(df)

    print(f"\nBuilding {prefix} dataset")
    print(f"Rows: {total:,}")

    # Reset pipeline state to avoid leakage from prior runs (e.g.,
    # behavioural/statistical history). This ensures train/test
    # partitions are processed independently.
    try:
        pipeline.reset_pipeline()
    except Exception:
        # If reset is not available, continue but warn
        print("Warning: feature pipeline reset unavailable.")

    for index, (_, row) in enumerate(df.iterrows(), start=1):

        event = generate_event(row)

        result = pipeline.process_event(event)

        vector = result["vector"]

        X.append(vector)

        y.append(row["Target"])

        if index % 10000 == 0:

            print(f"{index:,}/{total:,}")

    X = np.asarray(X, dtype=np.float32)

    y = np.asarray(y, dtype=np.int32)

    np.save(OUTPUT_DIR / f"X_{prefix}.npy", X)

    np.save(OUTPUT_DIR / f"y_{prefix}.npy", y)

    print()

    print(f"Saved X_{prefix}.npy")

    print(f"Saved y_{prefix}.npy")

    print("Shape:", X.shape)

    return X, y


def main():

    build_dataset(

        PROCESSED_DIR / "train.parquet",

        "train",

    )

    build_dataset(

        PROCESSED_DIR / "test.parquet",

        "test",

    )

if __name__ == "__main__":

    main()