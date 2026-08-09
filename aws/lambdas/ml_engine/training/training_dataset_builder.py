from __future__ import annotations

import logging
import importlib.util
import importlib
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

logger = logging.getLogger(__name__)

if importlib.util.find_spec("tqdm") is not None:
    tqdm = importlib.import_module("tqdm").tqdm
else:  # pragma: no cover - tqdm is optional.
    def tqdm(iterable, **_kwargs):
        return iterable


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
    total = len(df)

    logger.info("Building %s dataset (%s rows)", prefix, f"{total:,}")

    # Reset pipeline state to avoid leakage from prior runs (e.g.,
    # behavioural/statistical history). This ensures train/test
    # partitions are processed independently.
    try:
        pipeline.reset_pipeline()
    except Exception:
        # If reset is not available, continue but warn
        logger.warning("Feature pipeline reset unavailable.")

    if total == 0:
        raise ValueError(f"No rows found in {parquet_file}")

    first_event = generate_event(df.iloc[0])
    feature_width = len(pipeline.process_event(first_event)["vector"])
    try:
        pipeline.reset_pipeline()
    except Exception:
        logger.warning("Feature pipeline reset unavailable after width probe.")
    X = np.empty((total, feature_width), dtype=np.float32)
    y = np.empty(total, dtype=np.int32)

    for index, (_, row) in enumerate(tqdm(df.iterrows(), total=total, desc=f"Building {prefix}"), start=0):

        event = generate_event(row)

        result = pipeline.process_event(event)

        X[index] = np.asarray(result["vector"], dtype=np.float32)

        y[index] = int(row["Target"])

        if (index + 1) % 50000 == 0:

            logger.info("%s/%s", f"{index + 1:,}", f"{total:,}")

    np.save(OUTPUT_DIR / f"X_{prefix}.npy", X)

    np.save(OUTPUT_DIR / f"y_{prefix}.npy", y)

    logger.info("Saved X_%s.npy", prefix)
    logger.info("Saved y_%s.npy", prefix)
    logger.info("Shape: %s", X.shape)

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