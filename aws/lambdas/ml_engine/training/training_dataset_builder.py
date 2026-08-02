from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from .event_generator import generate_event

# IMPORTANT:
# Adjust this import if your feature pipeline exposes a different function.
from feature_engineering.feature_pipeline import process_event


BASE_DIR = Path(__file__).resolve().parent

PROCESSED_DIR = BASE_DIR / "datasets" / "processed"

OUTPUT_DIR = BASE_DIR / "saved_models"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def build_dataset(parquet_file, prefix):

    df = pd.read_parquet(parquet_file)
    X = []

    y = []

    total = len(df)

    print(f"\nBuilding {prefix} dataset")
    print(f"Rows: {total:,}")

    for index, (_, row) in enumerate(df.iterrows(), start=1):

        event = generate_event(row)

        result = process_event(event)

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