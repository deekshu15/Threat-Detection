"""
Dataset Inspector

Analyzes the merged CICIDS2017 dataset before preprocessing.
"""

from __future__ import annotations

import numpy as np

from .dataset_loader import load_dataset


def inspect():

    df = load_dataset()

    print("\n==============================")
    print("DATASET INFORMATION")
    print("==============================")

    print(df.info())

    print("\nShape:")
    print(df.shape)

    print("\nMissing Values:")

    missing = df.isna().sum()

    print(
        missing[
            missing > 0
        ].sort_values(
            ascending=False
        )
    )

    print("\nDuplicate Rows:")

    print(df.duplicated().sum())

    print("\nInfinite Values:")

    numeric = df.select_dtypes(
        include=np.number
    )

    print(
        np.isinf(
            numeric
        ).sum().sum()
    )

    print("\nAttack Labels:")

    print(
        df["Label"]
        .value_counts()
    )

    print("\nNumeric Columns:")

    print(
        len(
            numeric.columns
        )
    )

    print("\nCategorical Columns:")

    print(
        len(
            df.select_dtypes(
                exclude=np.number
            ).columns
        )
    )


if __name__ == "__main__":

    inspect()