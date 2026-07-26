"""
Dataset Loader

Loads and combines CICIDS2017 CSV datasets.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import pandas as pd


class DatasetLoader:

    def __init__(self):

        self.base_path = (
            Path(__file__)
            .resolve()
            .parents[4]
            / "datasets"
            / "raw"
            / "ids"
        )

    def discover_csv_files(self) -> List[Path]:

        files = sorted(
            self.base_path.rglob("*.csv")
        )

        if not files:

            raise FileNotFoundError(
                f"No CSV files found in {self.base_path}"
            )

        return files

    def load(self) -> pd.DataFrame:

        csv_files = self.discover_csv_files()

        dataframes = []

        for file in csv_files:

            print(f"Loading: {file.name}")

            df = pd.read_csv(
                file,
                low_memory=False,
            )

            df["source_file"] = file.name

            dataframes.append(df)

        merged = pd.concat(
            dataframes,
            ignore_index=True,
        )
        # Remove leading/trailing whitespace from all column names
        merged.columns = merged.columns.str.strip()

        print()

        print(f"Loaded {len(csv_files)} files")

        print(f"Total Rows : {len(merged):,}")

        print(f"Columns    : {len(merged.columns)}")

        return merged


_loader = DatasetLoader()


def load_dataset():

    return _loader.load()


if __name__ == "__main__":

    df = load_dataset()

    print()

    print(df.head())