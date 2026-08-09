"""
Dataset Loader

Loads and combines CICIDS2017 CSV datasets.
"""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
import logging
from pathlib import Path
from typing import List

import pandas as pd


logger = logging.getLogger(__name__)


def _load_csv(path: Path) -> pd.DataFrame:
    dataframe = pd.read_csv(path, low_memory=False)
    dataframe["source_file"] = path.name
    return dataframe


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

        max_workers = min(4, max(1, len(csv_files)))
        logger.info("Loading %s CSV files using %s workers", len(csv_files), max_workers)

        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            dataframes = list(executor.map(_load_csv, csv_files))

        merged = pd.concat(
            dataframes,
            ignore_index=True,
        )
        # Remove leading/trailing whitespace from all column names
        merged.columns = merged.columns.str.strip()

        logger.info("Loaded %s files", len(csv_files))
        logger.info("Total rows: %s", f"{len(merged):,}")
        logger.info("Columns: %s", len(merged.columns))

        return merged


_loader = DatasetLoader()


def load_dataset():

    return _loader.load()


if __name__ == "__main__":

    df = load_dataset()

    print()

    print(df.head())