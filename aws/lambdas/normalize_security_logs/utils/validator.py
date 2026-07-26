"""
Dataset validation utilities.

Validates security datasets before normalization.
"""

from pathlib import Path
import pandas as pd

from constants import SUPPORTED_FILE_TYPES, DATA_SOURCES


class DatasetValidator:
    """Validates security datasets."""

    @staticmethod
    def validate_file_type(file_name: str) -> bool:
        """
        Validate file extension.
        """
        extension = Path(file_name).suffix.lower()

        if extension not in SUPPORTED_FILE_TYPES:
            raise ValueError(
                f"Unsupported file type: {extension}"
            )

        return True

    @staticmethod
    def validate_not_empty(df: pd.DataFrame) -> bool:
        """
        Ensure DataFrame is not empty.
        """
        if df.empty:
            raise ValueError("Dataset is empty.")

        return True

    @staticmethod
    def validate_required_columns(
        df: pd.DataFrame,
        required_columns: list
    ) -> bool:
        """
        Validate required columns.
        """
        missing = [
            col for col in required_columns
            if col not in df.columns
        ]

        if missing:
            raise ValueError(
                f"Missing required columns: {missing}"
            )

        return True

    @staticmethod
    def validate_dataset_source(source: str) -> bool:
        """
        Validate dataset source.
        """
        if source not in DATA_SOURCES:
            raise ValueError(
                f"Unsupported dataset source: {source}"
            )

        return True