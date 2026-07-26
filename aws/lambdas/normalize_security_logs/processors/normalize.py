"""
Normalization Pipeline.

Coordinates dataset detection, processor selection,
and normalization into the common security schema.
"""

import pandas as pd

from processors.detector import DatasetDetector
from processors.factory import ProcessorFactory


class Normalizer:
    """Main normalization pipeline."""

    @staticmethod
    def normalize_dataframe(
        dataframe: pd.DataFrame,
        dataset_path: str
    ) -> pd.DataFrame:
        """
        Normalize any supported dataset.

        Args:
            dataframe: Input DataFrame.
            dataset_path: Dataset path or S3 object key.

        Returns:
            Normalized DataFrame.
        """

        # Detect dataset type
        dataset_type = DatasetDetector.detect(dataset_path)

        # Create processor
        processor = ProcessorFactory.create(dataset_type)

        # Normalize dataset
        normalized_df = processor.normalize(dataframe)

        return normalized_df