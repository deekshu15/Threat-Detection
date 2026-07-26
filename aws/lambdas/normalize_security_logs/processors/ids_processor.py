"""
IDS Processor

Normalizes CICIDS2017 datasets into the common security schema.
"""

import pandas as pd

from processors.base_processor import BaseProcessor
from utils.validator import DatasetValidator


class IDSProcessor(BaseProcessor):
    """Processor for CICIDS2017 datasets."""

    SOURCE_NAME = "ids"

    def validate(self, dataframe: pd.DataFrame) -> bool:
        """
        Validate IDS dataset before normalization.
        """

        DatasetValidator.validate_not_empty(dataframe)

        # Remove leading/trailing spaces in column names
        dataframe.columns = dataframe.columns.str.strip()

        # Ensure Label column exists
        DatasetValidator.validate_required_columns(
            dataframe,
            ["Label"]
        )

        return True

    def normalize(self, dataframe: pd.DataFrame) -> pd.DataFrame:
        """
        Normalize IDS dataset into common schema.
        """

        self.validate(dataframe)

        dataframe.columns = dataframe.columns.str.strip()

        normalized = pd.DataFrame()

        # Event ID
        normalized["event_id"] = range(1, len(dataframe) + 1)

        # Timestamp
        if "Timestamp" in dataframe.columns:
            normalized["timestamp"] = pd.to_datetime(
                dataframe["Timestamp"],
                errors="coerce"
            )
        else:
            normalized["timestamp"] = pd.NaT

        # Source
        normalized["source"] = self.SOURCE_NAME

        # Hostname
        normalized["hostname"] = "Unknown"

        # Username
        normalized["username"] = "Unknown"

        # Source IP
        normalized["src_ip"] = (
            dataframe["Source IP"]
            if "Source IP" in dataframe.columns
            else "N/A"
        )

        # Destination IP
        normalized["dst_ip"] = (
            dataframe["Destination IP"]
            if "Destination IP" in dataframe.columns
            else "N/A"
        )

        # Protocol
        normalized["protocol"] = (
            dataframe["Protocol"]
            if "Protocol" in dataframe.columns
            else "Unknown"
        )

        # Event Type
        normalized["event_type"] = dataframe["Label"]

        # Severity
        def map_severity(label):
            label = str(label).lower()

            if label == "benign":
                return "Low"

            return "High"

        normalized["severity"] = dataframe["Label"].apply(map_severity)

        # Raw message
        normalized["raw_message"] = None

        return normalized