"""
Windows Security Log Processor.

Reads Windows event logs and converts them to the common security schema.
"""

import json
from pathlib import Path

import pandas as pd

from processors.base_processor import BaseProcessor
from utils.validator import DatasetValidator


class WindowsProcessor(BaseProcessor):
    """Processor for Windows Security Logs."""

    # Windows Event Level → Standard Severity
    SEVERITY_MAP = {
        0: "Informational",
        1: "Low",
        2: "Medium",
        3: "High",
        4: "Critical"
    }

    def __init__(self):
        mapping_file = (
            Path(__file__).resolve().parents[1]
            / "mappings"
            / "windows_mapping.json"
        )

        with open(mapping_file, "r") as file:
            self.mapping = json.load(file)

    def validate(self, dataframe: pd.DataFrame) -> bool:
        """
        Validate the Windows dataset.
        """

        DatasetValidator.validate_not_empty(dataframe)

        DatasetValidator.validate_required_columns(
            dataframe,
            list(self.mapping.values())
        )

        return True

    def normalize(self, dataframe: pd.DataFrame) -> pd.DataFrame:
        """
        Normalize Windows logs into the common schema.
        """

        self.validate(dataframe)

        normalized = pd.DataFrame()

        # ----------------------------------------------------------
        # Map columns from Windows dataset to common schema
        # ----------------------------------------------------------
        for new_column, original_column in self.mapping.items():

            if original_column in dataframe.columns:
                normalized[new_column] = dataframe[original_column]
            else:
                normalized[new_column] = None

        # ----------------------------------------------------------
        # Better username handling
        # ----------------------------------------------------------
        if "User" in dataframe.columns and "TargetUserName" in dataframe.columns:
            normalized["username"] = dataframe["User"].fillna(
                dataframe["TargetUserName"]
            )

        # ----------------------------------------------------------
        # Convert timestamp
        # ----------------------------------------------------------
        normalized["timestamp"] = pd.to_datetime(
            normalized["timestamp"],
            errors="coerce"
        )

        # ----------------------------------------------------------
        # Convert Windows Event Level to Severity
        # ----------------------------------------------------------
        normalized["severity"] = (
            normalized["severity"]
            .map(self.SEVERITY_MAP)
            .fillna("Unknown")
        )

        # ----------------------------------------------------------
        # Dataset Source
        # ----------------------------------------------------------
        normalized["source"] = "windows"

        # ----------------------------------------------------------
        # Raw message placeholder
        # ----------------------------------------------------------
        normalized["raw_message"] = None

        # ----------------------------------------------------------
        # Final column order
        # ----------------------------------------------------------
        normalized = normalized[
            [
                "event_id",
                "timestamp",
                "source",
                "hostname",
                "username",
                "src_ip",
                "dst_ip",
                "protocol",
                "event_type",
                "severity",
                "raw_message",
            ]
        ]

        return normalized