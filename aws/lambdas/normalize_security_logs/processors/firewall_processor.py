"""
Firewall Processor

Normalizes firewall logs into the common SecurityEvent schema.
"""

import pandas as pd

from processors.base_processor import BaseProcessor
from utils.validator import DatasetValidator


class FirewallProcessor(BaseProcessor):
    """Processor for firewall log datasets."""

    SOURCE_NAME = "firewall"

    def validate(self, dataframe: pd.DataFrame) -> bool:
        """
        Validate firewall dataset.
        """

        DatasetValidator.validate_not_empty(dataframe)

        return True

    def normalize(self, dataframe: pd.DataFrame) -> pd.DataFrame:
        """
        Normalize firewall logs into the common schema.
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
        normalized["hostname"] = (
            dataframe["Hostname"]
            if "Hostname" in dataframe.columns
            else "Unknown"
        )

        # Username
        normalized["username"] = (
            dataframe["Username"]
            if "Username" in dataframe.columns
            else "Unknown"
        )

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
        normalized["event_type"] = (
            dataframe["Action"]
            if "Action" in dataframe.columns
            else "Unknown"
        )

        # Severity
        normalized["severity"] = (
            dataframe["Severity"]
            if "Severity" in dataframe.columns
            else "Medium"
        )

        # Raw Message
        normalized["raw_message"] = (
            dataframe["Message"]
            if "Message" in dataframe.columns
            else None
        )

        return normalized