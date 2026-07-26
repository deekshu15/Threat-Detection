"""
Dataset detector.

Determines the type of security log based on the S3 object key.
"""

from pathlib import Path


class DatasetDetector:
    """Detect dataset type from S3 object path."""

    @staticmethod
    def detect(s3_key: str) -> str:
        """
        Detect dataset source.

        Args:
            s3_key: S3 object key

        Returns:
            Dataset source name.
        """

        path = s3_key.lower()

        if "windows" in path:
            return "windows"

        if "ids" in path:
            return "ids"

        if "linux" in path:
            return "linux"

        if "firewall" in path:
            return "firewall"

        if "cve" in path:
            return "cve"

        if "threat_feeds" in path:
            return "threat_feeds"

        if "incident_records" in path:
            return "incident_records"

        raise ValueError(f"Unsupported dataset: {Path(s3_key).name}")