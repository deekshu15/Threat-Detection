from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd


class DashboardDataError(Exception):
    """Raised when dashboard data cannot be loaded or processed."""


class DashboardService:
    """
    Reads the latest processed security dataset and generates
    dashboard-ready statistics.

    This service does NOT modify the ML pipeline.
    """

    def __init__(self) -> None:
        self.processed_dir = (
            Path(__file__).resolve().parent.parent.parent
            / "datasets"
            / "processed"
        )

    # ---------------------------------------------------------
    # FILE LOADING
    # ---------------------------------------------------------

    def get_latest_processed_file(self) -> Path:
        if not self.processed_dir.exists():
            raise DashboardDataError(
                "Processed dataset directory does not exist."
            )

        files = list(self.processed_dir.glob("processed_*.csv"))

        if not files:
            raise DashboardDataError(
                "No processed dataset available. Upload a dataset first."
            )

        # Most recently modified processed dataset
        files.sort(
            key=lambda file: file.stat().st_mtime,
            reverse=True,
        )

        return files[0]

    def load_latest_dataset(self) -> tuple[pd.DataFrame, Path]:
        file_path = self.get_latest_processed_file()

        try:
            df = pd.read_csv(file_path)
        except Exception as exc:
            raise DashboardDataError(
                f"Unable to read processed dataset: {exc}"
            ) from exc

        if df.empty:
            raise DashboardDataError(
                "The processed dataset is empty."
            )

        return df, file_path

    # ---------------------------------------------------------
    # COLUMN HELPERS
    # ---------------------------------------------------------

    @staticmethod
    def find_column(
        df: pd.DataFrame,
        candidates: list[str],
    ) -> str | None:
        """
        Finds a column using case-insensitive matching.
        """

        normalized = {
            str(column).strip().lower(): column
            for column in df.columns
        }

        for candidate in candidates:
            key = candidate.strip().lower()

            if key in normalized:
                return normalized[key]

        # More flexible comparison
        for column in df.columns:
            column_normalized = (
                str(column)
                .strip()
                .lower()
                .replace("_", " ")
                .replace("-", " ")
            )

            for candidate in candidates:
                candidate_normalized = (
                    candidate.strip()
                    .lower()
                    .replace("_", " ")
                    .replace("-", " ")
                )

                if column_normalized == candidate_normalized:
                    return column

        return None

    @staticmethod
    def clean_value(value: Any) -> Any:
        if pd.isna(value):
            return None

        if hasattr(value, "item"):
            try:
                return value.item()
            except Exception:
                pass

        if isinstance(value, pd.Timestamp):
            return value.isoformat()

        return value

    # ---------------------------------------------------------
    # DATASET INFORMATION
    # ---------------------------------------------------------

    def get_metadata(
        self,
        df: pd.DataFrame,
        file_path: Path,
    ) -> dict[str, Any]:

        return {
            "filename": file_path.name,
            "rows": int(len(df)),
            "columns": int(len(df.columns)),
            "dataset_type": self.detect_dataset_type(df),
            "available_columns": [
                str(column)
                for column in df.columns
            ],
        }

    def detect_dataset_type(
        self,
        df: pd.DataFrame,
    ) -> str:

        columns = {
            str(column).lower()
            for column in df.columns
        }

        if "label" in columns:
            return "CICIDS2017 / Security Logs"

        if "cve_id" in columns or "cveid" in columns:
            return "CVE"

        if "severity" in columns and (
            "src_ip" in columns
            or "source_ip" in columns
        ):
            return "Security Event Logs"

        return "Security Dataset"

    # ---------------------------------------------------------
    # LABEL / THREAT DETECTION
    # ---------------------------------------------------------

    def get_label_column(
        self,
        df: pd.DataFrame,
    ) -> str | None:

        return self.find_column(
            df,
            [
                # Normalized security schema
                "event_type",

                # Original dataset labels
                "Label",
                "label",

                # Other possible schemas
                "attack",
                "attack_type",
                "attack type",
                "threat",
                "threat_type",
                "threat type",
                "classification",
                "class",
            ],
        )

    @staticmethod
    def is_benign(value: Any) -> bool:

        if value is None:
            return False

        normalized = str(value).strip().lower()

        benign_values = {
            "benign",
            "normal",
            "normal traffic",
            "safe",
            "legitimate",
            "0",
            "false",
        }

        return normalized in benign_values

    def get_summary(
        self,
        df: pd.DataFrame,
    ) -> dict[str, Any]:

        total_events = len(df)

        label_column = self.get_label_column(df)

        benign_events = 0
        threat_events = 0

        if label_column:
            benign_mask = df[label_column].apply(
                self.is_benign
            )

            benign_events = int(benign_mask.sum())
            threat_events = int(
                total_events - benign_events
            )

        return {
            "total_events": int(total_events),
            "benign_events": benign_events,
            "threat_events": threat_events,
            "threat_percentage": (
                round(
                    (threat_events / total_events) * 100,
                    2,
                )
                if total_events
                else 0
            ),
            "label_column": (
                str(label_column)
                if label_column
                else None
            ),
        }

    # ---------------------------------------------------------
    # SEVERITY
    # ---------------------------------------------------------

    def get_severity(
        self,
        df: pd.DataFrame,
    ) -> list[dict[str, Any]]:

        column = self.find_column(
            df,
            [
                "severity",
                "Severity",
                "risk_level",
                "risk level",
                "priority",
            ],
        )

        if not column:
            return []

        counts = (
            df[column]
            .fillna("Unknown")
            .astype(str)
            .value_counts()
        )

        return [
            {
                "name": str(name),
                "value": int(value),
            }
            for name, value in counts.items()
        ]

    # ---------------------------------------------------------
    # ATTACK DISTRIBUTION
    # ---------------------------------------------------------

    def get_attack_distribution(
        self,
        df: pd.DataFrame,
    ) -> list[dict[str, Any]]:

        label_column = self.get_label_column(df)

        if not label_column:
            return []

        counts = (
            df[label_column]
            .fillna("Unknown")
            .astype(str)
            .value_counts()
            .head(10)
        )

        return [
            {
                "name": str(name),
                "value": int(value),
            }
            for name, value in counts.items()
        ]

    # ---------------------------------------------------------
    # TREND
    # ---------------------------------------------------------

    def get_trend(
        self,
        df: pd.DataFrame,
    ) -> list[dict[str, Any]]:

        timestamp_column = self.find_column(
            df,
            [
                "timestamp",
                "Timestamp",
                "datetime",
                "date",
                "time",
                "flow_start",
                "Flow Start",
            ],
        )

        if not timestamp_column:
            return []

        timestamps = pd.to_datetime(
            df[timestamp_column],
            errors="coerce",
        )

        valid = df.loc[timestamps.notna()].copy()

        if valid.empty:
            return []

        valid["_dashboard_time"] = timestamps.loc[
            timestamps.notna()
        ]

        valid["_dashboard_date"] = (
            valid["_dashboard_time"]
            .dt.date
            .astype(str)
        )

        trend = (
            valid.groupby("_dashboard_date")
            .size()
            .reset_index(name="events")
        )

        trend = trend.sort_values(
            "_dashboard_date"
        ).tail(30)

        return [
            {
                "date": str(row["_dashboard_date"]),
                "events": int(row["events"]),
            }
            for _, row in trend.iterrows()
        ]

    # ---------------------------------------------------------
    # RECENT EVENTS
    # ---------------------------------------------------------

    def get_recent_events(
        self,
        df: pd.DataFrame,
        limit: int = 10,
    ) -> list[dict[str, Any]]:

        label_column = self.get_label_column(df)

        severity_column = self.find_column(
            df,
            [
                "severity",
                "Severity",
                "risk_level",
                "risk level",
            ],
        )

        source_column = self.find_column(
            df,
            [
                "src_ip",
                "source_ip",
                "source",
                "Source IP",
                "Src IP",
            ],
        )

        destination_column = self.find_column(
            df,
            [
                "dst_ip",
                "dest_ip",
                "destination_ip",
                "destination",
                "Destination IP",
                "Dst IP",
            ],
        )

        timestamp_column = self.find_column(
            df,
            [
                "timestamp",
                "Timestamp",
                "datetime",
                "date",
                "time",
            ],
        )

        records = []

        recent_df = df.tail(limit).iloc[::-1]

        for _, row in recent_df.iterrows():

            timestamp = (
                self.clean_value(row[timestamp_column])
                if timestamp_column
                else None
            )

            source = (
                self.clean_value(row[source_column])
                if source_column
                else None
            )

            destination = (
                self.clean_value(row[destination_column])
                if destination_column
                else None
            )

            threat = (
                self.clean_value(row[label_column])
                if label_column
                else None
            )

            severity = (
                self.clean_value(row[severity_column])
                if severity_column
                else None
            )

            records.append(
                {
                    "timestamp": timestamp,
                    "source": source,
                    "destination": destination,
                    "threat": threat,
                    "severity": severity,
                }
            )

        return records

    # ---------------------------------------------------------
    # COMPLETE DASHBOARD RESPONSE
    # ---------------------------------------------------------

    def get_dashboard(self) -> dict[str, Any]:

        df, file_path = self.load_latest_dataset()

        return {
            "success": True,

            "metadata": self.get_metadata(
                df,
                file_path,
            ),

            "summary": self.get_summary(df),

            "severity": self.get_severity(df),

            "attack_distribution": (
                self.get_attack_distribution(df)
            ),

            "trend": self.get_trend(df),

            "recent_events": (
                self.get_recent_events(df)
            ),
        }