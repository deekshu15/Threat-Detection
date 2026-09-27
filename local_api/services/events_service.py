from __future__ import annotations

import csv
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from local_api.models.event import SecurityEvent


logger = logging.getLogger("local_api.events")


class EventsService:
    def __init__(self) -> None:
        self.data_dir = Path(__file__).resolve().parent.parent.parent / "datasets"
        self.events_dir = (
            self.data_dir / "processed"
        )
        self.events_file = self.events_dir / "security_events.csv"
        self._ensure_file()

    def _latest_processed_file(self) -> Path | None:
        files = list(self.events_dir.glob("processed_*.csv"))
        if not files:
            return None
        return max(files, key=lambda file: file.stat().st_mtime)

    @staticmethod
    def _find_column(df: pd.DataFrame, *names: str) -> str | None:
        columns = {str(column).strip().lower(): column for column in df.columns}
        for name in names:
            if name.lower() in columns:
                return columns[name.lower()]
        return None

    def _load_dashboard_events(self) -> pd.DataFrame:
        """Load the same processed dataset used by the dashboard when available."""
        processed_file = self._latest_processed_file()
        if processed_file is None:
            return pd.read_csv(self.events_file) if self.events_file.exists() else pd.DataFrame()

        df = pd.read_csv(processed_file, low_memory=False)
        mappings = {
            "event_id": ("event_id", "id"),
            "timestamp": ("timestamp", "datetime", "date", "time"),
            "source": ("source", "src_ip", "source_ip"),
            "tool": ("tool", "source"),
            "target": ("target", "dst_ip", "destination_ip"),
            "source_ip": ("source_ip", "src_ip"),
            "destination_ip": ("destination_ip", "dst_ip"),
            "attack_type": ("attack_type", "event_type", "label", "class"),
            "severity": ("severity", "risk_level", "priority"),
            "risk_score": ("risk_score", "score"),
            "description": ("description", "raw_message", "message"),
            "recommendation": ("recommendation", "recommended_action"),
        }

        normalized = pd.DataFrame(index=df.index, dtype=object)
        for output_name, candidates in mappings.items():
            column = self._find_column(df, *candidates)
            normalized[output_name] = df[column] if column else None

        missing_event_ids = normalized["event_id"].isna()
        if missing_event_ids.any():
            normalized.loc[missing_event_ids, "event_id"] = [
                str(index) for index in normalized.index[missing_event_ids]
            ]
        normalized["source"] = normalized["source"].fillna("Unknown")
        normalized["tool"] = normalized["tool"].fillna(normalized["source"])
        normalized["attack_type"] = normalized["attack_type"].fillna("Unknown")
        normalized["severity"] = normalized["severity"].fillna("Unknown")
        return normalized

    def _ensure_file(self) -> None:
        if not self.events_dir.exists():
            self.events_dir.mkdir(parents=True, exist_ok=True)

        if not self.events_file.exists():
            self._write_header()

    def _write_header(self) -> None:
        fieldnames = list(SecurityEvent.model_fields.keys())
        with open(self.events_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

    def _append_event(self, event: SecurityEvent) -> None:
        fieldnames = list(SecurityEvent.model_fields.keys())
        with open(self.events_file, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writerow(event.model_dump())

    def save_event(self, event: SecurityEvent) -> SecurityEvent:
        if not event.event_id:
            event.event_id = str(uuid.uuid4())
        if not event.timestamp:
            event.timestamp = datetime.now(timezone.utc).isoformat()
        event.ingestion_time = datetime.now(timezone.utc).isoformat()

        self._append_event(event)
        logger.info("Saved security event %s from %s", event.event_id, event.tool or event.source)
        return event

    def get_events(self, limit: int = 100) -> list[dict[str, Any]]:
        try:
            df = self._load_dashboard_events()
        except Exception as exc:
            logger.error("Failed to read events: %s", exc)
            return []

        if df.empty:
            return []

        if "timestamp" in df.columns:
            df = df.sort_values("timestamp", ascending=False, na_position="last")
        df = df.head(limit)
        return json.loads(df.to_json(orient="records"))

    def get_analytics(self) -> dict[str, Any]:
        try:
            df = self._load_dashboard_events()
        except Exception as exc:
            logger.error("Failed to read events for analytics: %s", exc)
            return self._empty_analytics()

        if df.empty:
            return self._empty_analytics()

        total_events = len(df)
        severity_counts = df["severity"].fillna("Unknown").astype(str).value_counts().to_dict()
        attack_type_counts = df["attack_type"].fillna("Unknown").astype(str).value_counts().head(10).to_dict()
        tool_counts = df["tool"].fillna("Unknown").astype(str).value_counts().to_dict()

        risk_scores = pd.to_numeric(df["risk_score"], errors="coerce").dropna()
        average_risk_score = float(risk_scores.mean()) if not risk_scores.empty else 0.0

        severity_values = df["severity"].fillna("Unknown").astype(str).str.lower()
        critical_events = int((severity_values == "critical").sum())
        high_events = int((severity_values == "high").sum())
        medium_events = int((severity_values == "medium").sum())
        low_events = int((severity_values == "low").sum())

        return {
            "total_events": total_events,
            "critical_events": critical_events,
            "high_events": high_events,
            "medium_events": medium_events,
            "low_events": low_events,
            "average_risk_score": round(average_risk_score, 2),
            "severity_distribution": [
                {"severity": k, "count": int(v)} for k, v in severity_counts.items()
            ],
            "attack_type_frequency": [
                {"attack_type": k, "count": int(v)} for k, v in attack_type_counts.items()
            ],
            "tool_distribution": [
                {"tool": k, "count": int(v)} for k, v in tool_counts.items()
            ],
        }

    def _empty_analytics(self) -> dict[str, Any]:
        return {
            "total_events": 0,
            "critical_events": 0,
            "high_events": 0,
            "medium_events": 0,
            "low_events": 0,
            "average_risk_score": 0.0,
            "severity_distribution": [],
            "attack_type_frequency": [],
            "tool_distribution": [],
        }


events_service = EventsService()
