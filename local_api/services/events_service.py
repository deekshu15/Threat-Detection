from __future__ import annotations

import csv
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
        self.events_dir = (
            Path(__file__).resolve().parent.parent.parent
            / "datasets"
            / "processed"
        )
        self.events_file = self.events_dir / "security_events.csv"
        self._ensure_file()

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
        if not self.events_file.exists():
            return []

        try:
            df = pd.read_csv(self.events_file)
        except Exception as exc:
            logger.error("Failed to read events: %s", exc)
            return []

        if df.empty:
            return []

        df = df.sort_values("timestamp", ascending=False).head(limit)
        return df.where(pd.notna(df), None).to_dict(orient="records")

    def get_analytics(self) -> dict[str, Any]:
        if not self.events_file.exists():
            return self._empty_analytics()

        try:
            df = pd.read_csv(self.events_file)
        except Exception as exc:
            logger.error("Failed to read events for analytics: %s", exc)
            return self._empty_analytics()

        if df.empty:
            return self._empty_analytics()

        total_events = len(df)
        severity_counts = df["severity"].fillna("Unknown").value_counts().to_dict()
        attack_type_counts = df["attack_type"].fillna("Unknown").value_counts().head(10).to_dict()
        tool_counts = df["tool"].fillna("Unknown").value_counts().to_dict()

        risk_scores = df["risk_score"].dropna()
        average_risk_score = float(risk_scores.mean()) if not risk_scores.empty else 0.0

        critical_events = int((df["severity"].str.lower() == "critical").sum())
        high_events = int((df["severity"].str.lower() == "high").sum())
        medium_events = int((df["severity"].str.lower() == "medium").sum())
        low_events = int((df["severity"].str.lower() == "low").sum())

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
