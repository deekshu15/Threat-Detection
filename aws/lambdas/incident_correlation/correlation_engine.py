"""
Incident Correlation Engine

Calculates correlation scores between validated
security events.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import List

from .config import CONFIG
from .constants import (
    MAX_CORRELATION_SCORE,
    MIN_CORRELATION_SCORE,
)
from .validator import ValidatedIncidentEvent


# ==========================================================
# Result
# ==========================================================

@dataclass
class CorrelationResult:
    """
    Correlation result between two events.
    """

    event_a: str

    event_b: str

    score: float

    source_ip_match: bool

    destination_ip_match: bool

    host_match: bool

    user_match: bool

    mitre_match: bool

    risk_match: bool

    category_match: bool

    time_match: bool


# ==========================================================
# Correlation Engine
# ==========================================================

class CorrelationEngine:

    @staticmethod
    def correlate(
        event_a: ValidatedIncidentEvent,
        event_b: ValidatedIncidentEvent,
    ) -> CorrelationResult:

        score = 0.0

        # --------------------------------------
        # Source IP
        # --------------------------------------

        source_match = (
            event_a.src_ip == event_b.src_ip
        )

        if source_match:
            score += CONFIG.source_ip_weight * 100

        # --------------------------------------
        # Destination IP
        # --------------------------------------

        destination_match = (
            event_a.dest_ip == event_b.dest_ip
        )

        if destination_match:
            score += CONFIG.destination_ip_weight * 100

        # --------------------------------------
        # Host
        # --------------------------------------

        host_match = (
            event_a.host == event_b.host
        )

        if host_match:
            score += CONFIG.host_weight * 100

        # --------------------------------------
        # User
        # --------------------------------------

        user_match = (
            event_a.user == event_b.user
        )

        if user_match:
            score += CONFIG.user_weight * 100

        # --------------------------------------
        # MITRE
        # --------------------------------------

        mitre_match = (
            event_a.mitre_technique_id ==
            event_b.mitre_technique_id
        )

        if mitre_match:
            score += CONFIG.mitre_weight * 100

        # --------------------------------------
        # Risk Level
        # --------------------------------------

        risk_match = (
            event_a.risk_level ==
            event_b.risk_level
        )

        if risk_match:
            score += CONFIG.risk_level_weight * 100

        # --------------------------------------
        # Event Category
        # --------------------------------------

        category_match = (
            event_a.event_category ==
            event_b.event_category
        )

        if category_match:
            score += CONFIG.event_category_weight * 100

        # --------------------------------------
        # Time Window
        # --------------------------------------

        time_match = (
            CorrelationEngine._within_window(
                event_a.timestamp,
                event_b.timestamp,
            )
        )

        if time_match:
            score += CONFIG.time_weight * 100

        score = CorrelationEngine._normalize(score)

        return CorrelationResult(

            event_a=event_a.event_id,

            event_b=event_b.event_id,

            score=round(score, 2),

            source_ip_match=source_match,

            destination_ip_match=destination_match,

            host_match=host_match,

            user_match=user_match,

            mitre_match=mitre_match,

            risk_match=risk_match,

            category_match=category_match,

            time_match=time_match,
        )

    # --------------------------------------------------

    @staticmethod
    def correlate_events(
        events: List[ValidatedIncidentEvent],
    ) -> List[CorrelationResult]:
        """
        Correlate every event with every other event.
        """

        results = []

        for i in range(len(events)):

            for j in range(i + 1, len(events)):

                results.append(

                    CorrelationEngine.correlate(

                        events[i],

                        events[j],

                    )

                )

        return results

    # --------------------------------------------------

    @staticmethod
    def _within_window(
        first: datetime,
        second: datetime,
    ) -> bool:

        delta = abs(
            (first - second).total_seconds()
        )

        return delta <= (
            CONFIG.correlation_window_minutes * 60
        )

    # --------------------------------------------------

    @staticmethod
    def _normalize(
        score: float,
    ) -> float:

        if score < MIN_CORRELATION_SCORE:
            return MIN_CORRELATION_SCORE

        if score > MAX_CORRELATION_SCORE:
            return MAX_CORRELATION_SCORE

        return score