"""
Incident Builder

Builds finalized security incidents from
validated events, correlation results,
entity graph, and attack chains.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List
from uuid import uuid4

from .constants import (
    DEFAULT_INCIDENT_OWNER,
    DEFAULT_INCIDENT_PRIORITY,
    DEFAULT_INCIDENT_STATUS,
    DEFAULT_INCIDENT_TITLE,
    DEFAULT_DESCRIPTION,
)
from .attack_chain import AttackChain
from .correlation_engine import CorrelationResult
from .graph_builder import IncidentGraph
from .validator import ValidatedIncidentEvent


# ==========================================================
# Incident Model
# ==========================================================

@dataclass
class SecurityIncident:

    incident_id: str

    title: str

    description: str

    status: str

    owner: str

    priority: str

    severity: str

    created_at: str

    updated_at: str

    total_events: int

    average_risk_score: float

    maximum_risk_score: float

    confidence: float

    affected_hosts: List[str] = field(default_factory=list)

    affected_users: List[str] = field(default_factory=list)

    mitre_tactics: List[str] = field(default_factory=list)

    mitre_techniques: List[str] = field(default_factory=list)

    event_ids: List[str] = field(default_factory=list)

    attack_chains: List[AttackChain] = field(default_factory=list)

    graph: IncidentGraph | None = None

    correlations: List[CorrelationResult] = field(default_factory=list)

    metadata: Dict = field(default_factory=dict)


# ==========================================================
# Incident Builder
# ==========================================================

class IncidentBuilder:

    def build(
        self,
        events: List[ValidatedIncidentEvent],
        correlations: List[CorrelationResult],
        graph: IncidentGraph,
        attack_chains: List[AttackChain],
    ) -> List[SecurityIncident]:

        if not events:
            return []

        now = datetime.utcnow().isoformat()

        hosts = sorted(
            {
                event.host
                for event in events
                if event.host
            }
        )

        users = sorted(
            {
                event.user
                for event in events
                if event.user
            }
        )

        tactics = sorted(
            {
                event.mitre_tactic
                for event in events
                if event.mitre_tactic
            }
        )

        techniques = sorted(
            {
                event.mitre_technique_id
                for event in events
                if event.mitre_technique_id
            }
        )

        event_ids = [
            event.event_id
            for event in events
        ]

        average_risk = round(
            sum(
                event.risk_score
                for event in events
            ) / len(events),
            2,
        )

        maximum_risk = max(
            event.risk_score
            for event in events
        )

        confidence = round(
            sum(
                event.confidence
                for event in events
            ) / len(events),
            2,
        )

        severity = self._calculate_severity(
            maximum_risk
        )

        incident = SecurityIncident(

            incident_id=f"INC-{uuid4().hex[:8].upper()}",

            title=DEFAULT_INCIDENT_TITLE,

            description=DEFAULT_DESCRIPTION,

            status=DEFAULT_INCIDENT_STATUS,

            owner=DEFAULT_INCIDENT_OWNER,

            priority=self._calculate_priority(
                maximum_risk
            ),

            severity=severity,

            created_at=now,

            updated_at=now,

            total_events=len(events),

            average_risk_score=average_risk,

            maximum_risk_score=maximum_risk,

            confidence=confidence,

            affected_hosts=hosts,

            affected_users=users,

            mitre_tactics=tactics,

            mitre_techniques=techniques,

            event_ids=event_ids,

            attack_chains=attack_chains,

            graph=graph,

            correlations=correlations,

            metadata={

                "graph_nodes": len(graph.nodes),

                "graph_edges": len(graph.edges),

                "attack_chains": len(attack_chains),

                "correlations": len(correlations),

            },
        )

        return [incident]

    # ------------------------------------------------------

    @staticmethod
    def _calculate_priority(
        score: float,
    ) -> str:

        if score >= 90:
            return "P1"

        if score >= 75:
            return "P2"

        if score >= 50:
            return "P3"

        return DEFAULT_INCIDENT_PRIORITY

    # ------------------------------------------------------

    @staticmethod
    def _calculate_severity(
        score: float,
    ) -> str:

        if score >= 90:
            return "Critical"

        if score >= 75:
            return "High"

        if score >= 50:
            return "Medium"

        return "Low"


# ==========================================================
# Public Helper
# ==========================================================

def build_incidents(
    events: List[ValidatedIncidentEvent],
    correlations: List[CorrelationResult],
    graph: IncidentGraph,
    attack_chains: List[AttackChain],
) -> List[SecurityIncident]:
    """
    Build finalized incidents.
    """

    builder = IncidentBuilder()

    return builder.build(

        events,

        correlations,

        graph,

        attack_chains,

    )