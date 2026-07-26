"""
Attack Chain Builder

Constructs attack chains from correlated
security events using the MITRE ATT&CK
tactics observed in the event stream.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set

from .graph_builder import IncidentGraph
from .validator import ValidatedIncidentEvent


# ==========================================================
# MITRE ATT&CK Order
# ==========================================================

TACTIC_ORDER = {

    "Reconnaissance": 1,

    "Resource Development": 2,

    "Initial Access": 3,

    "Execution": 4,

    "Persistence": 5,

    "Privilege Escalation": 6,

    "Defense Evasion": 7,

    "Credential Access": 8,

    "Discovery": 9,

    "Lateral Movement": 10,

    "Collection": 11,

    "Command and Control": 12,

    "Exfiltration": 13,

    "Impact": 14,
}


# ==========================================================
# Models
# ==========================================================

@dataclass
class AttackStep:

    event_id: str

    tactic: str

    technique: str

    host: str

    user: str

    timestamp: str

    risk_level: str

    risk_score: float


@dataclass
class AttackChain:

    chain_id: str

    steps: List[AttackStep] = field(default_factory=list)

    hosts: Set[str] = field(default_factory=set)

    users: Set[str] = field(default_factory=set)

    techniques: Set[str] = field(default_factory=set)

    average_risk: float = 0.0

    max_risk: float = 0.0


# ==========================================================
# Builder
# ==========================================================

class AttackChainBuilder:

    def build(

        self,

        events: List[ValidatedIncidentEvent],

        graph: IncidentGraph,

    ) -> List[AttackChain]:

        if not events:

            return []

        ordered = sorted(

            events,

            key=lambda e: (

                TACTIC_ORDER.get(
                    e.mitre_tactic,
                    999,
                ),

                e.timestamp,
            ),
        )

        chain = AttackChain(
            chain_id="CHAIN-0001"
        )

        total = 0.0

        maximum = 0.0

        for event in ordered:

            step = AttackStep(

                event_id=event.event_id,

                tactic=event.mitre_tactic,

                technique=event.mitre_technique_id,

                host=event.host,

                user=event.user,

                timestamp=event.timestamp.isoformat(),

                risk_level=event.risk_level,

                risk_score=event.risk_score,

            )

            chain.steps.append(step)

            chain.hosts.add(event.host)

            chain.users.add(event.user)

            chain.techniques.add(
                event.mitre_technique_id
            )

            total += event.risk_score

            maximum = max(
                maximum,
                event.risk_score,
            )

        if chain.steps:

            chain.average_risk = round(

                total / len(chain.steps),

                2,

            )

            chain.max_risk = round(

                maximum,

                2,

            )

        return [chain]

    # --------------------------------------------------

    @staticmethod
    def summarize(
        chains: List[AttackChain],
    ) -> Dict:

        if not chains:

            return {

                "chains": 0,

                "steps": 0,

                "hosts": 0,

                "users": 0,

                "techniques": 0,

            }

        return {

            "chains": len(chains),

            "steps": sum(

                len(c.steps)

                for c in chains

            ),

            "hosts": len(

                {

                    h

                    for c in chains

                    for h in c.hosts

                }

            ),

            "users": len(

                {

                    u

                    for c in chains

                    for u in c.users

                }

            ),

            "techniques": len(

                {

                    t

                    for c in chains

                    for t in c.techniques

                }

            ),

        }


# ==========================================================
# Public Helper
# ==========================================================

def build_attack_chains(

    events: List[ValidatedIncidentEvent],

    graph: IncidentGraph,

) -> List[AttackChain]:

    """
    Build attack chains from correlated events.
    """

    builder = AttackChainBuilder()

    return builder.build(

        events,

        graph,

    )