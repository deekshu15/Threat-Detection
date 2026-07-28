"""
MITRE ATT&CK Enrichment Engine

Enriches validated security events with MITRE ATT&CK
metadata for downstream Risk Engine and ML Engine.

Responsibilities
----------------
- Map Technique → Tactic
- Map Technique → Attack Phase
- Map Technique → Kill Chain
- Calculate Technique Weight
- Calculate Tactic Weight
- Produce MITRE metadata

Author:
AI Threat Detection Dashboard
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------
# Result
# ---------------------------------------------------------

@dataclass(slots=True)
class MITREResult:

    technique_id: Optional[str] = None

    tactic: Optional[str] = None

    attack_phase: Optional[str] = None

    kill_chain_phase: Optional[str] = None

    technique_name: Optional[str] = None

    tactic_weight: int = 0

    technique_weight: int = 0

    confidence: float = 1.0

    metadata: Optional[dict] = None


# ---------------------------------------------------------
# ATT&CK Mapping
# ---------------------------------------------------------

MITRE_MAPPING = {

    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "phase": "Credential Access",
        "kill_chain": "Credential Access",
        "weight": 95,
    },

    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "phase": "Execution",
        "kill_chain": "Execution",
        "weight": 90,
    },

    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "phase": "Initial Access",
        "kill_chain": "Delivery",
        "weight": 90,
    },

    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Persistence",
        "phase": "Persistence",
        "kill_chain": "Persistence",
        "weight": 80,
    },

    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "phase": "Lateral Movement",
        "kill_chain": "Lateral Movement",
        "weight": 85,
    },

    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "phase": "Exfiltration",
        "kill_chain": "Exfiltration",
        "weight": 100,
    },

    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "phase": "Impact",
        "kill_chain": "Actions on Objectives",
        "weight": 100,
    },

    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "phase": "Initial Access",
        "kill_chain": "Exploitation",
        "weight": 95,
    },
}


TACTIC_WEIGHTS = {

    "Reconnaissance": 25,

    "Resource Development": 35,

    "Initial Access": 90,

    "Execution": 85,

    "Persistence": 80,

    "Privilege Escalation": 90,

    "Defense Evasion": 85,

    "Credential Access": 95,

    "Discovery": 65,

    "Lateral Movement": 90,

    "Collection": 70,

    "Command and Control": 95,

    "Exfiltration": 100,

    "Impact": 100,
}


# ---------------------------------------------------------
# Engine
# ---------------------------------------------------------

class MITREEnrichment:

    """
    Enrich security events with MITRE ATT&CK metadata.
    """

    def enrich(
        self,
        technique_id: Optional[str],
    ) -> MITREResult:

        if not technique_id:

            return MITREResult()

        technique = (
            str(technique_id)
            .upper()
            .strip()
        )

        if technique not in MITRE_MAPPING:

            logger.warning(
                "Unknown MITRE Technique %s",
                technique,
            )

            return MITREResult(
                technique_id=technique,
                confidence=0.2,
            )

        data = MITRE_MAPPING[technique]

        tactic = data["tactic"]

        return MITREResult(

            technique_id=technique,

            technique_name=data["name"],

            tactic=tactic,

            attack_phase=data["phase"],

            kill_chain_phase=data["kill_chain"],

            technique_weight=data["weight"],

            tactic_weight=TACTIC_WEIGHTS.get(
                tactic,
                50,
            ),

            confidence=1.0,

            metadata={
                "framework": "MITRE ATT&CK",
                "version": "Enterprise",
            },
        )
            # -----------------------------------------------------
    # Event Enrichment
    # -----------------------------------------------------

    def enrich_event(
        self,
        event: Dict,
    ) -> MITREResult:
        """
        Enrich an entire security event.

        Priority:

        1. Existing MITRE Technique
        2. Infer from event category/action
        """

        technique = event.get(
            "mitre_technique_id"
        )

        if technique:
            return self.enrich(
                technique
            )

        category = str(
            event.get(
                "event_category",
                "",
            )
        ).lower()

        action = str(
            event.get(
                "event_action",
                "",
            )
        ).lower()

        # -------------------------------------------------
        # Lightweight inference
        # -------------------------------------------------

        if "login" in action and "failed" in action:

            return self.enrich(
                "T1110"
            )

        if (
            "powershell" in action
            or "cmd" in action
        ):

            return self.enrich(
                "T1059"
            )

        if (
            "phishing" in category
            or "email" in category
        ):

            return self.enrich(
                "T1566"
            )

        if (
            "lateral" in category
            or "remote" in action
        ):

            return self.enrich(
                "T1021"
            )

        if (
            "ransomware" in category
            or "encrypt" in action
        ):

            return self.enrich(
                "T1486"
            )

        return MITREResult(
            confidence=0.0
        )

    # -----------------------------------------------------
    # Batch Enrichment
    # -----------------------------------------------------

    def enrich_events(
        self,
        events,
    ):

        results = []

        logger.info(

            "Running MITRE enrichment on %d events.",

            len(events)

        )

        for event in events:

            results.append(

                self.enrich_event(
                    event
                )

            )

        return results

    # -----------------------------------------------------
    # Statistics
    # -----------------------------------------------------

    def statistics(self):

        tactic_distribution = {}

        for technique in MITRE_MAPPING.values():

            tactic = technique[
                "tactic"
            ]

            tactic_distribution[
                tactic
            ] = (

                tactic_distribution.get(
                    tactic,
                    0,
                )

                + 1

            )

        return {

            "known_techniques":

                len(
                    MITRE_MAPPING
                ),

            "known_tactics":

                len(
                    TACTIC_WEIGHTS
                ),

            "tactic_distribution":

                tactic_distribution,

        }


# ---------------------------------------------------------
# Singleton
# ---------------------------------------------------------

_default_engine = MITREEnrichment()


def enrich(
    technique_id: str,
) -> MITREResult:

    return _default_engine.enrich(
        technique_id
    )


def enrich_event(
    event: Dict,
) -> MITREResult:

    return _default_engine.enrich_event(
        event
    )


def enrich_events(
    events,
):

    return _default_engine.enrich_events(
        events
    )


# ---------------------------------------------------------
# Local Testing
# ---------------------------------------------------------

if __name__ == "__main__":

    logging.basicConfig(

        level=logging.INFO,

        format="%(levelname)s - %(message)s"

    )

    sample_event = {

        "event_category":

            "Authentication",

        "event_action":

            "Login Failed",

        "mitre_technique_id":

            "T1110",

    }

    result = enrich_event(
        sample_event
    )

    print(result)

    print()

    print(

        _default_engine.statistics()

    )