"""
Recommendation Generator

Generates prioritized recommendations,
containment actions, recovery actions,
investigation steps, and prevention guidance
for a validated security incident.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from .config import CONFIG
from .constants import (
    BLOCK_IP,
    CATEGORY_CONTAINMENT,
    CATEGORY_ERADICATION,
    CATEGORY_INVESTIGATION,
    CATEGORY_MONITORING,
    CATEGORY_PREVENTION,
    CATEGORY_RECOVERY,
    COLLECT_FORENSICS,
    DISABLE_ACCOUNT,
    ENABLE_MONITORING,
    ESCALATE_IR,
    ISOLATE_HOST,
    NOTIFY_SOC,
    PATCH_SYSTEMS,
    REMOVE_PERSISTENCE,
    RESET_CREDENTIALS,
    REVIEW_LOGS,
    SCAN_ENDPOINTS,
    TERMINATE_PROCESS,
    UPDATE_SIGNATURES,
    VERIFY_RECOVERY,
)
from .validator import ValidatedIncident


# ==========================================================
# Models
# ==========================================================

@dataclass
class Recommendation:

    priority: str

    category: str

    action: str

    reason: str


@dataclass
class RecommendationResult:

    recommendations: List[Recommendation] = field(default_factory=list)

    containment_actions: List[str] = field(default_factory=list)

    eradication_actions: List[str] = field(default_factory=list)

    recovery_actions: List[str] = field(default_factory=list)

    investigation_steps: List[str] = field(default_factory=list)

    prevention_recommendations: List[str] = field(default_factory=list)


# ==========================================================
# Generator
# ==========================================================

class RecommendationGenerator:

    def generate(
        self,
        incident: ValidatedIncident,
    ) -> RecommendationResult:

        result = RecommendationResult()

        self._containment(
            incident,
            result,
        )

        self._eradication(
            incident,
            result,
        )

        self._recovery(
            incident,
            result,
        )

        self._investigation(
            incident,
            result,
        )

        self._prevention(
            incident,
            result,
        )

        result.recommendations.sort(
            key=self._priority_order
        )

        result.recommendations = result.recommendations[
            :CONFIG.max_recommendations
        ]

        return result

    # --------------------------------------------------

    def _containment(
        self,
        incident: ValidatedIncident,
        result: RecommendationResult,
    ) -> None:

        if incident.affected_hosts:

            result.containment_actions.append(
                ISOLATE_HOST
            )

            result.recommendations.append(

                Recommendation(

                    priority="Critical",

                    category=CATEGORY_CONTAINMENT,

                    action=ISOLATE_HOST,

                    reason="Prevent further lateral movement.",

                )

            )

        if incident.affected_users:

            result.containment_actions.append(
                DISABLE_ACCOUNT
            )

            result.recommendations.append(

                Recommendation(

                    priority="High",

                    category=CATEGORY_CONTAINMENT,

                    action=DISABLE_ACCOUNT,

                    reason="Protect compromised accounts.",

                )

            )

        result.containment_actions.append(
            BLOCK_IP
        )

    # --------------------------------------------------

    def _eradication(
        self,
        incident: ValidatedIncident,
        result: RecommendationResult,
    ) -> None:

        result.eradication_actions.extend(

            [

                TERMINATE_PROCESS,

                REMOVE_PERSISTENCE,

                SCAN_ENDPOINTS,

            ]

        )

        result.recommendations.append(

            Recommendation(

                priority="High",

                category=CATEGORY_ERADICATION,

                action=SCAN_ENDPOINTS,

                reason="Detect remaining malware.",

            )

        )

    # --------------------------------------------------

    def _recovery(
        self,
        incident: ValidatedIncident,
        result: RecommendationResult,
    ) -> None:

        result.recovery_actions.extend(

            [

                RESET_CREDENTIALS,

                PATCH_SYSTEMS,

                VERIFY_RECOVERY,

            ]

        )

        result.recommendations.append(

            Recommendation(

                priority="Medium",

                category=CATEGORY_RECOVERY,

                action=PATCH_SYSTEMS,

                reason="Reduce future exploitation risk.",

            )

        )

    # --------------------------------------------------

    def _investigation(
        self,
        incident: ValidatedIncident,
        result: RecommendationResult,
    ) -> None:

        result.investigation_steps.extend(

            [

                REVIEW_LOGS,

                COLLECT_FORENSICS,

                NOTIFY_SOC,

                ESCALATE_IR,

            ]

        )

        result.recommendations.append(

            Recommendation(

                priority="High",

                category=CATEGORY_INVESTIGATION,

                action=COLLECT_FORENSICS,

                reason="Preserve evidence for investigation.",

            )

        )

    # --------------------------------------------------

    def _prevention(
        self,
        incident: ValidatedIncident,
        result: RecommendationResult,
    ) -> None:

        result.prevention_recommendations.extend(

            [

                ENABLE_MONITORING,

                UPDATE_SIGNATURES,

            ]

        )

        result.recommendations.append(

            Recommendation(

                priority="Low",

                category=CATEGORY_PREVENTION,

                action=ENABLE_MONITORING,

                reason="Improve detection of similar attacks.",

            )

        )

    # --------------------------------------------------

    @staticmethod
    def _priority_order(
        recommendation: Recommendation,
    ) -> int:

        order = {

            "Critical": 0,

            "High": 1,

            "Medium": 2,

            "Low": 3,

        }

        return order.get(
            recommendation.priority,
            99,
        )


# ==========================================================
# Public Helper
# ==========================================================

def generate_recommendations(
    incident: ValidatedIncident,
) -> RecommendationResult:
    """
    Generate prioritized recommendations for
    a validated security incident.
    """

    generator = RecommendationGenerator()

    return generator.generate(
        incident
    )