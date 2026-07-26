"""
Root Cause Analyzer

Analyzes a validated incident to determine the
most probable attack origin, attack progression,
impacted assets, and likely root cause.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .validator import ValidatedIncident


# ==========================================================
# Result
# ==========================================================

@dataclass
class RootCauseResult:

    probable_root_cause: str

    attack_origin: str

    attack_progression: List[str]

    impacted_assets: List[str]

    impacted_users: List[str]

    mitre_analysis: List[str]

    confidence_reasoning: str

    overall_assessment: str


# ==========================================================
# Root Cause Analyzer
# ==========================================================

class RootCauseAnalyzer:

    def analyze(
        self,
        incident: ValidatedIncident,
    ) -> RootCauseResult:

        return RootCauseResult(

            probable_root_cause=self._determine_root_cause(
                incident
            ),

            attack_origin=self._determine_attack_origin(
                incident
            ),

            attack_progression=self._build_attack_progression(
                incident
            ),

            impacted_assets=self._build_impacted_assets(
                incident
            ),

            impacted_users=self._build_impacted_users(
                incident
            ),

            mitre_analysis=self._build_mitre_analysis(
                incident
            ),

            confidence_reasoning=self._confidence_reasoning(
                incident
            ),

            overall_assessment=self._overall_assessment(
                incident
            ),

        )

    # ------------------------------------------------------

    @staticmethod
    def _determine_root_cause(
        incident: ValidatedIncident,
    ) -> str:

        tactics = set(incident.mitre_tactics)

        if "Initial Access" in tactics:
            return (
                "Evidence indicates the attack likely "
                "began through an initial access event."
            )

        if "Credential Access" in tactics:
            return (
                "The incident appears to originate from "
                "credential compromise or credential theft."
            )

        if "Execution" in tactics:
            return (
                "Suspicious code execution appears to be "
                "the earliest identified activity."
            )

        if "Persistence" in tactics:
            return (
                "Persistence mechanisms indicate an "
                "attempt to maintain long-term access."
            )

        return (
            "The exact root cause could not be determined "
            "from the available evidence."
        )

    # ------------------------------------------------------

    @staticmethod
    def _determine_attack_origin(
        incident: ValidatedIncident,
    ) -> str:

        if incident.affected_hosts:

            return (
                f"Primary affected host: "
                f"{incident.affected_hosts[0]}"
            )

        return "Attack origin could not be identified."

    # ------------------------------------------------------

    @staticmethod
    def _build_attack_progression(
        incident: ValidatedIncident,
    ) -> List[str]:

        progression = []

        for tactic in incident.mitre_tactics:

            progression.append(
                f"Observed MITRE tactic: {tactic}"
            )

        if not progression:

            progression.append(
                "No attack progression available."
            )

        return progression

    # ------------------------------------------------------

    @staticmethod
    def _build_impacted_assets(
        incident: ValidatedIncident,
    ) -> List[str]:

        if incident.affected_hosts:

            return incident.affected_hosts

        return [
            "No impacted hosts identified."
        ]

    # ------------------------------------------------------

    @staticmethod
    def _build_impacted_users(
        incident: ValidatedIncident,
    ) -> List[str]:

        if incident.affected_users:

            return incident.affected_users

        return [
            "No impacted users identified."
        ]

    # ------------------------------------------------------

    @staticmethod
    def _build_mitre_analysis(
        incident: ValidatedIncident,
    ) -> List[str]:

        analysis = []

        if not incident.mitre_techniques:

            analysis.append(
                "No MITRE techniques available."
            )

            return analysis

        for tactic, technique in zip(

            incident.mitre_tactics,

            incident.mitre_techniques,

        ):

            analysis.append(

                f"{tactic} -> {technique}"

            )

        return analysis

    # ------------------------------------------------------

    @staticmethod
    def _confidence_reasoning(
        incident: ValidatedIncident,
    ) -> str:

        confidence = incident.confidence

        if confidence >= 0.90:

            return (
                "Very high confidence due to strong "
                "correlation, enrichment, and risk analysis."
            )

        if confidence >= 0.75:

            return (
                "High confidence supported by multiple "
                "correlated security events."
            )

        if confidence >= 0.50:

            return (
                "Moderate confidence. Additional "
                "investigation is recommended."
            )

        return (
            "Low confidence. Additional evidence should "
            "be collected before making conclusions."
        )

    # ------------------------------------------------------

    @staticmethod
    def _overall_assessment(
        incident: ValidatedIncident,
    ) -> str:

        score = incident.maximum_risk_score

        if score >= 90:

            return (
                "A critical multi-stage attack is likely "
                "in progress. Immediate containment and "
                "incident response are required."
            )

        if score >= 75:

            return (
                "High-risk malicious activity has been "
                "identified. Prompt investigation and "
                "containment are recommended."
            )

        if score >= 50:

            return (
                "Moderate-risk suspicious activity has "
                "been detected. Continue investigation "
                "and enhanced monitoring."
            )

        return (
            "Low-risk activity observed. Continue "
            "monitoring for additional indicators."
        )


# ==========================================================
# Public Helper
# ==========================================================

def analyze_root_cause(
    incident: ValidatedIncident,
) -> RootCauseResult:
    """
    Analyze a validated incident and determine
    its most probable root cause.
    """

    analyzer = RootCauseAnalyzer()

    return analyzer.analyze(
        incident
    )