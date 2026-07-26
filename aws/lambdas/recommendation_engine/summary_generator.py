"""
Summary Generator

Generates analyst-friendly summaries for
security incidents.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .validator import ValidatedIncident


# ==========================================================
# Result
# ==========================================================

@dataclass
class SummaryResult:

    title: str

    short_summary: str

    analyst_summary: str

    key_findings: List[str]

    risk_overview: str


# ==========================================================
# Summary Generator
# ==========================================================

class SummaryGenerator:

    def generate(
        self,
        incident: ValidatedIncident,
    ) -> SummaryResult:

        title = self._build_title(
            incident
        )

        short_summary = self._build_short_summary(
            incident
        )

        analyst_summary = self._build_analyst_summary(
            incident
        )

        findings = self._build_key_findings(
            incident
        )

        risk_overview = self._build_risk_overview(
            incident
        )

        return SummaryResult(

            title=title,

            short_summary=short_summary,

            analyst_summary=analyst_summary,

            key_findings=findings,

            risk_overview=risk_overview,

        )

    # ------------------------------------------------------

    @staticmethod
    def _build_title(
        incident: ValidatedIncident,
    ) -> str:

        return (

            f"{incident.severity} Security Incident "

            f"({incident.incident_id})"

        )

    # ------------------------------------------------------

    @staticmethod
    def _build_short_summary(
        incident: ValidatedIncident,
    ) -> str:

        return (

            f"{incident.total_events} correlated "

            f"security events were grouped into a "

            f"{incident.severity.lower()} severity incident."

        )

    # ------------------------------------------------------

    @staticmethod
    def _build_analyst_summary(
        incident: ValidatedIncident,
    ) -> str:

        hosts = len(
            incident.affected_hosts
        )

        users = len(
            incident.affected_users
        )

        tactics = ", ".join(
            incident.mitre_tactics
        ) if incident.mitre_tactics else "Unknown"

        return (

            f"The incident contains "

            f"{incident.total_events} correlated events "

            f"affecting {hosts} host(s) and "

            f"{users} user account(s). "

            f"The observed MITRE ATT&CK tactics include "

            f"{tactics}. "

            f"The highest calculated risk score is "

            f"{incident.maximum_risk_score:.2f} "

            f"with an overall confidence of "

            f"{incident.confidence:.2f}."

        )

    # ------------------------------------------------------

    @staticmethod
    def _build_key_findings(
        incident: ValidatedIncident,
    ) -> List[str]:

        findings = []

        findings.append(

            f"Incident Severity: {incident.severity}"

        )

        findings.append(

            f"Priority: {incident.priority}"

        )

        findings.append(

            f"Correlated Events: {incident.total_events}"

        )

        findings.append(

            f"Maximum Risk Score: {incident.maximum_risk_score:.2f}"

        )

        findings.append(

            f"Average Risk Score: {incident.average_risk_score:.2f}"

        )

        findings.append(

            f"Affected Hosts: {len(incident.affected_hosts)}"

        )

        findings.append(

            f"Affected Users: {len(incident.affected_users)}"

        )

        findings.append(

            f"Observed MITRE Techniques: "

            f"{len(incident.mitre_techniques)}"

        )

        findings.append(

            f"Attack Chains Identified: "

            f"{len(incident.attack_chains)}"

        )

        return findings

    # ------------------------------------------------------

    @staticmethod
    def _build_risk_overview(
        incident: ValidatedIncident,
    ) -> str:

        if incident.maximum_risk_score >= 90:

            return (

                "Critical risk detected. Immediate "

                "containment and incident response "

                "actions are recommended."

            )

        if incident.maximum_risk_score >= 75:

            return (

                "High-risk activity detected. Prompt "

                "investigation and containment should "

                "be initiated."

            )

        if incident.maximum_risk_score >= 50:

            return (

                "Medium-risk activity detected. Review "

                "the affected assets and continue "

                "monitoring."

            )

        return (

            "Low-risk activity detected. Continue "

            "monitoring and verify that no additional "

            "related events occur."

        )


# ==========================================================
# Public Helper
# ==========================================================

def generate_summary(
    incident: ValidatedIncident,
) -> SummaryResult:
    """
    Generate an analyst-friendly incident summary.
    """

    generator = SummaryGenerator()

    return generator.generate(
        incident
    )