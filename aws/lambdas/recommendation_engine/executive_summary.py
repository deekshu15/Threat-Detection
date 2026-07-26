"""
Executive Summary Generator

Generates a concise business-focused summary
for executives, management, and compliance
teams based on a validated security incident.
"""

from __future__ import annotations

from dataclasses import dataclass

from .validator import ValidatedIncident


# ==========================================================
# Result
# ==========================================================

@dataclass
class ExecutiveSummaryResult:

    headline: str

    business_impact: str

    operational_risk: str

    affected_assets: str

    executive_recommendation: str

    next_steps: str


# ==========================================================
# Executive Summary Generator
# ==========================================================

class ExecutiveSummaryGenerator:

    def generate(
        self,
        incident: ValidatedIncident,
    ) -> ExecutiveSummaryResult:

        return ExecutiveSummaryResult(

            headline=self._headline(
                incident
            ),

            business_impact=self._business_impact(
                incident
            ),

            operational_risk=self._operational_risk(
                incident
            ),

            affected_assets=self._affected_assets(
                incident
            ),

            executive_recommendation=self._recommendation(
                incident
            ),

            next_steps=self._next_steps(
                incident
            ),

        )

    # ------------------------------------------------------

    @staticmethod
    def _headline(
        incident: ValidatedIncident,
    ) -> str:

        return (

            f"{incident.severity} Security Incident "

            f"Detected"

        )

    # ------------------------------------------------------

    @staticmethod
    def _business_impact(
        incident: ValidatedIncident,
    ) -> str:

        hosts = len(
            incident.affected_hosts
        )

        users = len(
            incident.affected_users
        )

        events = incident.total_events

        if incident.maximum_risk_score >= 90:

            return (

                f"The organization is experiencing a "

                f"critical cybersecurity incident involving "

                f"{events} correlated security events "

                f"impacting {hosts} system(s) and "

                f"{users} user account(s). Immediate "

                f"response is required to minimize "

                f"business disruption."

            )

        if incident.maximum_risk_score >= 75:

            return (

                f"A high-risk security incident has been "

                f"identified affecting {hosts} system(s) "

                f"and {users} account(s). Rapid response "

                f"is recommended to reduce operational "

                f"impact."

            )

        if incident.maximum_risk_score >= 50:

            return (

                "Moderate-risk suspicious activity has "

                "been detected. Business operations are "

                "currently stable but require monitoring."

            )

        return (

            "Limited business impact is currently "

            "expected. Continue monitoring for any "

            "escalation."

        )

    # ------------------------------------------------------

    @staticmethod
    def _operational_risk(
        incident: ValidatedIncident,
    ) -> str:

        score = incident.maximum_risk_score

        if score >= 90:

            return (

                "Critical operational risk with potential "

                "service disruption, data compromise, or "

                "regulatory exposure."

            )

        if score >= 75:

            return (

                "High operational risk requiring rapid "

                "incident response."

            )

        if score >= 50:

            return (

                "Moderate operational risk with limited "

                "business disruption."

            )

        return (

            "Low operational risk."

        )

    # ------------------------------------------------------

    @staticmethod
    def _affected_assets(
        incident: ValidatedIncident,
    ) -> str:

        hosts = len(
            incident.affected_hosts
        )

        users = len(
            incident.affected_users
        )

        techniques = len(
            incident.mitre_techniques
        )

        return (

            f"{hosts} host(s), "

            f"{users} user account(s), "

            f"{techniques} MITRE ATT&CK "

            f"technique(s) observed."

        )

    # ------------------------------------------------------

    @staticmethod
    def _recommendation(
        incident: ValidatedIncident,
    ) -> str:

        score = incident.maximum_risk_score

        if score >= 90:

            return (

                "Authorize immediate containment, "

                "activate the Incident Response Team, "

                "and notify executive leadership."

            )

        if score >= 75:

            return (

                "Prioritize investigation and containment "

                "while monitoring critical systems."

            )

        if score >= 50:

            return (

                "Continue investigation and monitor "

                "affected assets."

            )

        return (

            "Maintain monitoring and verify that no "

            "additional suspicious activity occurs."

        )

    # ------------------------------------------------------

    @staticmethod
    def _next_steps(
        incident: ValidatedIncident,
    ) -> str:

        if incident.maximum_risk_score >= 90:

            return (

                "Immediate containment, forensic "

                "investigation, executive reporting, and "

                "continuous monitoring."

            )

        if incident.maximum_risk_score >= 75:

            return (

                "Complete incident investigation, "

                "contain affected systems, and review "

                "security controls."

            )

        if incident.maximum_risk_score >= 50:

            return (

                "Continue monitoring, perform log "

                "analysis, and verify endpoint health."

            )

        return (

            "Maintain normal monitoring procedures."

        )


# ==========================================================
# Public Helper
# ==========================================================

def generate_executive_summary(
    incident: ValidatedIncident,
) -> ExecutiveSummaryResult:
    """
    Generate an executive-level summary
    for a validated security incident.
    """

    generator = ExecutiveSummaryGenerator()

    return generator.generate(
        incident
    )