"""
Recommendation Engine

Orchestrates the Recommendation Engine
pipeline.

Pipeline

Validated Incident
        │
        ▼
Summary Generator
        │
        ▼
Root Cause Analyzer
        │
        ▼
Recommendation Generator
        │
        ▼
Executive Summary
        │
        ▼
Unified Response
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List

from .config import CONFIG
from .constants import (
    ENGINE_NAME,
    ENGINE_VERSION,
    STATUS_FAILED,
    STATUS_SUCCESS,
)
from .executive_summary import generate_executive_summary
from .recommendation_generator import generate_recommendations
from .root_cause_analyzer import analyze_root_cause
from .summary_generator import generate_summary
from .validator import validate_incident


# ==========================================================
# Recommendation Engine
# ==========================================================

class RecommendationEngine:

    def process(
        self,
        incident: Dict[str, Any],
    ) -> Dict[str, Any]:

        validated = validate_incident(
            incident
        )

        summary = generate_summary(
            validated
        )

        root_cause = analyze_root_cause(
            validated
        )

        recommendations = generate_recommendations(
            validated
        )

        executive = generate_executive_summary(
            validated
        )

        return {

            "success": True,

            "engine": ENGINE_NAME,

            "version": ENGINE_VERSION,

            "generated_at": datetime.utcnow().isoformat(),

            "incident": {

                "incident_id": validated.incident_id,

                "severity": validated.severity,

                "priority": validated.priority,

                "confidence": validated.confidence,

                "average_risk_score":
                    validated.average_risk_score,

                "maximum_risk_score":
                    validated.maximum_risk_score,

                "total_events":
                    validated.total_events,

            },

            "summary": {

                "title":
                    summary.title,

                "short_summary":
                    summary.short_summary,

                "analyst_summary":
                    summary.analyst_summary,

                "key_findings":
                    summary.key_findings,

                "risk_overview":
                    summary.risk_overview,

            },

            "root_cause": {

                "probable_root_cause":
                    root_cause.probable_root_cause,

                "attack_origin":
                    root_cause.attack_origin,

                "attack_progression":
                    root_cause.attack_progression,

                "impacted_assets":
                    root_cause.impacted_assets,

                "impacted_users":
                    root_cause.impacted_users,

                "mitre_analysis":
                    root_cause.mitre_analysis,

                "confidence_reasoning":
                    root_cause.confidence_reasoning,

                "overall_assessment":
                    root_cause.overall_assessment,

            },

            "recommendations": {

                "prioritized": [

                    {

                        "priority":
                            r.priority,

                        "category":
                            r.category,

                        "action":
                            r.action,

                        "reason":
                            r.reason,

                    }

                    for r in
                    recommendations.recommendations

                ],

                "containment":
                    recommendations.containment_actions,

                "eradication":
                    recommendations.eradication_actions,

                "recovery":
                    recommendations.recovery_actions,

                "investigation":
                    recommendations.investigation_steps,

                "prevention":
                    recommendations.prevention_recommendations,

            },

            "executive_summary": {

                "headline":
                    executive.headline,

                "business_impact":
                    executive.business_impact,

                "operational_risk":
                    executive.operational_risk,

                "affected_assets":
                    executive.affected_assets,

                "executive_recommendation":
                    executive.executive_recommendation,

                "next_steps":
                    executive.next_steps,

            },

            "configuration": {

                "max_recommendations":
                    CONFIG.max_recommendations,

                "summary_enabled":
                    CONFIG.enable_summary,

                "root_cause_enabled":
                    CONFIG.enable_root_cause,

                "recommendations_enabled":
                    CONFIG.enable_recommendations,

                "executive_summary_enabled":
                    CONFIG.enable_executive_summary,

            }

        }


# ==========================================================
# Lambda Handler
# ==========================================================

ENGINE = RecommendationEngine()


def lambda_handler(
    event: Dict[str, Any],
    context: Any,
) -> Dict[str, Any]:

    try:

        incident = event.get(
            "incident",
            event,
        )

        result = ENGINE.process(
            incident
        )

        return {

            "statusCode": 200,

            "body": json.dumps(

                {

                    "status":
                        STATUS_SUCCESS,

                    "data":
                        result,

                },

                default=str,

            ),

        }

    except Exception as exc:

        return {

            "statusCode": 500,

            "body": json.dumps(

                {

                    "status":
                        STATUS_FAILED,

                    "error":
                        str(exc),

                }

            ),

        }


# ==========================================================
# Local Testing
# ==========================================================

if __name__ == "__main__":

    sample_incident = {

        "incident_id": "INC-1001",

        "title": "Credential Attack",

        "description": "Multiple authentication failures followed by successful login.",

        "severity": "Critical",

        "priority": "P1",

        "status": "Open",

        "confidence": 0.94,

        "average_risk_score": 88,

        "maximum_risk_score": 97,

        "total_events": 18,

        "affected_hosts": [

            "SERVER-01",

            "SERVER-02",

        ],

        "affected_users": [

            "administrator",

        ],

        "mitre_tactics": [

            "Initial Access",

            "Credential Access",

            "Persistence",

        ],

        "mitre_techniques": [

            "T1078",

            "T1110",

            "T1053",

        ],

        "event_ids": [

            "E1",

            "E2",

            "E3",

        ],

        "attack_chains": [],

        "graph": {},

        "correlations": [],

    }

    response = ENGINE.process(
        sample_incident
    )

    print(

        json.dumps(

            response,

            indent=4,

            default=str,

        )

    )