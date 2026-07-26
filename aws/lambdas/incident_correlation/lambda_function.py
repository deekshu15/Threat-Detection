"""
Incident Correlation Lambda

Pipeline:

Validated Events
        │
Correlation Engine
        │
Graph Builder
        │
Attack Chain Builder
        │
Incident Builder
        │
Return Incident JSON
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Any, Dict, List

from .attack_chain import build_attack_chains
from .config import CONFIG
from .constants import (
    ENGINE_NAME,
    ENGINE_VERSION,
)
from .correlation_engine import (
    correlate_events,
)
from .graph_builder import build_graph
from .incident_builder import build_incidents
from .validator import validate_event


# ==========================================================
# Incident Correlation Engine
# ==========================================================

class IncidentCorrelationEngine:

    def process(
        self,
        events: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Execute the complete incident
        correlation pipeline.
        """

        # ------------------------------------------
        # Validate Events
        # ------------------------------------------

        validated_events = [

            validate_event(event)

            for event in events

        ]

        # ------------------------------------------
        # Correlate Events
        # ------------------------------------------

        correlation_results = correlate_events(
            validated_events
        )

        # ------------------------------------------
        # Build Graph
        # ------------------------------------------

        graph = build_graph(
            validated_events,
            correlation_results,
        )

        # ------------------------------------------
        # Build Attack Chains
        # ------------------------------------------

        attack_chains = build_attack_chains(
            validated_events,
            graph,
        )

        # ------------------------------------------
        # Build Incidents
        # ------------------------------------------

        incidents = build_incidents(

            validated_events,

            correlation_results,

            graph,

            attack_chains,

        )

        # ------------------------------------------
        # Statistics
        # ------------------------------------------

        statistics = {

            "validated_events": len(
                validated_events
            ),

            "correlations": len(
                correlation_results
            ),

            "graph_nodes": len(
                graph.nodes
            ),

            "graph_edges": len(
                graph.edges
            ),

            "attack_chains": len(
                attack_chains
            ),

            "incidents": len(
                incidents
            ),

        }

        # ------------------------------------------
        # Response
        # ------------------------------------------

        return {

            "success": True,

            "engine": ENGINE_NAME,

            "version": ENGINE_VERSION,

            "processed_at": datetime.utcnow().isoformat(),

            "configuration": {

                "correlation_window_minutes":
                    CONFIG.correlation_window_minutes,

                "graph_enabled":
                    CONFIG.enable_graph,

                "attack_chain_enabled":
                    CONFIG.enable_attack_chain,

            },

            "statistics": statistics,

            "incidents": [

                asdict(incident)

                for incident in incidents

            ],

        }


# ==========================================================
# Lambda Handler
# ==========================================================

def lambda_handler(
    event: Dict[str, Any],
    context: Any = None,
) -> Dict[str, Any]:
    """
    AWS Lambda entry point.
    """

    try:

        events = event.get(
            "events",
            [],
        )

        if not isinstance(events, list):

            raise ValueError(
                "'events' must be a list."
            )

        engine = IncidentCorrelationEngine()

        return engine.process(events)

    except Exception as exc:

        return {

            "success": False,

            "engine": ENGINE_NAME,

            "version": ENGINE_VERSION,

            "processed_at":
                datetime.utcnow().isoformat(),

            "error": str(exc),

        }


# ==========================================================
# Local Testing
# ==========================================================

if __name__ == "__main__":

    sample = {

        "events": []

    }

    result = lambda_handler(sample)

    from pprint import pprint

    pprint(result)