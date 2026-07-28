"""
Threat Enrichment Pipeline

Orchestrates the complete threat enrichment workflow.

Pipeline
--------
Validated Event
        │
IOC Matcher
        │
CVE Lookup
        │
MITRE Enrichment
        │
Asset Context
        │
Severity Engine
        │
Threat Score Engine
        │
Fully Enriched Event

Author:
AI Threat Detection Dashboard
"""

from __future__ import annotations

import copy
import logging
from typing import Dict, List

from .asset_context import AssetContext
from .cve_lookup import CVELookup
from .ioc_matcher import IOCMatcher
from .mitre_enrichment import MITREEnrichment
from .severity import calculate_severity
from .threat_score import ThreatScoreEngine
from .validator import validate_event
from aws.lambdas.threat_enrichment_old import severity

logger = logging.getLogger(__name__)


class ThreatEnrichmentPipeline:
    """
    Production Threat Enrichment Pipeline.
    """

    def __init__(
        self,
        cve_dataset_path: str,
        ioc_feed_path: str,
    ):

        logger.info(
            "Initializing Threat Enrichment Pipeline..."
        )

        self.validator = validate_event

        self.ioc_matcher = IOCMatcher(
            ioc_feed_path
        )

        self.cve_lookup = CVELookup(
            cve_dataset_path
        )

        self.mitre = MITREEnrichment()

        self.asset = AssetContext()

        self.severity = calculate_severity

        self.threat_score = ThreatScoreEngine()

        logger.info(
            "Threat Enrichment Pipeline Ready."
        )

    # -----------------------------------------------------
    # Single Event
    # -----------------------------------------------------

    def enrich(
        self,
        event: Dict,
    ) -> Dict:

        logger.debug(
            "Enriching event..."
        )

        validated = self.validator(
            event
        )

        enriched = copy.deepcopy(
            validated.__dict__
        )
                # ---------------------------------------------
        # IOC Matching
        # ---------------------------------------------

        ioc = self.ioc_matcher.match_event(
            enriched
        )

        enriched.update({

            "matched_ioc":
                ioc.matched_ioc,

            "ioc_type":
                ioc.ioc_type,

            "ioc_value":
                ioc.ioc_value,

            "ioc_source":
                ioc.ioc_source,

            "ioc_confidence":
                ioc.ioc_confidence,

            "threat_level":
                ioc.threat_level,

        })

        # ---------------------------------------------
        # CVE Lookup
        # ---------------------------------------------

        cve = self.cve_lookup.lookup_event(
            enriched
        )

        enriched.update({

            "cve_exists":
                cve.cve_exists,

            "cve_id":
                cve.cve_id,

            "cvss_score":
                cve.cvss_score,

            "severity":
                cve.severity
                or enriched.get(
                    "severity"
                ),

            "cve_description":
                cve.description,

            "published":
                cve.published,

        })

        # ---------------------------------------------
        # MITRE
        # ---------------------------------------------

        mitre = self.mitre.enrich_event(
            enriched
        )

        enriched.update({

            "mitre_technique_id":
                mitre.technique_id,

            "mitre_tactic":
                mitre.tactic,

            "attack_phase":
                mitre.attack_phase,

            "kill_chain_phase":
                mitre.kill_chain_phase,

            "technique_name":
                mitre.technique_name,

            "technique_weight":
                mitre.technique_weight,

            "tactic_weight":
                mitre.tactic_weight,

        })
                # ---------------------------------------------
        # Asset Context
        # ---------------------------------------------
        asset = self.asset.enrich(enriched)

        enriched.update({

            "asset_type": asset.get("asset_type"),

            "asset_criticality": asset.get("asset_criticality"),

            "attack_category": asset.get("attack_category"),

        })

        # ---------------------------------------------
        # Severity Calculation
        # ---------------------------------------------

        severity = calculate_severity(enriched)

        enriched.update({

            "severity": severity["severity"],

            "severity_score": severity["severity_score"],

            "risk_weight": severity["risk_weight"],

            "known_attack": False,

        })

        # ---------------------------------------------
        # Threat Score
        # ---------------------------------------------

        threat = self.threat_score.calculate(
            enriched
        )

        enriched.update({

            "threat_score":
                threat.threat_score,

            "threat_level":
                threat.threat_level,

            "confidence":
                threat.confidence,

            "score_breakdown":
                threat.score_breakdown,

        })

        # ---------------------------------------------
        # Pipeline Metadata
        # ---------------------------------------------

        enriched["enrichment_status"] = "SUCCESS"

        enriched["pipeline_version"] = "1.0"

        return enriched

    # -----------------------------------------------------
    # Batch Enrichment
    # -----------------------------------------------------

    def enrich_events(
        self,
        events: List[Dict],
    ) -> List[Dict]:

        logger.info(

            "Enriching %d events.",

            len(events)

        )

        enriched_events = []

        for event in events:

            try:

                enriched_events.append(

                    self.enrich(
                        event
                    )

                )

            except Exception as exc:

                logger.exception(

                    "Failed to enrich event: %s",

                    exc

                )

        return enriched_events

    # -----------------------------------------------------
    # Statistics
    # -----------------------------------------------------

    def statistics(
        self,
        events: List[Dict],
    ) -> Dict:

        if not events:

            return {

                "total_events": 0,

                "average_threat_score": 0,

                "critical_events": 0,

                "high_events": 0,

                "matched_iocs": 0,

            }

        scores = [

            e.get(
                "threat_score",
                0,
            )

            for e in events

        ]

        return {

            "total_events":

                len(events),

            "average_threat_score":

                round(

                    sum(scores) / len(scores),

                    2,

                ),

            "critical_events":

                sum(

                    1

                    for e in events

                    if e.get(
                        "threat_level"
                    ) == "CRITICAL"

                ),

            "high_events":

                sum(

                    1

                    for e in events

                    if e.get(
                        "threat_level"
                    ) == "HIGH"

                ),

            "matched_iocs":

                sum(

                    1

                    for e in events

                    if e.get(
                        "matched_ioc"
                    )

                ),

        }


# ---------------------------------------------------------
# Local Testing
# ---------------------------------------------------------

if __name__ == "__main__":

    logging.basicConfig(

        level=logging.INFO,

        format="%(levelname)s - %(message)s"

    )

    pipeline = ThreatEnrichmentPipeline(

        cve_dataset_path="../../normalized_output/cve_reference.parquet",

        ioc_feed_path="../../datasets/raw/threat_feeds/"

    )

    sample_event = {

        "event_id": "1",

        "timestamp": "2026-01-01T10:00:00Z",

        "src_ip": "192.168.1.100",

        "dest_ip": "10.0.0.5",

        "event_category": "Authentication",

        "event_action": "Login Failed",

        "raw_log": "Authentication failure CVE-2025-0168"

    }

    result = pipeline.enrich(
        sample_event
    )

    print(result)

    print()

    stats = pipeline.statistics(
        [result]
    )

    print(stats)