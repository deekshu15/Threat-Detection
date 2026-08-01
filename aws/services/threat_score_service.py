"""
Enterprise Threat Score Service

Combines all enrichment services into a unified,
explainable threat score.

Features
--------
• IOC Intelligence
• CVE Risk
• MITRE ATT&CK Risk
• Asset Criticality
• Behavioral Risk
• Explainable Scoring
• Confidence
• Threat Assessment

Python 3.11+
"""

from __future__ import annotations

import asyncio

from datetime import UTC
from datetime import datetime
from threading import Lock
from typing import Any

from ..lambdas.threat_enrichment.config import THREAT_SCORE

from ..lambdas.threat_enrichment.logger import get_logger

from ..models.score import (

    ScoreComponent,

    ThreatAssessment,

    ThreatScore,

    RiskLevel,

)

from .base_service import BaseService


class ThreatScoreService(BaseService):

    service_name = "ThreatScoreService"

    ####################################################################
    # Initialization
    ####################################################################

    def __init__(

        self,

        ioc_service,

        cve_service,

        mitre_service,

        asset_service,

        behavior_service,

    ):

        super().__init__()

        self.logger = get_logger(
            "ThreatScoreService"
        )

        self.lock = Lock()

        ###############################################################
        # Dependencies
        ###############################################################

        self.ioc = ioc_service

        self.cve = cve_service

        self.mitre = mitre_service

        self.asset = asset_service

        self.behavior = behavior_service

        ###############################################################
        # Cache
        ###############################################################

        self.lookup_cache = {}

        ###############################################################
        # Metadata
        ###############################################################

        self.loaded_at = datetime.now(
            UTC
        )

        ###############################################################
        # Statistics
        ###############################################################

        self.stats_data = {

            "scores": 0,

            "lookups": 0,

            "hits": 0,

            "misses": 0,

        }

    ####################################################################
    # Initialize
    ####################################################################

    def initialize(self):

        super().initialize()

        self.loaded_at = datetime.now(
            UTC
        )
        ####################################################################
    # IOC Component
    ####################################################################

    def ioc_component(
        self,
        event,
    ) -> ScoreComponent:

        score = 0.0

        matches = getattr(
            event,
            "iocs",
            [],
        )

        if matches:

            score = min(

                len(matches) * 2.5,

                10.0,

            )

        return ScoreComponent(

            name="IOC",

            score=score,

            weight=THREAT_SCORE.ioc_weight,

            details=f"{len(matches)} IOC matches",

        )
        ####################################################################
    # CVE Component
    ####################################################################

    def cve_component(
        self,
        event,
    ) -> ScoreComponent:

        cves = getattr(
            event,
            "cves",
            [],
        )

        if not cves:

            score = 0.0

        else:

            score = max(

                cve.cvss.base_score

                for cve in cves

            )

        return ScoreComponent(

            name="CVE",

            score=score,

            weight=THREAT_SCORE.cve_weight,

            details=f"{len(cves)} CVEs",

        )
        ####################################################################
    # MITRE Component
    ####################################################################

    def mitre_component(
        self,
        event,
    ) -> ScoreComponent:

        mappings = getattr(
            event,
            "mitre",
            [],
        )

        score = min(

            len(mappings) * 1.5,

            10.0,

        )

        return ScoreComponent(

            name="MITRE",

            score=score,

            weight=THREAT_SCORE.mitre_weight,

            details=f"{len(mappings)} ATT&CK techniques",

        )
        ####################################################################
    # Asset Component
    ####################################################################

    def asset_component(
        self,
        event,
    ) -> ScoreComponent:

        score = 0.0

        asset = getattr(
            event,
            "asset",
            None,
        )

        if asset:

            score = self.asset.business_score(
                asset
            )

        return ScoreComponent(

            name="Asset",

            score=score,

            weight=THREAT_SCORE.asset_weight,

            details="Business criticality",

        )
        ####################################################################
    # Behavior Component
    ####################################################################

    def behavior_component(
        self,
        event,
    ) -> ScoreComponent:

        score = self.behavior.behavioral_risk(
            event
        )

        return ScoreComponent(

            name="Behavior",

            score=score,

            weight=THREAT_SCORE.behavior_weight,

            details="Behavior analytics",

        )
        ####################################################################
    # Score Components
    ####################################################################

    def collect_components(
        self,
        event,
    ) -> list[ScoreComponent]:

        return [

            self.ioc_component(event),

            self.cve_component(event),

            self.mitre_component(event),

            self.asset_component(event),

            self.behavior_component(event),

        ]

    ####################################################################
    # Weighted Score
    ####################################################################

    def weighted_score(
        self,
        components: list[ScoreComponent],
    ) -> float:

        total = 0.0

        weight_sum = 0.0

        for component in components:

            total += (
                component.score
                * component.weight
            )

            weight_sum += component.weight

        if weight_sum == 0:

            return 0.0

        return round(

            total / weight_sum,

            2,

        )

    ####################################################################
    # Normalize Score
    ####################################################################

    def normalize_score(
        self,
        score: float,
    ) -> float:

        return round(

            max(

                0.0,

                min(score, 10.0),

            ),

            2,

        )

    ####################################################################
    # Risk Level
    ####################################################################

    def risk_level(
        self,
        score: float,
    ) -> RiskLevel:

        if score >= 9.0:

            return RiskLevel.CRITICAL

        if score >= 7.0:

            return RiskLevel.HIGH

        if score >= 4.0:

            return RiskLevel.MEDIUM

        if score >= 2.0:

            return RiskLevel.LOW

        return RiskLevel.INFORMATIONAL

    ####################################################################
    # Confidence
    ####################################################################

    def confidence(
        self,
        components: list[ScoreComponent],
    ) -> float:

        populated = sum(

            1

            for component in components

            if component.score > 0

        )

        return round(

            populated

            / len(components)

            * 100,

            2,

        )

    ####################################################################
    # Rank Components
    ####################################################################

    def rank_components(
        self,
        components: list[ScoreComponent],
    ) -> list[ScoreComponent]:

        return sorted(

            components,

            key=lambda c: c.score,

            reverse=True,

        )

    ####################################################################
    # Explanation
    ####################################################################

    def explanation(
        self,
        components: list[ScoreComponent],
    ) -> list[str]:

        ranked = self.rank_components(
            components
        )

        return [

            f"{component.name}: "
            f"{component.score:.2f}/10 "
            f"({component.details})"

            for component in ranked

        ]

    ####################################################################
    # Build Threat Score
    ####################################################################

    def build_score(
        self,
        event,
    ) -> ThreatScore:

        components = self.collect_components(
            event
        )

        score = self.normalize_score(

            self.weighted_score(
                components
            )

        )

        confidence = self.confidence(
            components
        )

        return ThreatScore(

            score=score,

            level=self.risk_level(score),

            confidence=confidence,

            components=components,

        )

    ####################################################################
    # Threat Assessment
    ####################################################################

    def build_assessment(
        self,
        event,
    ) -> ThreatAssessment:

        threat_score = self.build_score(
            event
        )

        return ThreatAssessment(

            threat_score=threat_score,

            summary=self.explanation(
                threat_score.components
            ),

            generated_at=datetime.now(
                UTC
            ),

        )
        ####################################################################
    # Threat Category
    ####################################################################

    def categorize(
        self,
        event,
    ) -> str:

        if getattr(event, "iocs", None):

            return "Known Threat"

        if getattr(event, "cves", None):

            return "Vulnerability Exploitation"

        if getattr(event, "mitre", None):

            return "ATT&CK Activity"

        behavior = self.behavior.behavioral_risk(
            event
        )

        if behavior >= 7:

            return "Behavioral Anomaly"

        return "Unknown"

    ####################################################################
    # Alert Priority
    ####################################################################

    def priority(
        self,
        score: float,
    ) -> str:

        if score >= 9:

            return "P1"

        if score >= 7:

            return "P2"

        if score >= 4:

            return "P3"

        return "P4"

    ####################################################################
    # Recommendations
    ####################################################################

    def recommendations(
        self,
        event,
    ) -> list[str]:

        actions = []

        if getattr(event, "iocs", None):

            actions.append(
                "Block identified indicators of compromise."
            )

        if getattr(event, "cves", None):

            actions.append(
                "Patch vulnerable systems immediately."
            )

        if getattr(event, "mitre", None):

            actions.append(
                "Review ATT&CK techniques and associated mitigations."
            )

        behavior = self.behavior.behavioral_risk(
            event
        )

        if behavior >= 7:

            actions.append(
                "Investigate anomalous user and host behavior."
            )

        asset = getattr(
            event,
            "asset",
            None,
        )

        if asset and getattr(asset, "internet_facing", False):

            actions.append(
                "Validate exposure of the affected internet-facing asset."
            )

        if not actions:

            actions.append(
                "Continue monitoring."
            )

        return actions

    ####################################################################
    # Next Steps
    ####################################################################

    def next_steps(
        self,
        event,
    ) -> list[str]:

        return [

            "Validate the alert.",

            "Collect supporting evidence.",

            "Correlate related events.",

            "Determine business impact.",

            "Escalate if necessary.",

        ]

    ####################################################################
    # Enrich Event
    ####################################################################

    def enrich_event(
        self,
        event,
    ):

        assessment = self.build_assessment(
            event
        )

        event.threat_assessment = assessment

        event.threat_category = self.categorize(
            event
        )

        event.priority = self.priority(
            assessment.threat_score.score
        )

        event.recommendations = self.recommendations(
            event
        )

        event.next_steps = self.next_steps(
            event
        )

        return event

    ####################################################################
    # Batch Scoring
    ####################################################################

    def score_events(
        self,
        events: list,
    ) -> list:

        results = []

        for event in events:

            results.append(

                self.enrich_event(
                    event
                )

            )

        return results

    ####################################################################
    # Compare Scores
    ####################################################################

    def compare_scores(
        self,
        first,
        second,
    ) -> float:

        a = self.build_score(
            first
        ).score

        b = self.build_score(
            second
        ).score

        return round(

            a - b,

            2,

        )

    ####################################################################
    # Incident Score
    ####################################################################

    def incident_score(
        self,
        events: list,
    ) -> float:

        if not events:

            return 0.0

        scores = [

            self.build_score(
                event
            ).score

            for event in events

        ]

        return round(

            sum(scores)
            / len(scores),

            2,

        )

    ####################################################################
    # Risk Summary
    ####################################################################

    def summary(
        self,
        event,
    ) -> dict[str, Any]:

        assessment = self.build_assessment(
            event
        )

        return {

            "score":
                assessment.threat_score.score,

            "risk":
                assessment.threat_score.level.value,

            "confidence":
                assessment.threat_score.confidence,

            "priority":
                self.priority(
                    assessment.threat_score.score
                ),

            "category":
                self.categorize(
                    event
                ),

            "recommendations":
                self.recommendations(
                    event
                ),
        }
        ####################################################################
    # Statistics
    ####################################################################

    def stats(
        self,
    ) -> dict[str, Any]:

        return {

            "service":
                self.service_name,

            "scores_generated":
                self.stats_data["scores"],

            "cache":
                len(self.lookup_cache),

            "loaded_at":
                self.loaded_at.isoformat()
                if self.loaded_at
                else None,

            **self.stats_data,

        }

    ####################################################################
    # Health
    ####################################################################

    def health(
        self,
    ) -> dict[str, Any]:

        dependencies = {

            "ioc":
                self.ioc.health(),

            "cve":
                self.cve.health(),

            "mitre":
                self.mitre.health(),

            "asset":
                self.asset.health(),

            "behavior":
                self.behavior.health(),

        }

        return {

            "service":
                self.service_name,

            "status":
                "healthy",

            "dependencies":
                dependencies,

            "cache":
                len(self.lookup_cache),

            "scores":
                self.stats_data["scores"],

            "loaded_at":
                self.loaded_at.isoformat()
                if self.loaded_at
                else None,

        }

    ####################################################################
    # Diagnostics
    ####################################################################

    def diagnostics(
        self,
    ) -> dict[str, Any]:

        return {

            "ioc_cache":
                len(self.ioc.lookup_cache),

            "cve_cache":
                len(self.cve.lookup_cache),

            "mitre_cache":
                len(self.mitre.lookup_cache),

            "asset_cache":
                len(self.asset.lookup_cache),

            "behavior_cache":
                len(self.behavior.lookup_cache),

            "score_cache":
                len(self.lookup_cache),

        }

    ####################################################################
    # Clear Cache
    ####################################################################

    def clear_cache(
        self,
    ) -> None:

        self.lookup_cache.clear()

    ####################################################################
    # Refresh
    ####################################################################

    def refresh(
        self,
    ) -> None:

        self.clear_cache()

        self.loaded_at = datetime.now(
            UTC
        )

    ####################################################################
    # Async Refresh
    ####################################################################

    async def async_refresh(
        self,
    ) -> None:

        loop = asyncio.get_running_loop()

        await loop.run_in_executor(

            None,

            self.refresh,

        )

    ####################################################################
    # Process
    ####################################################################

    def process(
        self,
        event,
    ):

        self.stats_data[
            "scores"
        ] += 1

        return self.enrich_event(
            event
        )

    ####################################################################
    # Batch Process
    ####################################################################

    def process_many(
        self,
        events: list,
    ) -> list:

        results = []

        for event in events:

            results.append(
                self.process(event)
            )

        return results

    ####################################################################
    # Shutdown
    ####################################################################

    def shutdown(
        self,
    ) -> None:

        self.clear_cache()

        super().shutdown()

    ####################################################################
    # Magic Methods
    ####################################################################

    def __len__(
        self,
    ) -> int:

        return self.stats_data["scores"]

    def __repr__(
        self,
    ) -> str:

        return (

            f"<ThreatScoreService "

            f"scores={self.stats_data['scores']} "

            f"cache={len(self.lookup_cache)}>"

        )
    