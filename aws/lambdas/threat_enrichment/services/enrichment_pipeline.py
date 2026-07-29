"""
Enterprise Threat Enrichment Pipeline

Pipeline Flow

Raw Event
    │
    ▼
Validation
    │
    ▼
IOC Enrichment
    │
    ▼
CVE Enrichment
    │
    ▼
MITRE Enrichment
    │
    ▼
Asset Enrichment
    │
    ▼
Behavior Analytics
    │
    ▼
Threat Scoring
    │
    ▼
Final ThreatAssessment
"""

from __future__ import annotations

import asyncio
import time

from collections import defaultdict
from datetime import UTC
from datetime import datetime
from threading import Lock
from typing import Any

from ..logger import get_logger

from ..exceptions import PipelineExecutionError

from .base_service import BaseService


class EnrichmentPipeline(BaseService):

    service_name = "EnrichmentPipeline"

    ####################################################################
    # Initialization
    ####################################################################

    def __init__(

        self,

        validator,

        ioc_service,

        cve_service,

        mitre_service,

        asset_service,

        behavior_service,

        threat_score_service,

    ):

        super().__init__()

        self.logger = get_logger(
            "EnrichmentPipeline"
        )

        self.lock = Lock()

        ###############################################################
        # Services
        ###############################################################

        self.validator = validator

        self.ioc = ioc_service

        self.cve = cve_service

        self.mitre = mitre_service

        self.asset = asset_service

        self.behavior = behavior_service

        self.threat_score = threat_score_service

        ###############################################################
        # Metrics
        ###############################################################

        self.metrics = defaultdict(float)

        self.pipeline_runs = 0

        self.pipeline_failures = 0

        self.loaded_at = datetime.now(
            UTC
        )
        ####################################################################
    # Timer
    ####################################################################

    def _time_stage(

        self,

        stage: str,

        function,

        *args,

        **kwargs,

    ):

        start = time.perf_counter()

        result = function(

            *args,

            **kwargs,

        )

        elapsed = (

            time.perf_counter()

            - start

        ) * 1000

        self.metrics[
            stage
        ] += elapsed

        return result
    ####################################################################
    # Validation
    ####################################################################

    def validate(

        self,

        event,

    ):

        return self._time_stage(

            "validation",

            self.validator.validate,

            event,

        )
    ####################################################################
    # IOC Enrichment
    ####################################################################

    def enrich_iocs(

        self,

        event,

    ):

        return self._time_stage(

            "ioc",

            self.ioc.enrich_event,

            event,

        )
    ####################################################################
    # CVE Enrichment
    ####################################################################

    def enrich_cves(

        self,

        event,

    ):

        return self._time_stage(

            "cve",

            self.cve.enrich_event,

            event,

        )
    ####################################################################
    # MITRE Enrichment
    ####################################################################

    def enrich_mitre(

        self,

        event,

    ):

        return self._time_stage(

            "mitre",

            self.mitre.enrich_event,

            event,

        )
    ####################################################################
    # Asset Enrichment
    ####################################################################

    def enrich_asset(

        self,

        event,

    ):

        return self._time_stage(

            "asset",

            self.asset.enrich_event,

            event,

        )
    ####################################################################
    # Behavior Analytics
    ####################################################################

    def enrich_behavior(

        self,

        event,

    ):

        return self._time_stage(

            "behavior",

            self.behavior.enrich_event,

            event,

        )
    ####################################################################
    # Threat Score
    ####################################################################

    def score(

        self,

        event,

    ):

        return self._time_stage(

            "threat_score",

            self.threat_score.process,

            event,

        )
    ####################################################################
    # Execute Pipeline
    ####################################################################

    def execute(
        self,
        event,
    ):

        self.pipeline_runs += 1

        started = datetime.now(UTC)

        self.logger.info(
            "Pipeline started."
        )

        try:

            ###########################################################
            # Validation
            ###########################################################

            self.validate(event)

            ###########################################################
            # IOC
            ###########################################################

            self.enrich_iocs(event)

            ###########################################################
            # CVE
            ###########################################################

            self.enrich_cves(event)

            ###########################################################
            # MITRE
            ###########################################################

            self.enrich_mitre(event)

            ###########################################################
            # Asset
            ###########################################################

            self.enrich_asset(event)

            ###########################################################
            # Behavior
            ###########################################################

            self.enrich_behavior(event)

            ###########################################################
            # Threat Score
            ###########################################################

            self.score(event)

            ###########################################################
            # Metadata
            ###########################################################

            event.pipeline = {

                "started_at":
                    started.isoformat(),

                "completed_at":
                    datetime.now(
                        UTC
                    ).isoformat(),

                "status":
                    "completed",

            }

            self.logger.info(
                "Pipeline completed successfully."
            )

            return event

        except Exception as exc:

            self.pipeline_failures += 1

            self.logger.exception(exc)

            raise PipelineExecutionError(
                str(exc)
            ) from exc
    ####################################################################
    # Retry
    ####################################################################

    def execute_with_retry(

        self,

        event,

        retries: int = 3,

    ):

        last_exception = None

        for _ in range(retries):

            try:

                return self.execute(
                    event
                )

            except Exception as exc:

                last_exception = exc

                self.logger.warning(
                    "Retrying pipeline..."
                )

        raise last_exception
    ####################################################################
    # Batch
    ####################################################################

    def process_many(

        self,

        events: list,

    ) -> list:

        results = []

        for event in events:

            results.append(

                self.execute(
                    event
                )

            )

        return results
    ####################################################################
    # Async Batch
    ####################################################################

    async def process_many_async(

        self,

        events: list,

    ):

        tasks = [

            asyncio.to_thread(

                self.execute,

                event,

            )

            for event in events

        ]

        return await asyncio.gather(

            *tasks

        )
    ####################################################################
    # Summary
    ####################################################################

    def execution_summary(
        self,
    ) -> dict[str, Any]:

        return {

            "runs":
                self.pipeline_runs,

            "failures":
                self.pipeline_failures,

            "success":

                self.pipeline_runs
                - self.pipeline_failures,

            "metrics":

                dict(self.metrics),

        }
    ####################################################################
    # Stage Metrics
    ####################################################################

    def stage_metrics(
        self,
    ) -> dict[str, float]:

        return dict(
            self.metrics
        )
    ####################################################################
    # Reset Metrics
    ####################################################################

    def reset_metrics(
        self,
    ) -> None:

        self.metrics.clear()

        self.pipeline_runs = 0

        self.pipeline_failures = 0
        ####################################################################
    # Statistics
    ####################################################################

    def stats(
        self,
    ) -> dict[str, Any]:

        return {

            "service":
                self.service_name,

            "pipeline_runs":
                self.pipeline_runs,

            "pipeline_failures":
                self.pipeline_failures,

            "successes":
                self.pipeline_runs
                - self.pipeline_failures,

            "stage_metrics":
                dict(self.metrics),

            "loaded_at":
                self.loaded_at.isoformat()
                if self.loaded_at
                else None,

        }

    ####################################################################
    # Health
    ####################################################################

    def health(
        self,
    ) -> dict[str, Any]:

        return {

            "service":
                self.service_name,

            "status":
                "healthy",

            "validator":
                self.validator.health(),

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

            "threat_score":
                self.threat_score.health(),

        }

    ####################################################################
    # Diagnostics
    ####################################################################

    def diagnostics(
        self,
    ) -> dict[str, Any]:

        return {

            "runs":
                self.pipeline_runs,

            "failures":
                self.pipeline_failures,

            "validator":
                self.validator.stats(),

            "ioc":
                self.ioc.stats(),

            "cve":
                self.cve.stats(),

            "mitre":
                self.mitre.stats(),

            "asset":
                self.asset.stats(),

            "behavior":
                self.behavior.stats(),

            "threat_score":
                self.threat_score.stats(),

        }

    ####################################################################
    # Refresh
    ####################################################################

    def refresh(
        self,
    ) -> None:

        self.reset_metrics()

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

        return self.execute(
            event
        )

    ####################################################################
    # Process Async
    ####################################################################

    async def process_async(
        self,
        event,
    ):

        return await asyncio.to_thread(

            self.execute,

            event,

        )

    ####################################################################
    # Shutdown
    ####################################################################

    def shutdown(
        self,
    ) -> None:

        self.logger.info(
            "Shutting down enrichment pipeline..."
        )

        self.reset_metrics()

        super().shutdown()

    ####################################################################
    # Magic Methods
    ####################################################################

    def __len__(
        self,
    ) -> int:

        return self.pipeline_runs

    def __repr__(
        self,
    ) -> str:

        return (

            f"<EnrichmentPipeline "

            f"runs={self.pipeline_runs} "

            f"failures={self.pipeline_failures}>"

        )
    