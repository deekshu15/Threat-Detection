"""
Threat Analysis Service

Central orchestration layer for the AI Threat Detection Dashboard.
"""

from pathlib import Path

from aws.lambdas.feature_engineering.feature_pipeline import process_event
from aws.lambdas.ml_engine.predictor import predict
from aws.lambdas.threat_enrichment_old.enrichment import ThreatEnrichmentPipeline


class AnalysisService:

    def __init__(self):

        project_root = Path(__file__).resolve().parents[2]

        cve_dataset = (
            project_root
            / "normalized_output"
            / "cve_reference.parquet"
        )

        ioc_feed = (
            project_root
            / "datasets"
            / "raw"
            / "threat_feeds"
        )

        self.enrichment = ThreatEnrichmentPipeline(
            cve_dataset_path=str(cve_dataset),
            ioc_feed_path=str(ioc_feed),
        )

    def analyze(self, event: dict):

        # ----------------------------------------
        # Threat Enrichment
        # ----------------------------------------

        enriched_event = self.enrichment.enrich(event)

        # ----------------------------------------
        # Feature Engineering
        # ----------------------------------------

        engineered = process_event(enriched_event)

        # ----------------------------------------
        # ML Prediction
        # ----------------------------------------

        prediction = predict(
            engineered["vector"]
        )

        return {

            "prediction": prediction,

            "enriched_event": enriched_event,

            "validated_event": engineered["validated_event"],

            "features": engineered["features"],

            "vector": engineered["vector"]

        }


analysis_service = AnalysisService()