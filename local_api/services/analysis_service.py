"""
Threat Analysis Service

Central orchestration layer for the AI Threat Detection Dashboard.
"""

from pathlib import Path

from aws.lambdas.feature_engineering.feature_pipeline import process_event
from aws.lambdas.ml_engine.predictor import predict
try:
    from aws.lambdas.threat_enrichment_old.enrichment import ThreatEnrichmentPipeline
except Exception:
    try:
        # Try the deployed pipeline instance (may import heavy deps).
        from aws.lambdas.threat_enrichment.lambda_function import PIPELINE as ThreatEnrichmentPipeline  # type: ignore
    except Exception:
        # Last-resort: provide a lightweight no-op pipeline for local development.
        ThreatEnrichmentPipeline = None


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

        # If we failed to import a usable enrichment pipeline, use a no-op
        # pipeline that returns the event unchanged (allows local testing).
        if ThreatEnrichmentPipeline is None:
            class _NoopEnrichment:
                def enrich(self, event):
                    return event

            self.enrichment = _NoopEnrichment()
            return

        # Otherwise instantiate or assign the real pipeline.
        try:
            self.enrichment = ThreatEnrichmentPipeline(
                cve_dataset_path=str(cve_dataset),
                ioc_feed_path=str(ioc_feed),
            )
        except Exception:
            # If it's an already-initialized pipeline instance, assign directly.
            self.enrichment = ThreatEnrichmentPipeline

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