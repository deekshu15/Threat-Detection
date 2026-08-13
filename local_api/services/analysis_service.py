"""
Threat Analysis Service

Central orchestration layer for the AI Threat Detection Dashboard.
"""

from aws.lambdas.feature_engineering.feature_pipeline import process_event
from aws.lambdas.ml_engine.predictor import predict

try:
    # The deployed pipeline instance (may import heavy deps).
    from aws.lambdas.threat_enrichment.lambda_function import PIPELINE as ThreatEnrichmentPipeline  # type: ignore
except Exception:
    # Last-resort: provide a lightweight no-op pipeline for local development.
    ThreatEnrichmentPipeline = None


class AnalysisService:

    def __init__(self):

        # If we failed to import a usable enrichment pipeline, use a no-op
        # pipeline that returns the event unchanged (allows local testing).
        if ThreatEnrichmentPipeline is None:
            class _NoopEnrichment:
                def enrich(self, event):
                    return event

            self.enrichment = _NoopEnrichment()
            return

        # The pipeline is already an initialized EnrichmentPipeline instance.
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