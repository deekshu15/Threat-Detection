"""
ML Inference Pipeline

Flow:
Security Event
    ↓
Feature Engineering
    ↓
Predictor
    ↓
Postprocessor
    ↓
Final AI Response
"""

from __future__ import annotations

from typing import Dict

from feature_engineering.feature_pipeline import process_event
from .predictor import predict
from .postprocessor import postprocess


class MLInferencePipeline:

    def run(self, event: Dict) -> Dict:
        # Feature Engineering
        feature_result = process_event(event)

        vector = feature_result["vector"]

        # ML Prediction
        prediction = predict(vector)

        # Post Processing
        response = postprocess(prediction)

        # Attach additional information
        response["event_id"] = event.get("event_id")
        response["features"] = len(vector)

        return response


_pipeline = MLInferencePipeline()


def run_inference(event: Dict):
    return _pipeline.run(event)


if __name__ == "__main__":

    sample_event = {
        "event_id": "TEST-001",
        "timestamp": "2026-07-26T12:00:00Z",
        "src_ip": "192.168.1.10",
        "dest_ip": "10.0.0.5",
        "src_port": 52345,
        "dest_port": 80,
        "protocol": "TCP",
        "severity": "HIGH",
        "event_category": "Network Attack",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1498",
        "cvss_score": 9.8,
        "threat_score": 92,
        "asset_criticality": "HIGH",
        "ioc_match": True,
        "host_event_count": 5,
        "high_risk_event_count": 2,
        "rolling_event_count": 10,
        "failed_login_count": 0,
        "privilege_escalation_count": 0,
        "user_risk": 8,
        "host_risk": 9,
        "attack_frequency": 3,
        "anomaly_score": 0.95,
    }

    from pprint import pprint

    pprint(run_inference(sample_event))