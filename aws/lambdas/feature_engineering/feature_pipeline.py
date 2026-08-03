"""
Feature Engineering Pipeline

Orchestrates validation, encoding, temporal/network/flow/behavioral/
statistical feature generation, merging, and vectorization. Exposes
module helpers for batch processing and resetting stateful generators.
"""
from __future__ import annotations

from typing import Dict, List
from dataclasses import asdict

from .validator import validate_event
from .encoders import encode_event
from .temporal_features import generate_temporal_features
from .network_features import generate_network_features
from .flow_features import generate_flow_features
from .behavioral_features import generate_behavioral_features
from .statistical_features import generate_statistical_features
from .feature_selector import (
    merge_features,
    feature_vector,
    feature_dataframe,
)


class FeatureEngineeringPipeline:

    """Complete feature engineering pipeline."""

    def __init__(self) -> None:
        pass

    def process(self, event: Dict) -> Dict:
        validated = validate_event(event)

        encoded = encode_event(asdict(validated))

        temporal = generate_temporal_features(validated.timestamp)

        network = generate_network_features(
            validated.src_ip,
            validated.dest_ip,
            validated.src_port,
            validated.dest_port,
        )

        flow = generate_flow_features(event)

        behavioral = generate_behavioral_features(validated)

        statistical = generate_statistical_features(validated)

        features = merge_features(
            encoded,
            temporal,
            network,
            flow,
            behavioral,
            statistical,
        )

        vector = feature_vector(features)

        return {"validated_event": asdict(validated), "features": features, "vector": vector}

    def process_batch(self, events: List[Dict]) -> List[Dict]:
        results: List[Dict] = []

        for event in events:
            try:
                results.append(self.process(event))
            except Exception:
                # Skip invalid events
                continue

        return results

    def dataframe(self, events: List[Dict]):
        processed = self.process_batch(events)
        feature_sets = [item["features"] for item in processed]
        return feature_dataframe(feature_sets)

    def statistics(self, processed_events: List[Dict]) -> Dict:
        total = len(processed_events)
        if total == 0:
            return {"processed_events": 0, "feature_count": 0, "vector_length": 0}

        first = processed_events[0]
        return {
            "processed_events": total,
            "feature_count": len(first["features"]),
            "vector_length": len(first["vector"]),
        }

    def reset(self) -> None:
        # Reset stateful modules
        from .behavioral_features import reset_behavioral_statistics
        from .statistical_features import reset_statistics

        reset_behavioral_statistics()
        reset_statistics()


# Singleton
_pipeline = FeatureEngineeringPipeline()


def process_event(event: Dict) -> Dict:
    return _pipeline.process(event)


def process_events(events: List[Dict]) -> List[Dict]:
    return _pipeline.process_batch(events)


def generate_feature_dataframe(events: List[Dict]):
    return _pipeline.dataframe(events)


def reset_pipeline():
    """Reset stateful components in the feature pipeline (module helper)."""
    return _pipeline.reset()


if __name__ == "__main__":
    from pprint import pprint

    sample_event = {
        "event_id": "EVT-1001",
        "timestamp": "2026-07-25T10:15:30",
        "src_ip": "192.168.1.10",
        "dest_ip": "8.8.8.8",
        "protocol": "TCP",
        "severity": "UNKNOWN",
        "event_category": "Other",
        "asset_criticality": "UNKNOWN",
        "threat_score": 0,
        "src_port": 50555,
        "dest_port": 443,
        "user": "admin",
        "host": "server01",
    }

    result = process_event(sample_event)

    pprint(result)

    print("\nFeature Vector Length:", len(result["vector"]))
