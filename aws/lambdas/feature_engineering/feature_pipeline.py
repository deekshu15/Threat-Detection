"""
Feature Engineering Pipeline

Complete orchestration pipeline for
feature generation.

Pipeline

Validated Event
      │
      ▼
Encoding
      │
      ▼
Temporal Features
      │
      ▼
Network Features
      │
      ▼
Behavioral Features
      │
      ▼
Statistical Features
      │
      ▼
Merge Features
      │
      ▼
Feature Selection
      │
      ▼
ML Feature Vector

Author:
AI Threat Detection Dashboard
"""

from __future__ import annotations

from typing import Dict, List
from dataclasses import asdict

from .validator import validate_event
from .encoders import encode_event
from .temporal_features import generate_temporal_features
from .network_features import generate_network_features
from .behavioral_features import generate_behavioral_features
from .statistical_features import generate_statistical_features
from .feature_selector import (
    merge_features,
    feature_vector,
    feature_dataframe,
)
# ---------------------------------------------------------
# Feature Pipeline
# ---------------------------------------------------------

class FeatureEngineeringPipeline:

    """
    Complete feature engineering pipeline.
    """

    def __init__(self):

        pass
    # -----------------------------------------------------
    # Process Single Event
    # -----------------------------------------------------

    def process(
        self,
        event: Dict,
    ) -> Dict:

        #
        # Step 1
        #

        validated = validate_event(

            event

        )

        #
        # Step 2
        #

        encoded = encode_event(

            asdict(validated)

        )

        #
        # Step 3
        #

        temporal = generate_temporal_features(

            validated.timestamp

        )

        #
        # Step 4
        #

        network = generate_network_features(

            validated.src_ip,

            validated.dest_ip,

            validated.src_port,

            validated.dest_port,

        )

        #
        # Step 5
        #

        behavioral = generate_behavioral_features(

            validated

        )

        #
        # Step 6
        #

        statistical = generate_statistical_features(

            validated

        )
        #
        # Step 7
        #

        features = merge_features(

            encoded,

            temporal,

            network,

            behavioral,

            statistical,

        )

        #
        # Step 8
        #

        vector = feature_vector(

            features

        )

        return {

            "validated_event": asdict(
                validated
            ),

            "features": features,

            "vector": vector,

        }
        
    # -----------------------------------------------------
    # Process Batch
    # -----------------------------------------------------

    def process_batch(
        self,
        events: List[Dict],
    ) -> List[Dict]:

        results = []

        for event in events:

            try:

                results.append(

                    self.process(

                        event

                    )

                )

            except Exception:

                #
                # Skip invalid events
                #

                continue

        return results

    # -----------------------------------------------------
    # Feature DataFrame
    # -----------------------------------------------------

    def dataframe(
        self,
        events: List[Dict],
    ):

        processed = self.process_batch(

            events

        )

        feature_sets = [

            item["features"]

            for item in processed

        ]

        return feature_dataframe(

            feature_sets

        )
    # -----------------------------------------------------
    # Statistics
    # -----------------------------------------------------

    def statistics(
        self,
        processed_events: List[Dict],
    ) -> Dict:

        total = len(

            processed_events

        )

        if total == 0:

            return {

                "processed_events": 0,

                "feature_count": 0,

                "vector_length": 0,

            }

        first = processed_events[0]

        return {

            "processed_events": total,

            "feature_count": len(

                first["features"]

            ),

            "vector_length": len(

                first["vector"]

            ),

        }
    # -----------------------------------------------------
    # Reset Stateful Components
    # -----------------------------------------------------

    def reset(
        self,
    ) -> None:

        #
        # Behavioral module
        #

        from .behavioral_features import (

            reset_behavioral_statistics,

        )

        #
        # Statistical module
        #

        from .statistical_features import (

            reset_statistics,

        )

        reset_behavioral_statistics()

        reset_statistics()
        
# ---------------------------------------------------------
# Singleton
# ---------------------------------------------------------

_pipeline = FeatureEngineeringPipeline()


def process_event(
    event: Dict,
) -> Dict:

    return _pipeline.process(

        event

    )


def process_events(
    events: List[Dict],
) -> List[Dict]:

    return _pipeline.process_batch(

        events

    )


def generate_feature_dataframe(
    events: List[Dict],
):

    return _pipeline.dataframe(

        events

    )


# ---------------------------------------------------------
# Local Testing
# ---------------------------------------------------------

if __name__ == "__main__":

    from pprint import pprint

    sample_event = {

        "event_id": "EVT-1001",

        "timestamp": "2026-07-25T10:15:30",

        "src_ip": "192.168.1.10",

        "dest_ip": "8.8.8.8",

        "protocol": "TCP",

        "severity": "HIGH",

        "event_category": "Malware",

        "asset_criticality": "CRITICAL",

        "threat_score": 92.4,

        "cvss_score": 9.8,

        "matched_ioc": True,

        "mitre_technique_id": "T1486",

        "mitre_tactic": "Impact",

        "user": "admin",

        "host": "server01",

        "src_port": 50555,

        "dest_port": 443,

    }

    result = process_event(

        sample_event

    )

    pprint(result)

    print()

    print(

        "Feature Vector Length:",

        len(result["vector"])

    )
