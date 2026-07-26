"""
Statistical Feature Engineering

Generates statistical and historical features
for ML-based threat detection.

Responsibilities
----------------
- Rolling Event Count
- Event Frequency
- Moving Average
- Standard Deviation
- Threat Score Statistics
- Historical Baselines
- Anomaly Indicators

Author:
AI Threat Detection Dashboard
"""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass
from statistics import mean, stdev
from typing import Dict

from .config import (
    MAX_HISTORY_EVENTS,
)
# ---------------------------------------------------------
# Statistical Features
# ---------------------------------------------------------

@dataclass(slots=True)
class StatisticalFeatures:

    rolling_event_count: int

    average_threat_score: float

    maximum_threat_score: float

    minimum_threat_score: float

    threat_score_std: float

    attack_frequency: float

    anomaly_score: float
# ---------------------------------------------------------
# Generator
# ---------------------------------------------------------

class StatisticalFeatureGenerator:

    """
    Generates rolling statistical features
    from historical events.
    """

    def __init__(self):

        self.history = deque(

            maxlen=MAX_HISTORY_EVENTS

        )
    # -----------------------------------------------------
    # Safe Mean
    # -----------------------------------------------------

    @staticmethod
    def _mean(values):

        if not values:

            return 0.0

        return round(

            mean(values),

            4,

        )

    # -----------------------------------------------------
    # Safe Standard Deviation
    # -----------------------------------------------------

    @staticmethod
    def _std(values):

        if len(values) < 2:

            return 0.0

        return round(

            stdev(values),

            4,

        )

    # -----------------------------------------------------
    # Safe Maximum
    # -----------------------------------------------------

    @staticmethod
    def _max(values):

        if not values:

            return 0.0

        return max(values)

    # -----------------------------------------------------
    # Safe Minimum
    # -----------------------------------------------------

    @staticmethod
    def _min(values):

        if not values:

            return 0.0

        return min(values)
    # -----------------------------------------------------
    # Update History
    # -----------------------------------------------------

    def _update_history(
        self,
        event,
    ):

        self.history.append(

            event

        )
    # -----------------------------------------------------
    # Attack Frequency
    # -----------------------------------------------------

    def _attack_frequency(
        self,
    ) -> float:

        total = len(

            self.history

        )

        if total == 0:

            return 0.0

        attacks = sum(

            1

            for event in self.history

            if event.threat_score >= 70

        )

        return round(

            attacks / total,

            4,

        )

    # -----------------------------------------------------
    # Anomaly Score (Z-Score)
    # -----------------------------------------------------

    def _anomaly_score(
        self,
        threat_score: float,
        average: float,
        std_dev: float,
    ) -> float:

        if std_dev == 0:

            return 0.0

        z_score = abs(

            (threat_score - average)

            / std_dev

        )

        return round(

            z_score,

            4,

        )

    # -----------------------------------------------------
    # Rolling Statistics
    # -----------------------------------------------------

    def _statistics(
        self,
    ):

        scores = [

            event.threat_score

            for event in self.history

        ]

        return {

            "average": self._mean(scores),

            "maximum": self._max(scores),

            "minimum": self._min(scores),

            "std": self._std(scores),

        }
    # -----------------------------------------------------
    # Generate
    # -----------------------------------------------------

    def generate(
        self,
        event,
    ) -> StatisticalFeatures:

        #
        # Add latest event
        #

        self._update_history(

            event

        )

        stats = self._statistics()

        anomaly = self._anomaly_score(

            event.threat_score,

            stats["average"],

            stats["std"],

        )

        return StatisticalFeatures(

            rolling_event_count=len(

                self.history

            ),

            average_threat_score=stats["average"],

            maximum_threat_score=stats["maximum"],

            minimum_threat_score=stats["minimum"],

            threat_score_std=stats["std"],

            attack_frequency=self._attack_frequency(),

            anomaly_score=anomaly,

        )

    # -----------------------------------------------------
    # Dictionary Output
    # -----------------------------------------------------

    def generate_dict(
        self,
        event,
    ) -> Dict:

        return asdict(

            self.generate(

                event

            )

        )
    # -----------------------------------------------------
    # Batch Processing
    # -----------------------------------------------------

    def generate_batch(
        self,
        events,
    ):

        features = []

        for event in events:

            features.append(

                self.generate_dict(

                    event

                )

            )

        return features

    # -----------------------------------------------------
    # Reset Statistics
    # -----------------------------------------------------

    def reset(self):

        self.history.clear()


# ---------------------------------------------------------
# Singleton
# ---------------------------------------------------------

_generator = StatisticalFeatureGenerator()


def generate_statistical_features(
    event,
) -> Dict:

    return _generator.generate_dict(

        event

    )


def generate_batch_statistical_features(
    events,
):

    return _generator.generate_batch(

        events

    )


def reset_statistics():

    _generator.reset()


# ---------------------------------------------------------
# Local Testing
# ---------------------------------------------------------

if __name__ == "__main__":

    from pprint import pprint

    from types import SimpleNamespace

    samples = [

        15,

        22,

        18,

        30,

        91,

    ]

    for score in samples:

        event = SimpleNamespace(

            threat_score=score

        )

        result = generate_statistical_features(

            event

        )

        pprint(result)