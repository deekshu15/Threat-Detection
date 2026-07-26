"""
Behavioral Feature Engineering

Generates behavioral features from enriched
security events.

Responsibilities
----------------
- User Activity
- Host Activity
- Login Statistics
- Failed Login Tracking
- Privilege Escalation Tracking
- IOC Frequency
- User Risk
- Host Risk

Author:
AI Threat Detection Dashboard
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, asdict, dataclass
from typing import Dict

from .config import (
    HIGH_RISK_EVENT_THRESHOLD,
    IOC_THRESHOLD,
    MAX_HISTORY_EVENTS,
)
# ---------------------------------------------------------
# Behavioral Features
# ---------------------------------------------------------

@dataclass(slots=True)
class BehavioralFeatures:

    user_event_count: int

    host_event_count: int

    failed_login_count: int

    successful_login_count: int

    privilege_escalation_count: int

    ioc_match_count: int

    high_risk_event_count: int

    user_risk: float

    host_risk: float
# ---------------------------------------------------------
# Generator
# ---------------------------------------------------------

class BehavioralFeatureGenerator:

    """
    Generates behavioral features for
    users and hosts.
    """

    def __init__(self):

        #
        # User statistics
        #

        self.user_events = defaultdict(int)

        self.failed_logins = defaultdict(int)

        self.successful_logins = defaultdict(int)

        self.user_risk = defaultdict(float)

        #
        # Host statistics
        #

        self.host_events = defaultdict(int)

        self.host_risk = defaultdict(float)

        #
        # Threat statistics
        #

        self.ioc_hits = defaultdict(int)

        self.high_risk_events = defaultdict(int)

        self.privilege_escalation = defaultdict(int)

        #
        # Event history
        #

        self.history = deque(

            maxlen=MAX_HISTORY_EVENTS

        )
    # -----------------------------------------------------
    # Update Internal Statistics
    # -----------------------------------------------------

    def _update_statistics(
        self,
        event,
    ) -> None:

        user = event.user or "UNKNOWN"

        host = event.host or "UNKNOWN"

        category = (

            event.event_category.lower()

        )

        self.user_events[user] += 1

        self.host_events[host] += 1

        #
        # Login Tracking
        #

        if "login" in category:

            if event.severity in (

                "HIGH",

                "CRITICAL",

            ):

                self.failed_logins[user] += 1

            else:

                self.successful_logins[user] += 1

        #
        # IOC Tracking
        #

        if event.matched_ioc:

            self.ioc_hits[user] += 1

        #
        # High Risk Tracking
        #

        if event.threat_score >= 80:

            self.high_risk_events[user] += 1

        #
        # Privilege Escalation
        #

        if (

            "privilege"

            in category

        ):

            self.privilege_escalation[user] += 1

        self.history.append(

            event
        )
    # -----------------------------------------------------
    # User Risk
    # -----------------------------------------------------

    def _calculate_user_risk(
        self,
        user: str,
    ) -> float:

        risk = 0.0

        risk += min(

            self.failed_logins[user] * 5,

            30,

        )

        risk += min(

            self.ioc_hits[user] * 10,

            30,

        )

        risk += min(

            self.high_risk_events[user] * 4,

            20,

        )

        risk += min(

            self.privilege_escalation[user] * 10,

            20,

        )

        return round(

            min(

                risk,

                100,

            ),

            2,

        )
    # -----------------------------------------------------
    # Host Risk
    # -----------------------------------------------------

    def _calculate_host_risk(
        self,
        host: str,
    ) -> float:

        risk = 0.0

        total_events = self.host_events[host]

        if total_events >= HIGH_RISK_EVENT_THRESHOLD:

            risk += 20

        risk += min(

            total_events * 2,

            30,

        )

        return round(

            min(

                risk,

                100,

            ),

            2,

        )

    # -----------------------------------------------------
    # Generate Features
    # -----------------------------------------------------

    def generate(
        self,
        event,
    ) -> BehavioralFeatures:

        #
        # Update statistics first
        #

        self._update_statistics(

            event

        )

        user = event.user or "UNKNOWN"

        host = event.host or "UNKNOWN"

        user_risk = self._calculate_user_risk(

            user

        )

        host_risk = self._calculate_host_risk(

            host

        )

        self.user_risk[user] = user_risk

        self.host_risk[host] = host_risk

        return BehavioralFeatures(

            user_event_count=self.user_events[user],

            host_event_count=self.host_events[host],

            failed_login_count=self.failed_logins[user],

            successful_login_count=self.successful_logins[user],

            privilege_escalation_count=self.privilege_escalation[user],

            ioc_match_count=self.ioc_hits[user],

            high_risk_event_count=self.high_risk_events[user],

            user_risk=user_risk,

            host_risk=host_risk,

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

        self.user_events.clear()

        self.failed_logins.clear()

        self.successful_logins.clear()

        self.user_risk.clear()

        self.host_events.clear()

        self.host_risk.clear()

        self.ioc_hits.clear()

        self.high_risk_events.clear()

        self.privilege_escalation.clear()

        self.history.clear()


# ---------------------------------------------------------
# Singleton
# ---------------------------------------------------------

_generator = BehavioralFeatureGenerator()


def generate_behavioral_features(
    event,
) -> Dict:

    return _generator.generate_dict(

        event

    )


def generate_batch_behavioral_features(
    events,
):

    return _generator.generate_batch(

        events

    )


def reset_behavioral_statistics():

    _generator.reset()


# ---------------------------------------------------------
# Local Testing
# ---------------------------------------------------------

if __name__ == "__main__":

    from pprint import pprint

    from types import SimpleNamespace

    event = SimpleNamespace(

        user="admin",

        host="server01",

        severity="HIGH",

        event_category="Privilege Escalation",

        matched_ioc=True,

        threat_score=95,

    )

    result = generate_behavioral_features(

        event

    )

    pprint(result)