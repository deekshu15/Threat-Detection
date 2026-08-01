"""
Enterprise Behavior Analytics Service

Provides behavioral enrichment and anomaly detection.

Features
--------
• User Behavior Analytics (UBA)
• Entity Behavior Analytics (UEBA)
• Behavioral Baselines
• Statistical Profiling
• MITRE Correlation
• Behavioral Risk
• Attack Chain Detection
• Event Enrichment

Python 3.11+
"""

from __future__ import annotations

import asyncio
import json
import statistics

from collections import defaultdict
from datetime import UTC
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any

from ..lambdas.threat_enrichment.logger import get_logger

from .base_service import BaseService


class BehaviorService(BaseService):

    service_name = "BehaviorService"

    ####################################################################
    # Initialization
    ####################################################################

    def __init__(
        self,
        baseline_directory: str | Path | None = None,
    ):

        super().__init__()

        self.logger = get_logger(
            "BehaviorService"
        )

        self.lock = Lock()

        self.baseline_directory = (

            Path(baseline_directory)

            if baseline_directory

            else Path("data/baselines")

        )

        ###############################################################
        # Baselines
        ###############################################################

        self.user_profiles = {}

        self.asset_profiles = {}

        self.network_profiles = {}

        ###############################################################
        # Event History
        ###############################################################

        self.user_history = defaultdict(list)

        self.asset_history = defaultdict(list)

        self.ip_history = defaultdict(list)

        ###############################################################
        # Cache
        ###############################################################

        self.lookup_cache = {}

        ###############################################################
        # Metadata
        ###############################################################

        self.loaded_at = None

        ###############################################################
        # Statistics
        ###############################################################

        self.stats_data = {

            "profiles": 0,

            "users": 0,

            "assets": 0,

            "events": 0,

            "lookups": 0,

            "hits": 0,

            "misses": 0,

        }

    ####################################################################
    # Initialize
    ####################################################################

    def initialize(self):

        super().initialize()

        self.load_profiles()

    ####################################################################
    # Load Profiles
    ####################################################################

    def load_profiles(self):

        if not self.baseline_directory.exists():

            return

        files = sorted(

            self.baseline_directory.glob(
                "*.json"
            )

        )

        for file in files:

            self.load_file(file)

        self.loaded_at = datetime.now(
            UTC
        )

    ####################################################################
    # Load File
    ####################################################################

    def load_file(
        self,
        path: Path,
    ):

        with open(
            path,
            encoding="utf-8",
        ) as fp:

            data = json.load(fp)

        self.user_profiles.update(

            data.get(
                "users",
                {},
            )

        )

        self.asset_profiles.update(

            data.get(
                "assets",
                {},
            )

        )

        self.network_profiles.update(

            data.get(
                "network",
                {},
            )

        )

        self.stats_data["profiles"] = (

            len(self.user_profiles)

            +

            len(self.asset_profiles)

            +

            len(self.network_profiles)

        )

    ####################################################################
    # Learn Event
    ####################################################################

    def learn_event(
        self,
        event,
    ):

        if getattr(event, "user", None):

            username = getattr(
                event.user,
                "username",
                None,
            )

            if username:

                self.user_history[
                    username
                ].append(event)

        if getattr(event, "asset", None):

            hostname = getattr(
                event.asset,
                "hostname",
                None,
            )

            if hostname:

                self.asset_history[
                    hostname
                ].append(event)

        if getattr(event, "network", None):

            ip = getattr(
                event.network,
                "source_ip",
                None,
            )

            if ip:

                self.ip_history[
                    ip
                ].append(event)

        self.stats_data[
            "events"
        ] += 1
        ####################################################################
    # User Anomaly
    ####################################################################

    def user_anomaly(
        self,
        event,
    ) -> float:

        user = getattr(event, "user", None)

        if user is None:
            return 0.0

        username = getattr(
            user,
            "username",
            None,
        )

        if not username:
            return 0.0

        profile = self.user_profiles.get(
            username,
            {},
        )

        score = 0.0

        score += self.login_time_anomaly(
            event,
            profile,
        )

        score += self.geo_anomaly(
            event,
            profile,
        )

        score += self.impossible_travel(
            event,
            profile,
        )

        return round(
            min(score, 10.0),
            2,
        )

    ####################################################################
    # Asset Anomaly
    ####################################################################

    def asset_anomaly(
        self,
        event,
    ) -> float:

        asset = getattr(event, "asset", None)

        if asset is None:
            return 0.0

        hostname = getattr(
            asset,
            "hostname",
            None,
        )

        if not hostname:
            return 0.0

        profile = self.asset_profiles.get(
            hostname,
            {},
        )

        score = 0.0

        score += self.rare_process_score(
            event,
            profile,
        )

        score += self.parent_process_score(
            event,
            profile,
        )

        return round(
            min(score, 10.0),
            2,
        )

    ####################################################################
    # Network Anomaly
    ####################################################################

    def network_anomaly(
        self,
        event,
    ) -> float:

        network = getattr(
            event,
            "network",
            None,
        )

        if network is None:
            return 0.0

        profile = self.network_profiles.get(
            network.source_ip,
            {},
        )

        score = 0.0

        score += self.port_anomaly(
            event,
            profile,
        )

        score += self.protocol_anomaly(
            event,
            profile,
        )

        return round(
            min(score, 10.0),
            2,
        )

    ####################################################################
    # Login Time
    ####################################################################

    def login_time_anomaly(
        self,
        event,
        profile,
    ) -> float:

        timestamp = getattr(
            event,
            "timestamp",
            None,
        )

        if timestamp is None:
            return 0.0

        allowed = profile.get(
            "working_hours",
            [8, 18],
        )

        hour = timestamp.hour

        if allowed[0] <= hour <= allowed[1]:
            return 0.0

        return 3.0

    ####################################################################
    # Geographic Anomaly
    ####################################################################

    def geo_anomaly(
        self,
        event,
        profile,
    ) -> float:

        location = getattr(
            event.user,
            "location",
            None,
        )

        allowed = profile.get(
            "countries",
            [],
        )

        if not allowed:
            return 0.0

        if location in allowed:
            return 0.0

        return 3.5

    ####################################################################
    # Impossible Travel
    ####################################################################

    def impossible_travel(
        self,
        event,
        profile,
    ) -> float:

        previous = profile.get(
            "last_country",
        )

        current = getattr(
            event.user,
            "location",
            None,
        )

        if previous is None:
            return 0.0

        if previous == current:
            return 0.0

        return 2.5

    ####################################################################
    # Rare Process
    ####################################################################

    def rare_process_score(
        self,
        event,
        profile,
    ) -> float:

        process = getattr(
            event,
            "process",
            None,
        )

        if process is None:
            return 0.0

        known = profile.get(
            "processes",
            [],
        )

        if process.name in known:
            return 0.0

        return 3.0

    ####################################################################
    # Parent Process
    ####################################################################

    def parent_process_score(
        self,
        event,
        profile,
    ) -> float:

        process = getattr(
            event,
            "process",
            None,
        )

        if process is None:
            return 0.0

        expected = profile.get(
            "parent_processes",
            {},
        )

        parent = process.parent

        allowed = expected.get(
            process.name,
            [],
        )

        if parent in allowed:
            return 0.0

        return 2.5

    ####################################################################
    # Port Anomaly
    ####################################################################

    def port_anomaly(
        self,
        event,
        profile,
    ) -> float:

        network = event.network

        expected = profile.get(
            "ports",
            [],
        )

        if network.destination_port in expected:
            return 0.0

        return 2.0

    ####################################################################
    # Protocol Anomaly
    ####################################################################

    def protocol_anomaly(
        self,
        event,
        profile,
    ) -> float:

        network = event.network

        expected = profile.get(
            "protocols",
            [],
        )

        protocol = str(
            network.protocol
        )

        if protocol in expected:
            return 0.0

        return 1.5

    ####################################################################
    # Baseline Deviation
    ####################################################################

    def deviation_score(
        self,
        values: list[float],
        value: float,
    ) -> float:

        if len(values) < 3:
            return 0.0

        mean = statistics.mean(values)

        deviation = statistics.stdev(values)

        if deviation == 0:
            return 0.0

        z = abs(
            (value - mean)
            / deviation
        )

        return round(
            min(z, 10.0),
            2,
        )
        ####################################################################
    # Attack Sequence Detection
    ####################################################################

    def detect_attack_sequence(
        self,
        events: list,
    ) -> dict[str, Any]:

        indicators = []

        score = 0.0

        techniques = []

        for event in events:

            if getattr(event, "mitre", None):

                for mapping in event.mitre:

                    if mapping.technique:

                        techniques.append(
                            mapping.technique.technique_id
                        )

        techniques = list(dict.fromkeys(techniques))

        #
        # Very simple heuristic
        #

        if len(techniques) >= 3:

            indicators.append(
                "Multi-stage ATT&CK activity"
            )

            score += 3.0

        if len(events) >= 10:

            indicators.append(
                "High event volume"
            )

            score += 2.0

        return {

            "score": round(
                min(score, 10.0),
                2,
            ),

            "techniques": techniques,

            "indicators": indicators,

        }

    ####################################################################
    # MITRE Behavior Correlation
    ####################################################################

    def mitre_behavior_score(
        self,
        event,
    ) -> float:

        mappings = getattr(
            event,
            "mitre",
            [],
        )

        if not mappings:

            return 0.0

        score = 0.0

        for mapping in mappings:

            if mapping.groups:

                score += 1.5

            if mapping.software:

                score += 1.0

            if mapping.technique:

                score += 1.0

        return round(
            min(score, 10.0),
            2,
        )

    ####################################################################
    # Behavioral Risk
    ####################################################################

    def behavioral_risk(
        self,
        event,
    ) -> float:

        user = self.user_anomaly(event)

        asset = self.asset_anomaly(event)

        network = self.network_anomaly(event)

        mitre = self.mitre_behavior_score(event)

        total = (

            user * 0.35 +

            asset * 0.25 +

            network * 0.20 +

            mitre * 0.20

        )

        return round(
            min(total, 10.0),
            2,
        )

    ####################################################################
    # Behavioral Confidence
    ####################################################################

    def confidence(
        self,
        event,
    ) -> float:

        score = 0.0

        if getattr(event, "user", None):

            score += 2.5

        if getattr(event, "asset", None):

            score += 2.5

        if getattr(event, "network", None):

            score += 2.5

        if getattr(event, "mitre", None):

            score += 2.5

        return score

    ####################################################################
    # Indicators
    ####################################################################

    def indicators(
        self,
        event,
    ) -> list[str]:

        items = []

        if self.user_anomaly(event) > 5:

            items.append(
                "User behavior anomaly"
            )

        if self.asset_anomaly(event) > 5:

            items.append(
                "Asset behavior anomaly"
            )

        if self.network_anomaly(event) > 5:

            items.append(
                "Network anomaly"
            )

        if self.mitre_behavior_score(event) > 3:

            items.append(
                "ATT&CK correlation"
            )

        return items

    ####################################################################
    # Summary
    ####################################################################

    def summary(
        self,
        event,
    ) -> dict[str, Any]:

        return {

            "behavior_score":
                self.behavioral_risk(event),

            "confidence":
                self.confidence(event),

            "indicators":
                self.indicators(event),

        }

    ####################################################################
    # Enrich Event
    ####################################################################

    def enrich_event(
        self,
        event,
    ):

        event.behavior = self.summary(
            event
        )

        return event

    ####################################################################
    # Batch Analysis
    ####################################################################

    def analyze_events(
        self,
        events: list,
    ) -> list:

        enriched = []

        for event in events:

            enriched.append(

                self.enrich_event(
                    event
                )

            )

        return enriched

    ####################################################################
    # Composite Score
    ####################################################################

    def composite_score(
        self,
        events: list,
    ) -> float:

        if not events:

            return 0.0

        scores = [

            self.behavioral_risk(e)

            for e in events

        ]

        return round(

            statistics.mean(scores),

            2,

        )
        ####################################################################
    # Export Profiles
    ####################################################################

    def export_json(
        self,
        path: str | Path,
    ) -> None:

        path = Path(path)

        data = {

            "users": self.user_profiles,

            "assets": self.asset_profiles,

            "network": self.network_profiles,

        }

        with open(
            path,
            "w",
            encoding="utf-8",
        ) as fp:

            json.dump(

                data,

                fp,

                indent=4,

                ensure_ascii=False,

            )

    ####################################################################
    # Import Profiles
    ####################################################################

    def import_json(
        self,
        path: str | Path,
    ) -> None:

        path = Path(path)

        with open(
            path,
            encoding="utf-8",
        ) as fp:

            data = json.load(fp)

        self.user_profiles.update(
            data.get("users", {})
        )

        self.asset_profiles.update(
            data.get("assets", {})
        )

        self.network_profiles.update(
            data.get("network", {})
        )

        self.stats_data["profiles"] = (

            len(self.user_profiles)

            +

            len(self.asset_profiles)

            +

            len(self.network_profiles)

        )

    ####################################################################
    # Statistics
    ####################################################################

    def stats(
        self,
    ) -> dict[str, Any]:

        return {

            "service":
                self.service_name,

            "profiles":
                self.stats_data["profiles"],

            "users":
                len(self.user_profiles),

            "assets":
                len(self.asset_profiles),

            "network":
                len(self.network_profiles),

            "events":
                self.stats_data["events"],

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

        return {

            "service":
                self.service_name,

            "status":
                "healthy",

            "profiles":
                self.stats_data["profiles"],

            "users":
                len(self.user_profiles),

            "assets":
                len(self.asset_profiles),

            "network":
                len(self.network_profiles),

            "events_processed":
                self.stats_data["events"],

            "cache":
                len(self.lookup_cache),

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

            "user_profiles":
                len(self.user_profiles),

            "asset_profiles":
                len(self.asset_profiles),

            "network_profiles":
                len(self.network_profiles),

            "user_history":
                len(self.user_history),

            "asset_history":
                len(self.asset_history),

            "ip_history":
                len(self.ip_history),

            "lookup_cache":
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
    # Clear Service
    ####################################################################

    def clear(
        self,
    ) -> None:

        self.user_profiles.clear()

        self.asset_profiles.clear()

        self.network_profiles.clear()

        self.user_history.clear()

        self.asset_history.clear()

        self.ip_history.clear()

        self.lookup_cache.clear()

        self.stats_data["profiles"] = 0

        self.stats_data["events"] = 0

    ####################################################################
    # Refresh
    ####################################################################

    def refresh(
        self,
    ) -> None:

        self.logger.info(
            "Refreshing behavioral profiles..."
        )

        self.clear()

        self.load_profiles()

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
        events: list,
    ) -> list:

        return self.analyze_events(
            events
        )

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

        return self.stats_data["profiles"]

    def __repr__(
        self,
    ) -> str:

        return (

            f"<BehaviorService "

            f"profiles={self.stats_data['profiles']} "

            f"events={self.stats_data['events']}>"

        )
    