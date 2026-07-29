"""
IOC Service

Enterprise IOC Enrichment Service

Responsibilities
----------------
* Load IOC feeds
* Normalize indicators
* Match IPs, Domains, URLs, Hashes
* CIDR matching
* Reputation scoring
* Confidence calculation
* Threat intelligence aggregation
* Feed versioning
* Statistics
* Health monitoring
* Async refresh support

Python 3.11+
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import ipaddress
import json
import re
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any

from ..exceptions import IOCLoadError
from ..logger import get_logger
from ..models.ioc import (
    IOCConfidence,
    IOCMatch,
    IOCModel,
    IOCReputation,
    IOCType,
)
from .base_service import BaseService


class IOCService(BaseService):
    """
    Enterprise IOC lookup engine.

    This class keeps all IOC datasets indexed in memory
    for O(1) lookups wherever possible.
    """

    service_name = "IOCService"

    ####################################################################
    # Initialization
    ####################################################################

    def __init__(
        self,
        feed_directory: str | Path | None = None,
    ) -> None:

        super().__init__()

        self.feed_directory = (
            Path(feed_directory)
            if feed_directory
            else Path("data/ioc")
        )

        self.logger = get_logger("IOCService")

        self.lock = Lock()

        ################################################################
        # Feed metadata
        ################################################################

        self.feed_version = "1.0"

        self.loaded_at = None

        self.feed_count = 0

        ################################################################
        # IOC Storage
        ################################################################

        self.iocs: list[IOCModel] = []

        ################################################################
        # Fast indexes
        ################################################################

        self.ip_index: dict[str, IOCModel] = {}

        self.domain_index: dict[str, IOCModel] = {}

        self.url_index: dict[str, IOCModel] = {}

        self.sha256_index: dict[str, IOCModel] = {}

        self.sha1_index: dict[str, IOCModel] = {}

        self.md5_index: dict[str, IOCModel] = {}

        self.email_index: dict[str, IOCModel] = {}

        self.mutex_index: dict[str, IOCModel] = {}

        self.process_index: dict[str, IOCModel] = {}

        self.registry_index: dict[str, IOCModel] = {}

        ################################################################
        # CIDR Networks
        ################################################################

        self.networks: list[
            tuple[ipaddress._BaseNetwork, IOCModel]
        ] = []

        ################################################################
        # Statistics
        ################################################################

        self.stats_data = {

            "loaded": 0,

            "ip": 0,

            "domain": 0,

            "url": 0,

            "sha256": 0,

            "sha1": 0,

            "md5": 0,

            "email": 0,

            "mutex": 0,

            "process": 0,

            "registry": 0,

            "cidr": 0,

            "lookups": 0,

            "matches": 0,

            "misses": 0,
        }

        ################################################################
        # Cache
        ################################################################

        self.lookup_cache: dict[str, IOCMatch | None] = {}

        ################################################################
        # Feed Sources
        ################################################################

        self.feed_sources: list[Path] = []

    ####################################################################
    # Feed Loading
    ####################################################################

    def initialize(self) -> None:

        super().initialize()

        self.load_all_feeds()

    ####################################################################
    # Feed Discovery
    ####################################################################

    def discover_feeds(self) -> list[Path]:

        feeds = []

        if not self.feed_directory.exists():

            self.logger.warning(
                "IOC feed directory not found: %s",
                self.feed_directory,
            )

            return feeds

        for extension in (
            "*.json",
            "*.csv",
        ):

            feeds.extend(
                self.feed_directory.glob(extension)
            )

        self.feed_sources = sorted(feeds)

        return self.feed_sources

    ####################################################################
    # Load All
    ####################################################################

    def load_all_feeds(self) -> None:

        feeds = self.discover_feeds()

        self.logger.info(
            "Loading %d IOC feeds...",
            len(feeds),
        )

        for feed in feeds:

            try:

                self.load_feed(feed)

            except Exception as exc:

                self.logger.exception(exc)

        self.loaded_at = datetime.now(UTC)

        self.feed_count = len(feeds)

        self.logger.info(
            "IOC loading complete (%d indicators)",
            len(self.iocs),
        )

    ####################################################################
    # Feed Loader
    ####################################################################

    def load_feed(
        self,
        path: Path,
    ) -> None:

        suffix = path.suffix.lower()

        if suffix == ".json":

            self._load_json(path)

        elif suffix == ".csv":

            self._load_csv(path)

        else:

            raise IOCLoadError(
                f"Unsupported feed: {suffix}"
            )

    ####################################################################
    # JSON Loader
    ####################################################################

    def _load_json(
        self,
        path: Path,
    ) -> None:

        with open(
            path,
            encoding="utf-8",
        ) as file:

            data = json.load(file)

        if isinstance(data, dict):

            data = data.get(
                "iocs",
                [],
            )

        for row in data:

            self.add_ioc(row)

    ####################################################################
    # CSV Loader
    ####################################################################

    def _load_csv(
        self,
        path: Path,
    ) -> None:

        with open(
            path,
            newline="",
            encoding="utf-8",
        ) as file:

            reader = csv.DictReader(file)

            for row in reader:

                self.add_ioc(row)
        ####################################################################
    # Add IOC
    ####################################################################

    def add_ioc(
        self,
        data: dict[str, Any] | IOCModel,
    ) -> IOCModel:

        if isinstance(data, IOCModel):
            ioc = data
        else:
            normalized = self.normalize_ioc(data)
            ioc = IOCModel(**normalized)

        if self._is_duplicate(ioc):
            return ioc

        self.iocs.append(ioc)

        self._index_ioc(ioc)

        self.stats_data["loaded"] += 1

        return ioc

    ####################################################################
    # IOC Normalization
    ####################################################################

    def normalize_ioc(
        self,
        data: dict[str, Any],
    ) -> dict[str, Any]:

        indicator = str(
            data.get(
                "indicator",
                data.get("value", "")
            )
        ).strip()

        indicator = self._normalize_indicator(indicator)

        ioc_type = data.get("type")

        if not ioc_type:
            ioc_type = self.detect_type(indicator)

        reputation = data.get(
            "reputation",
            IOCReputation.UNKNOWN,
        )

        confidence = data.get(
            "confidence",
            IOCConfidence.MEDIUM,
        )

        normalized = {

            "indicator": indicator,

            "ioc_type": ioc_type,

            "reputation": reputation,

            "confidence": confidence,

            "description":
                data.get("description"),

            "source":
                data.get("source"),

            "tags":
                data.get("tags", []),

            "first_seen":
                data.get("first_seen"),

            "last_seen":
                data.get("last_seen"),

            "reference":
                data.get("reference"),
        }

        return normalized

    ####################################################################
    # Normalize Indicator
    ####################################################################

    def _normalize_indicator(
        self,
        indicator: str,
    ) -> str:

        indicator = indicator.strip()

        indicator = indicator.lower()

        return indicator

    ####################################################################
    # Automatic Type Detection
    ####################################################################

    def detect_type(
        self,
        indicator: str,
    ) -> IOCType:

        if self._is_ipv4(indicator):
            return IOCType.IP

        if self._is_ipv6(indicator):
            return IOCType.IP

        if self._is_cidr(indicator):
            return IOCType.IP

        if self._is_url(indicator):
            return IOCType.URL

        if self._is_domain(indicator):
            return IOCType.DOMAIN

        if self._is_sha256(indicator):
            return IOCType.SHA256

        if self._is_sha1(indicator):
            return IOCType.SHA1

        if self._is_md5(indicator):
            return IOCType.MD5

        if self._is_email(indicator):
            return IOCType.EMAIL

        return IOCType.UNKNOWN

    ####################################################################
    # Duplicate Detection
    ####################################################################

    def _is_duplicate(
        self,
        ioc: IOCModel,
    ) -> bool:

        indicator = ioc.indicator

        if ioc.ioc_type == IOCType.IP:
            return indicator in self.ip_index

        if ioc.ioc_type == IOCType.DOMAIN:
            return indicator in self.domain_index

        if ioc.ioc_type == IOCType.URL:
            return indicator in self.url_index

        if ioc.ioc_type == IOCType.SHA256:
            return indicator in self.sha256_index

        if ioc.ioc_type == IOCType.SHA1:
            return indicator in self.sha1_index

        if ioc.ioc_type == IOCType.MD5:
            return indicator in self.md5_index

        if ioc.ioc_type == IOCType.EMAIL:
            return indicator in self.email_index

        if ioc.ioc_type == IOCType.MUTEX:
            return indicator in self.mutex_index

        if ioc.ioc_type == IOCType.PROCESS:
            return indicator in self.process_index

        if ioc.ioc_type == IOCType.REGISTRY:
            return indicator in self.registry_index

        return False

    ####################################################################
    # Index Builder
    ####################################################################

    def _index_ioc(
        self,
        ioc: IOCModel,
    ) -> None:

        indicator = ioc.indicator

        if ioc.ioc_type == IOCType.IP:

            if self._is_cidr(indicator):

                network = ipaddress.ip_network(
                    indicator,
                    strict=False,
                )

                self.networks.append(
                    (
                        network,
                        ioc,
                    )
                )

                self.stats_data["cidr"] += 1

            else:

                self.ip_index[indicator] = ioc

                self.stats_data["ip"] += 1

            return

        if ioc.ioc_type == IOCType.DOMAIN:

            self.domain_index[indicator] = ioc

            self.stats_data["domain"] += 1

            return

        if ioc.ioc_type == IOCType.URL:

            self.url_index[indicator] = ioc

            self.stats_data["url"] += 1

            return

        if ioc.ioc_type == IOCType.SHA256:

            self.sha256_index[indicator] = ioc

            self.stats_data["sha256"] += 1

            return

        if ioc.ioc_type == IOCType.SHA1:

            self.sha1_index[indicator] = ioc

            self.stats_data["sha1"] += 1

            return

        if ioc.ioc_type == IOCType.MD5:

            self.md5_index[indicator] = ioc

            self.stats_data["md5"] += 1

            return

        if ioc.ioc_type == IOCType.EMAIL:

            self.email_index[indicator] = ioc

            self.stats_data["email"] += 1

            return

        if ioc.ioc_type == IOCType.MUTEX:

            self.mutex_index[indicator] = ioc

            self.stats_data["mutex"] += 1

            return

        if ioc.ioc_type == IOCType.PROCESS:

            self.process_index[indicator] = ioc

            self.stats_data["process"] += 1

            return

        if ioc.ioc_type == IOCType.REGISTRY:

            self.registry_index[indicator] = ioc

            self.stats_data["registry"] += 1

    ####################################################################
    # Validation Helpers
    ####################################################################

    @staticmethod
    def _is_ipv4(value: str) -> bool:

        try:
            return isinstance(
                ipaddress.ip_address(value),
                ipaddress.IPv4Address,
            )
        except ValueError:
            return False

    @staticmethod
    def _is_ipv6(value: str) -> bool:

        try:
            return isinstance(
                ipaddress.ip_address(value),
                ipaddress.IPv6Address,
            )
        except ValueError:
            return False

    @staticmethod
    def _is_cidr(value: str) -> bool:

        try:
            ipaddress.ip_network(
                value,
                strict=False,
            )
            return "/" in value
        except ValueError:
            return False

    @staticmethod
    def _is_domain(value: str) -> bool:

        regex = (
            r"^(?:[a-zA-Z0-9]"
            r"(?:[a-zA-Z0-9-]{0,61}"
            r"[a-zA-Z0-9])?\.)+"
            r"[A-Za-z]{2,}$"
        )

        return bool(
            re.fullmatch(
                regex,
                value,
            )
        )

    @staticmethod
    def _is_url(value: str) -> bool:

        return value.startswith(
            (
                "http://",
                "https://",
            )
        )

    @staticmethod
    def _is_sha256(value: str) -> bool:

        return bool(
            re.fullmatch(
                r"[A-Fa-f0-9]{64}",
                value,
            )
        )

    @staticmethod
    def _is_sha1(value: str) -> bool:

        return bool(
            re.fullmatch(
                r"[A-Fa-f0-9]{40}",
                value,
            )
        )

    @staticmethod
    def _is_md5(value: str) -> bool:

        return bool(
            re.fullmatch(
                r"[A-Fa-f0-9]{32}",
                value,
            )
        )

    @staticmethod
    def _is_email(value: str) -> bool:

        return bool(
            re.fullmatch(
                r"[^@]+@[^@]+\.[^@]+",
                value,
            )
        )
        ####################################################################
    # Generic Lookup
    ####################################################################

    def lookup(
        self,
        indicator: str,
    ) -> IOCMatch | None:

        if not indicator:
            return None

        indicator = self._normalize_indicator(indicator)

        self.stats_data["lookups"] += 1

        cached = self.lookup_cache.get(indicator)

        if cached is not None:
            return cached

        result = None

        if self._is_ipv4(indicator) or self._is_ipv6(indicator):
            result = self.lookup_ip(indicator)

        elif self._is_url(indicator):
            result = self.lookup_url(indicator)

        elif self._is_domain(indicator):
            result = self.lookup_domain(indicator)

        elif (
            self._is_sha256(indicator)
            or self._is_sha1(indicator)
            or self._is_md5(indicator)
        ):
            result = self.lookup_hash(indicator)

        elif self._is_email(indicator):
            result = self.lookup_email(indicator)

        if result:

            self.stats_data["matches"] += 1

        else:

            self.stats_data["misses"] += 1

        self.lookup_cache[indicator] = result

        return result

    ####################################################################
    # IP Lookup
    ####################################################################

    def lookup_ip(
        self,
        ip: str,
    ) -> IOCMatch | None:

        ip = self._normalize_indicator(ip)

        if ip in self.ip_index:

            return self._create_match(
                self.ip_index[ip]
            )

        ip_obj = ipaddress.ip_address(ip)

        for network, ioc in self.networks:

            if ip_obj in network:

                return self._create_match(ioc)

        return None

    ####################################################################
    # Domain Lookup
    ####################################################################

    def lookup_domain(
        self,
        domain: str,
    ) -> IOCMatch | None:

        domain = self._normalize_indicator(domain)

        ioc = self.domain_index.get(domain)

        if ioc:

            return self._create_match(ioc)

        return None

    ####################################################################
    # URL Lookup
    ####################################################################

    def lookup_url(
        self,
        url: str,
    ) -> IOCMatch | None:

        url = self._normalize_indicator(url)

        ioc = self.url_index.get(url)

        if ioc:

            return self._create_match(ioc)

        return None

    ####################################################################
    # Hash Lookup
    ####################################################################

    def lookup_hash(
        self,
        value: str,
    ) -> IOCMatch | None:

        value = value.lower()

        if len(value) == 64:

            ioc = self.sha256_index.get(value)

            if ioc:
                return self._create_match(ioc)

        elif len(value) == 40:

            ioc = self.sha1_index.get(value)

            if ioc:
                return self._create_match(ioc)

        elif len(value) == 32:

            ioc = self.md5_index.get(value)

            if ioc:
                return self._create_match(ioc)

        return None

    ####################################################################
    # Email Lookup
    ####################################################################

    def lookup_email(
        self,
        email: str,
    ) -> IOCMatch | None:

        email = self._normalize_indicator(email)

        ioc = self.email_index.get(email)

        if ioc:

            return self._create_match(ioc)

        return None

    ####################################################################
    # Process Lookup
    ####################################################################

    def lookup_process(
        self,
        process: str,
    ) -> IOCMatch | None:

        process = process.lower()

        ioc = self.process_index.get(process)

        if ioc:

            return self._create_match(ioc)

        return None

    ####################################################################
    # Mutex Lookup
    ####################################################################

    def lookup_mutex(
        self,
        mutex: str,
    ) -> IOCMatch | None:

        mutex = mutex.lower()

        ioc = self.mutex_index.get(mutex)

        if ioc:

            return self._create_match(ioc)

        return None

    ####################################################################
    # Registry Lookup
    ####################################################################

    def lookup_registry(
        self,
        registry: str,
    ) -> IOCMatch | None:

        registry = registry.lower()

        ioc = self.registry_index.get(registry)

        if ioc:

            return self._create_match(ioc)

        return None

    ####################################################################
    # Batch Lookup
    ####################################################################

    def lookup_many(
        self,
        indicators: list[str],
    ) -> list[IOCMatch]:

        matches = []

        for indicator in indicators:

            result = self.lookup(indicator)

            if result:

                matches.append(result)

        return matches

    ####################################################################
    # Match Builder
    ####################################################################

    def _create_match(
        self,
        ioc: IOCModel,
    ) -> IOCMatch:

        return IOCMatch(

            indicator=ioc.indicator,

            ioc_type=ioc.ioc_type,

            reputation=ioc.reputation,

            confidence=ioc.confidence,

            source=ioc.source,

            description=ioc.description,

            tags=ioc.tags,

            first_seen=ioc.first_seen,

            last_seen=ioc.last_seen,
        )

    ####################################################################
    # Contains
    ####################################################################

    def contains(
        self,
        indicator: str,
    ) -> bool:

        return self.lookup(indicator) is not None

    ####################################################################
    # Count
    ####################################################################

    def count(self) -> int:

        return len(self.iocs)

    ####################################################################
    # Clear Cache
    ####################################################################

    def clear_cache(self) -> None:

        self.lookup_cache.clear()

    ####################################################################
    # Cache Size
    ####################################################################

    def cache_size(self) -> int:

        return len(self.lookup_cache)
        ####################################################################
    # Reputation Engine
    ####################################################################

    def reputation_score(
        self,
        reputation: IOCReputation,
    ) -> int:
        """
        Convert IOC reputation into a numeric score.
        """

        mapping = {

            IOCReputation.UNKNOWN: 10,

            IOCReputation.SUSPICIOUS: 40,

            IOCReputation.MALICIOUS: 100,

            IOCReputation.TRUSTED: 0,
        }

        return mapping.get(
            reputation,
            10,
        )

    ####################################################################
    # Confidence Engine
    ####################################################################

    def confidence_score(
        self,
        confidence: IOCConfidence,
    ) -> int:

        mapping = {

            IOCConfidence.LOW: 25,

            IOCConfidence.MEDIUM: 50,

            IOCConfidence.HIGH: 80,

            IOCConfidence.VERY_HIGH: 100,
        }

        return mapping.get(
            confidence,
            50,
        )

    ####################################################################
    # IOC Weight
    ####################################################################

    def indicator_weight(
        self,
        ioc_type: IOCType,
    ) -> float:

        weights = {

            IOCType.IP: 0.8,

            IOCType.DOMAIN: 0.9,

            IOCType.URL: 0.95,

            IOCType.SHA256: 1.0,

            IOCType.SHA1: 0.95,

            IOCType.MD5: 0.9,

            IOCType.EMAIL: 0.6,

            IOCType.MUTEX: 0.85,

            IOCType.PROCESS: 0.75,

            IOCType.REGISTRY: 0.7,

            IOCType.UNKNOWN: 0.5,
        }

        return weights.get(
            ioc_type,
            0.5,
        )

    ####################################################################
    # IOC Threat Score
    ####################################################################

    def calculate_threat_score(
        self,
        ioc: IOCModel,
    ) -> float:

        reputation = self.reputation_score(
            ioc.reputation,
        )

        confidence = self.confidence_score(
            ioc.confidence,
        )

        weight = self.indicator_weight(
            ioc.ioc_type,
        )

        score = (
            reputation * 0.55
            + confidence * 0.45
        ) * weight

        return round(
            score,
            2,
        )

    ####################################################################
    # Sort Matches
    ####################################################################

    def sort_matches(
        self,
        matches: list[IOCMatch],
    ) -> list[IOCMatch]:

        return sorted(

            matches,

            key=lambda match: (

                self.reputation_score(
                    match.reputation
                ),

                self.confidence_score(
                    match.confidence
                ),
            ),

            reverse=True,
        )

    ####################################################################
    # Best Match
    ####################################################################

    def best_match(
        self,
        matches: list[IOCMatch],
    ) -> IOCMatch | None:

        if not matches:

            return None

        matches = self.sort_matches(
            matches,
        )

        return matches[0]

    ####################################################################
    # Merge Duplicate IOC
    ####################################################################

    def merge_ioc(
        self,
        existing: IOCModel,
        incoming: IOCModel,
    ) -> IOCModel:

        if (
            self.reputation_score(
                incoming.reputation
            )
            >
            self.reputation_score(
                existing.reputation
            )
        ):
            existing.reputation = incoming.reputation

        if (
            self.confidence_score(
                incoming.confidence
            )
            >
            self.confidence_score(
                existing.confidence
            )
        ):
            existing.confidence = incoming.confidence

        tags = set(existing.tags)

        tags.update(
            incoming.tags,
        )

        existing.tags = sorted(tags)

        if incoming.description:

            existing.description = incoming.description

        if incoming.last_seen:

            existing.last_seen = incoming.last_seen

        return existing

    ####################################################################
    # Feed Priority
    ####################################################################

    def feed_priority(
        self,
        source: str | None,
    ) -> int:

        priorities = {

            "MISP": 100,

            "OTX": 95,

            "AbuseIPDB": 90,

            "AlienVault": 90,

            "VirusTotal": 90,

            "RecordedFuture": 100,

            "OpenCTI": 95,

            "Internal": 100,

            "Custom": 80,
        }

        if source is None:

            return 50

        return priorities.get(
            source,
            50,
        )

    ####################################################################
    # Rank IOC
    ####################################################################

    def rank_iocs(
        self,
        iocs: list[IOCModel],
    ) -> list[IOCModel]:

        return sorted(

            iocs,

            key=lambda x: (

                self.calculate_threat_score(
                    x
                ),

                self.feed_priority(
                    x.source
                ),
            ),

            reverse=True,
        )

    ####################################################################
    # Highest Risk IOC
    ####################################################################

    def highest_risk(
        self,
        iocs: list[IOCModel],
    ) -> IOCModel | None:

        ranked = self.rank_iocs(
            iocs,
        )

        if ranked:

            return ranked[0]

        return None

    ####################################################################
    # Average Threat Score
    ####################################################################

    def average_score(
        self,
        iocs: list[IOCModel],
    ) -> float:

        if not iocs:

            return 0.0

        scores = [

            self.calculate_threat_score(i)

            for i in iocs

        ]

        return round(

            sum(scores) / len(scores),

            2,
        )
        ####################################################################
    # Statistics
    ####################################################################

    def stats(self) -> dict[str, Any]:
        """
        Return IOC service statistics.
        """

        return {

            "service": self.service_name,

            "feed_count": self.feed_count,

            "loaded_at":
                self.loaded_at.isoformat()
                if self.loaded_at
                else None,

            "ioc_count":
                len(self.iocs),

            "cache_size":
                len(self.lookup_cache),

            **self.stats_data,
        }

    ####################################################################
    # Health
    ####################################################################

    def health(self) -> dict[str, Any]:

        return {

            "service":
                self.service_name,

            "status":
                "healthy",

            "feeds":
                self.feed_count,

            "loaded":
                len(self.iocs),

            "cache":
                len(self.lookup_cache),

            "initialized":
                self.initialized_at.isoformat(),

            "last_refresh":
                self.loaded_at.isoformat()
                if self.loaded_at
                else None,
        }

    ####################################################################
    # Cache
    ####################################################################

    def clear_cache(self) -> None:

        self.lookup_cache.clear()

    ####################################################################
    # Clear Database
    ####################################################################

    def clear(self) -> None:

        self.iocs.clear()

        self.ip_index.clear()

        self.domain_index.clear()

        self.url_index.clear()

        self.sha256_index.clear()

        self.sha1_index.clear()

        self.md5_index.clear()

        self.email_index.clear()

        self.registry_index.clear()

        self.process_index.clear()

        self.mutex_index.clear()

        self.networks.clear()

        self.lookup_cache.clear()

    ####################################################################
    # Refresh
    ####################################################################

    def refresh(self) -> None:

        self.logger.info(
            "Refreshing IOC feeds..."
        )

        self.clear()

        self.load_all_feeds()

    ####################################################################
    # Async Refresh
    ####################################################################

    async def async_refresh(self) -> None:

        loop = asyncio.get_running_loop()

        await loop.run_in_executor(
            None,
            self.refresh,
        )

    ####################################################################
    # Export JSON
    ####################################################################

    def export_json(
        self,
        path: str | Path,
    ) -> None:

        path = Path(path)

        output = [

            ioc.model_dump(
                mode="json",
            )

            for ioc in self.iocs

        ]

        with open(
            path,
            "w",
            encoding="utf-8",
        ) as fp:

            json.dump(

                output,

                fp,

                indent=4,

                ensure_ascii=False,
            )

    ####################################################################
    # Import JSON
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

            rows = json.load(fp)

        for row in rows:

            self.add_ioc(row)

    ####################################################################
    # SHA256 Helper
    ####################################################################

    @staticmethod
    def sha256(
        data: bytes,
    ) -> str:

        return hashlib.sha256(
            data,
        ).hexdigest()

    ####################################################################
    # MD5 Helper
    ####################################################################

    @staticmethod
    def md5(
        data: bytes,
    ) -> str:

        return hashlib.md5(
            data,
        ).hexdigest()

    ####################################################################
    # SHA1 Helper
    ####################################################################

    @staticmethod
    def sha1(
        data: bytes,
    ) -> str:

        return hashlib.sha1(
            data,
        ).hexdigest()

    ####################################################################
    # Process
    ####################################################################

    def process(
        self,
        indicators: list[str],
    ) -> list[IOCMatch]:

        return self.lookup_many(
            indicators,
        )

    ####################################################################
    # Shutdown
    ####################################################################

    def shutdown(self) -> None:

        self.logger.info(
            "Stopping IOC service..."
        )

        self.clear_cache()

        super().shutdown()

    ####################################################################
    # String Representation
    ####################################################################

    def __len__(self) -> int:

        return len(
            self.iocs,
        )

    def __contains__(
        self,
        indicator: str,
    ) -> bool:

        return self.contains(
            indicator,
        )

    def __repr__(self) -> str:

        return (
            f"<IOCService "
            f"feeds={self.feed_count} "
            f"iocs={len(self.iocs)}>"
        )