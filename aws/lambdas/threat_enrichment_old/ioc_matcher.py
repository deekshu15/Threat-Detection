"""
IOC Matcher

Matches Indicators of Compromise (IOCs) against incoming
security events.

Responsibilities
----------------
- Match malicious IPs
- Match malicious domains
- Match malicious URLs
- Match file hashes
- Calculate IOC confidence
- Return IOC enrichment

Author: AI Threat Detection Dashboard
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

import pandas as pd

logger = logging.getLogger(__name__)


# ---------------------------------------------------------
# IOC Match Result
# ---------------------------------------------------------

@dataclass(slots=True)
class IOCMatch:

    matched_ioc: bool = False

    ioc_type: Optional[str] = None

    ioc_value: Optional[str] = None

    ioc_source: Optional[str] = None

    ioc_confidence: float = 0.0

    threat_level: str = "Unknown"

    description: Optional[str] = None

    metadata: Optional[dict] = None


# ---------------------------------------------------------
# IOC Matcher
# ---------------------------------------------------------

class IOCMatcher:
    """
    Production IOC matcher.

    Loads threat intelligence feeds once and performs
    in-memory lookups for high performance.
    """

    def __init__(
        self,
        threat_feed_path: Optional[str] = None,
    ):

        self.threat_feed_path = threat_feed_path

        self.malicious_ips: Set[str] = set()

        self.malicious_domains: Set[str] = set()

        self.malicious_urls: Set[str] = set()

        self.malicious_hashes: Set[str] = set()

        self.feed_metadata: Dict = {}

        if threat_feed_path:

            self.load_feed(threat_feed_path)

    # -----------------------------------------------------
    # Feed Loading
    # -----------------------------------------------------

    def load_feed(
        self,
        file_path: str,
    ) -> None:

        path = Path(file_path)

        if not path.exists():

            logger.warning(
                "Threat feed not found: %s",
                file_path,
            )

            return

        logger.info(
            "Loading IOC feed %s",
            file_path,
        )

        if path.suffix == ".csv":

            df = pd.read_csv(path)

        elif path.suffix == ".parquet":

            df = pd.read_parquet(path)

        else:

            raise ValueError(
                "Unsupported threat feed format."
            )

        self._parse_feed(df)

        logger.info(
            "IOC feed loaded successfully."
        )

    # -----------------------------------------------------
    # Feed Parsing
    # -----------------------------------------------------

    def _parse_feed(
        self,
        df: pd.DataFrame,
    ) -> None:

        columns = {
            c.lower(): c
            for c in df.columns
        }

        if "ip" in columns:

            self.malicious_ips.update(

                str(ip).strip()

                for ip in df[columns["ip"]]

                if pd.notna(ip)

            )

        if "domain" in columns:

            self.malicious_domains.update(

                str(domain).lower().strip()

                for domain in df[columns["domain"]]

                if pd.notna(domain)

            )

        if "url" in columns:

            self.malicious_urls.update(

                str(url).lower().strip()

                for url in df[columns["url"]]

                if pd.notna(url)

            )

        if "hash" in columns:

            self.malicious_hashes.update(

                str(hash_value).lower().strip()

                for hash_value in df[columns["hash"]]

                if pd.notna(hash_value)

            )

        self.feed_metadata = {

            "records": len(df),

            "columns": list(df.columns),
        }

    # -----------------------------------------------------
    # Public Match Function
    # -----------------------------------------------------

    def match_event(
        self,
        event: Dict,
    ) -> IOCMatch:

        ip_match = self._match_ip(
            event
        )

        if ip_match.matched_ioc:

            return ip_match

        domain_match = self._match_domain(
            event
        )

        if domain_match.matched_ioc:

            return domain_match

        url_match = self._match_url(
            event
        )

        if url_match.matched_ioc:

            return url_match

        hash_match = self._match_hash(
            event
        )

        if hash_match.matched_ioc:

            return hash_match

        return IOCMatch(
            matched_ioc=False
        )
            # -----------------------------------------------------
    # IP Matching
    # -----------------------------------------------------

    def _match_ip(
        self,
        event: Dict,
    ) -> IOCMatch:

        for field in ("src_ip", "dest_ip"):

            ip = event.get(field)

            if not ip:
                continue

            try:
                ipaddress.ip_address(str(ip))
            except ValueError:
                continue

            if str(ip) in self.malicious_ips:

                logger.info(
                    "Matched malicious IP %s",
                    ip,
                )

                return IOCMatch(
                    matched_ioc=True,
                    ioc_type="IP",
                    ioc_value=str(ip),
                    ioc_source="Threat Feed",
                    ioc_confidence=1.0,
                    threat_level="High",
                    description="Known malicious IP address",
                    metadata={
                        "matched_field": field
                    },
                )

        return IOCMatch()

    # -----------------------------------------------------
    # Domain Matching
    # -----------------------------------------------------

    def _match_domain(
        self,
        event: Dict,
    ) -> IOCMatch:

        domains = []

        for key in (
            "domain",
            "hostname",
            "dns_query",
            "url_host",
        ):

            value = event.get(key)

            if value:
                domains.append(
                    str(value)
                    .lower()
                    .strip()
                )

        for domain in domains:

            if domain in self.malicious_domains:

                logger.info(
                    "Matched malicious domain %s",
                    domain,
                )

                return IOCMatch(
                    matched_ioc=True,
                    ioc_type="DOMAIN",
                    ioc_value=domain,
                    ioc_source="Threat Feed",
                    ioc_confidence=0.98,
                    threat_level="High",
                    description="Known malicious domain",
                )

        return IOCMatch()

    # -----------------------------------------------------
    # URL Matching
    # -----------------------------------------------------

    def _match_url(
        self,
        event: Dict,
    ) -> IOCMatch:

        url = event.get("url")

        if not url:
            return IOCMatch()

        url = str(url).lower().strip()

        if url in self.malicious_urls:

            logger.info(
                "Matched malicious URL %s",
                url,
            )

            return IOCMatch(
                matched_ioc=True,
                ioc_type="URL",
                ioc_value=url,
                ioc_source="Threat Feed",
                ioc_confidence=0.99,
                threat_level="Critical",
                description="Known malicious URL",
            )

        return IOCMatch()

    # -----------------------------------------------------
    # Hash Matching
    # -----------------------------------------------------

    def _match_hash(
        self,
        event: Dict,
    ) -> IOCMatch:

        for field in (
            "md5",
            "sha1",
            "sha256",
            "file_hash",
        ):

            value = event.get(field)

            if not value:
                continue

            hash_value = (
                str(value)
                .lower()
                .strip()
            )

            if hash_value in self.malicious_hashes:

                logger.info(
                    "Matched malicious hash %s",
                    hash_value,
                )

                return IOCMatch(
                    matched_ioc=True,
                    ioc_type="HASH",
                    ioc_value=hash_value,
                    ioc_source="Threat Feed",
                    ioc_confidence=1.0,
                    threat_level="Critical",
                    description="Known malicious file hash",
                    metadata={
                        "hash_algorithm": field
                    },
                )

        return IOCMatch()

    # -----------------------------------------------------
    # Batch Matching
    # -----------------------------------------------------

    def match_events(
        self,
        events: List[Dict],
    ) -> List[IOCMatch]:

        results: List[IOCMatch] = []

        logger.info(
            "Matching %d events against IOC feed...",
            len(events),
        )

        for event in events:

            results.append(
                self.match_event(event)
            )

        return results

    # -----------------------------------------------------
    # Feed Statistics
    # -----------------------------------------------------

    def statistics(self) -> Dict:

        return {

            "malicious_ips": len(
                self.malicious_ips
            ),

            "malicious_domains": len(
                self.malicious_domains
            ),

            "malicious_urls": len(
                self.malicious_urls
            ),

            "malicious_hashes": len(
                self.malicious_hashes
            ),

            "feed_metadata": self.feed_metadata,
        }


# ---------------------------------------------------------
# Global Matcher
# ---------------------------------------------------------

_default_matcher = IOCMatcher()


def match_event(
    event: Dict,
) -> IOCMatch:

    return _default_matcher.match_event(
        event
    )


def match_events(
    events: List[Dict],
) -> List[IOCMatch]:

    return _default_matcher.match_events(
        events
    )


# ---------------------------------------------------------
# Local Testing
# ---------------------------------------------------------

if __name__ == "__main__":

    logging.basicConfig(
        level=logging.INFO
    )

    matcher = IOCMatcher()

    matcher.malicious_ips.add(
        "192.168.1.10"
    )

    matcher.malicious_domains.add(
        "evil.example.com"
    )

    sample_event = {

        "src_ip": "192.168.1.10",

        "dest_ip": "10.0.0.2",

        "domain": "evil.example.com",

        "url": "https://evil.example.com",

        "sha256": "abcd1234"
    }

    result = matcher.match_event(
        sample_event
    )

    print(result)