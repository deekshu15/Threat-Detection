"""
Enterprise CVE Service

Provides CVE enrichment for Threat Events.

Features
--------
• NVD JSON Feed Loading
• CVSS v2/v3/v4 Support
• EPSS Support
• CISA KEV Support
• CPE Matching
• Vendor/Product Indexing
• O(1) CVE Lookup
• Statistics
• Async Refresh
• Health Monitoring

Python 3.11+
"""

from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any

from ..exceptions import CVELoadError
from ..logger import get_logger
from ..models.cve import (
    CVEModel,
    CVSSMetrics,
)
from .base_service import BaseService


class CVEService(BaseService):

    service_name = "CVEService"

    ####################################################################
    # Initialization
    ####################################################################

    def __init__(
        self,
        feed_directory: str | Path | None = None,
    ) -> None:

        super().__init__()

        self.logger = get_logger("CVEService")

        self.lock = Lock()

        self.feed_directory = (
            Path(feed_directory)
            if feed_directory
            else Path("data/cve")
        )

        ################################################################
        # Storage
        ################################################################

        self.cves: list[CVEModel] = []

        ################################################################
        # Fast Indexes
        ################################################################

        self.cve_index: dict[str, CVEModel] = {}

        self.vendor_index: defaultdict[
            str,
            list[CVEModel],
        ] = defaultdict(list)

        self.product_index: defaultdict[
            str,
            list[CVEModel],
        ] = defaultdict(list)

        self.cpe_index: defaultdict[
            str,
            list[CVEModel],
        ] = defaultdict(list)

        self.cwe_index: defaultdict[
            str,
            list[CVEModel],
        ] = defaultdict(list)

        ################################################################
        # Metadata
        ################################################################

        self.loaded_at = None

        self.feed_count = 0

        ################################################################
        # Cache
        ################################################################

        self.lookup_cache: dict[
            str,
            CVEModel | None,
        ] = {}

        ################################################################
        # Statistics
        ################################################################

        self.stats_data = {

            "loaded": 0,

            "lookups": 0,

            "hits": 0,

            "misses": 0,

            "vendors": 0,

            "products": 0,

            "cpes": 0,

            "cwes": 0,
        }

    ####################################################################
    # Initialize
    ####################################################################

    def initialize(self) -> None:

        super().initialize()

        self.load_all_feeds()

    ####################################################################
    # Feed Discovery
    ####################################################################

    def discover_feeds(self) -> list[Path]:

        if not self.feed_directory.exists():

            return []

        feeds = sorted(

            self.feed_directory.glob(
                "*.json"
            )

        )

        self.feed_count = len(feeds)

        return feeds

    ####################################################################
    # Load All
    ####################################################################

    def load_all_feeds(self) -> None:

        feeds = self.discover_feeds()

        self.logger.info(

            "Loading %d CVE feeds",

            len(feeds),

        )

        for feed in feeds:

            try:

                self.load_feed(feed)

            except Exception as exc:

                self.logger.exception(exc)

        self.loaded_at = datetime.now(
            UTC
        )

    ####################################################################
    # Feed Loader
    ####################################################################

    def load_feed(
        self,
        path: Path,
    ) -> None:

        with open(
            path,
            encoding="utf-8",
        ) as fp:

            data = json.load(fp)

        vulnerabilities = data.get(
            "vulnerabilities",
            [],
        )

        for row in vulnerabilities:

            self.add_cve(row)

    ####################################################################
    # Add CVE
    ####################################################################

    def add_cve(
        self,
        data: dict[str, Any] | CVEModel,
    ) -> CVEModel:

        if isinstance(
            data,
            CVEModel,
        ):

            cve = data

        else:

            cve = self.normalize_cve(
                data,
            )

        if cve.cve_id in self.cve_index:

            return self.cve_index[
                cve.cve_id
            ]

        self.cves.append(cve)

        self.cve_index[
            cve.cve_id
        ] = cve

        self.index_cve(cve)

        self.stats_data[
            "loaded"
        ] += 1

        return cve
        ####################################################################
    # Normalize CVE
    ####################################################################

    def normalize_cve(
        self,
        data: dict[str, Any],
    ) -> CVEModel:

        cve = data.get("cve", data)

        metrics = self.parse_cvss(
            cve.get("metrics", {})
        )

        descriptions = cve.get(
            "descriptions",
            [],
        )

        description = ""

        for item in descriptions:

            if item.get("lang") == "en":

                description = item.get(
                    "value",
                    "",
                )

                break

        references = [

            r.get("url")

            for r in cve.get(
                "references",
                []
            )

            if r.get("url")

        ]

        weaknesses = self.extract_cwes(cve)

        cpes = self.extract_cpes(data)

        vendors = self.extract_vendors(cpes)

        products = self.extract_products(cpes)

        return CVEModel(

            cve_id=cve["id"],

            description=description,

            cvss=metrics,

            cpes=cpes,

            vendors=vendors,

            products=products,

            cwes=weaknesses,

            references=references,

            published=cve.get(
                "published",
            ),

            last_modified=cve.get(
                "lastModified",
            ),
        )

    ####################################################################
    # Parse CVSS
    ####################################################################

    def parse_cvss(
        self,
        metrics: dict[str, Any],
    ) -> CVSSMetrics:

        for key in (

            "cvssMetricV40",

            "cvssMetricV31",

            "cvssMetricV30",

            "cvssMetricV2",

        ):

            if key not in metrics:

                continue

            values = metrics[key]

            if not values:

                continue

            metric = values[0]

            data = metric.get(
                "cvssData",
                {},
            )

            return CVSSMetrics(

                version=data.get(
                    "version",
                ),

                base_score=data.get(
                    "baseScore",
                    0,
                ),

                base_severity=data.get(
                    "baseSeverity",
                ),

                vector=data.get(
                    "vectorString",
                ),

                attack_vector=data.get(
                    "attackVector",
                ),

                attack_complexity=data.get(
                    "attackComplexity",
                ),

                privileges_required=data.get(
                    "privilegesRequired",
                ),

                user_interaction=data.get(
                    "userInteraction",
                ),

                scope=data.get(
                    "scope",
                ),

                confidentiality=data.get(
                    "confidentialityImpact",
                ),

                integrity=data.get(
                    "integrityImpact",
                ),

                availability=data.get(
                    "availabilityImpact",
                ),
            )

        return CVSSMetrics()

    ####################################################################
    # Extract CWE
    ####################################################################

    def extract_cwes(
        self,
        cve: dict[str, Any],
    ) -> list[str]:

        result = []

        weaknesses = cve.get(
            "weaknesses",
            [],
        )

        for weakness in weaknesses:

            for desc in weakness.get(
                "description",
                [],
            ):

                value = desc.get("value")

                if value:

                    result.append(value)

        return sorted(
            set(result)
        )

    ####################################################################
    # Extract CPE
    ####################################################################

    def extract_cpes(
        self,
        raw: dict[str, Any],
    ) -> list[str]:

        output = []

        configurations = raw.get(
            "configurations",
            [],
        )

        for config in configurations:

            for node in config.get(
                "nodes",
                [],
            ):

                for match in node.get(
                    "cpeMatch",
                    [],
                ):

                    cpe = match.get(
                        "criteria"
                    )

                    if cpe:

                        output.append(cpe)

        return sorted(
            set(output)
        )

    ####################################################################
    # Vendors
    ####################################################################

    def extract_vendors(
        self,
        cpes: list[str],
    ) -> list[str]:

        vendors = []

        for cpe in cpes:

            parts = cpe.split(":")

            if len(parts) > 3:

                vendors.append(
                    parts[3]
                )

        return sorted(
            set(vendors)
        )

    ####################################################################
    # Products
    ####################################################################

    def extract_products(
        self,
        cpes: list[str],
    ) -> list[str]:

        products = []

        for cpe in cpes:

            parts = cpe.split(":")

            if len(parts) > 4:

                products.append(
                    parts[4]
                )

        return sorted(
            set(products)
        )

    ####################################################################
    # Build Indexes
    ####################################################################

    def index_cve(
        self,
        cve: CVEModel,
    ) -> None:

        for vendor in cve.vendors:

            self.vendor_index[
                vendor
            ].append(cve)

        for product in cve.products:

            self.product_index[
                product
            ].append(cve)

        for cpe in cve.cpes:

            self.cpe_index[
                cpe
            ].append(cve)

        for cwe in cve.cwes:

            self.cwe_index[
                cwe
            ].append(cve)

        self.stats_data[
            "vendors"
        ] = len(
            self.vendor_index
        )

        self.stats_data[
            "products"
        ] = len(
            self.product_index
        )

        self.stats_data[
            "cpes"
        ] = len(
            self.cpe_index
        )

        self.stats_data[
            "cwes"
        ] = len(
            self.cwe_index
        )
        ####################################################################
    # CVE Lookup
    ####################################################################

    def lookup_cve(
        self,
        cve_id: str,
    ) -> CVEModel | None:

        if not cve_id:
            return None

        cve_id = cve_id.upper().strip()

        self.stats_data["lookups"] += 1

        cached = self.lookup_cache.get(cve_id)

        if cached is not None:

            self.stats_data["hits"] += 1

            return cached

        result = self.cve_index.get(cve_id)

        if result:

            self.stats_data["hits"] += 1

        else:

            self.stats_data["misses"] += 1

        self.lookup_cache[cve_id] = result

        return result

    ####################################################################
    # Vendor Lookup
    ####################################################################

    def lookup_vendor(
        self,
        vendor: str,
    ) -> list[CVEModel]:

        if not vendor:

            return []

        return self.vendor_index.get(
            vendor.lower(),
            [],
        )

    ####################################################################
    # Product Lookup
    ####################################################################

    def lookup_product(
        self,
        product: str,
    ) -> list[CVEModel]:

        if not product:

            return []

        return self.product_index.get(
            product.lower(),
            [],
        )

    ####################################################################
    # CPE Lookup
    ####################################################################

    def lookup_cpe(
        self,
        cpe: str,
    ) -> list[CVEModel]:

        if not cpe:

            return []

        return self.cpe_index.get(
            cpe,
            [],
        )

    ####################################################################
    # CWE Lookup
    ####################################################################

    def lookup_cwe(
        self,
        cwe: str,
    ) -> list[CVEModel]:

        if not cwe:

            return []

        return self.cwe_index.get(
            cwe.upper(),
            [],
        )

    ####################################################################
    # Batch Lookup
    ####################################################################

    def lookup_many(
        self,
        cves: list[str],
    ) -> list[CVEModel]:

        results = []

        for cve in cves:

            result = self.lookup_cve(cve)

            if result:

                results.append(result)

        return results

    ####################################################################
    # Exists
    ####################################################################

    def exists(
        self,
        cve_id: str,
    ) -> bool:

        return self.lookup_cve(cve_id) is not None

    ####################################################################
    # Critical CVEs
    ####################################################################

    def critical_cves(self) -> list[CVEModel]:

        return [

            cve

            for cve in self.cves

            if cve.cvss.base_score >= 9.0

        ]

    ####################################################################
    # High Severity
    ####################################################################

    def high_cves(self) -> list[CVEModel]:

        return [

            cve

            for cve in self.cves

            if cve.cvss.base_score >= 7.0

        ]

    ####################################################################
    # Medium Severity
    ####################################################################

    def medium_cves(self) -> list[CVEModel]:

        return [

            cve

            for cve in self.cves

            if 4.0 <= cve.cvss.base_score < 7.0

        ]

    ####################################################################
    # Low Severity
    ####################################################################

    def low_cves(self) -> list[CVEModel]:

        return [

            cve

            for cve in self.cves

            if cve.cvss.base_score < 4.0

        ]

    ####################################################################
    # Filter by Score
    ####################################################################

    def score_range(
        self,
        minimum: float,
        maximum: float,
    ) -> list[CVEModel]:

        return [

            cve

            for cve in self.cves

            if minimum <= cve.cvss.base_score <= maximum

        ]

    ####################################################################
    # Latest CVEs
    ####################################################################

    def latest(
        self,
        limit: int = 20,
    ) -> list[CVEModel]:

        return sorted(

            self.cves,

            key=lambda x: (
                x.last_modified
                or ""
            ),

            reverse=True,

        )[:limit]

    ####################################################################
    # Highest Score
    ####################################################################

    def highest_score(
        self,
        limit: int = 20,
    ) -> list[CVEModel]:

        return sorted(

            self.cves,

            key=lambda x: (
                x.cvss.base_score
            ),

            reverse=True,

        )[:limit]

    ####################################################################
    # Count
    ####################################################################

    def count(self) -> int:

        return len(self.cves)

    ####################################################################
    # Contains
    ####################################################################

    def __contains__(
        self,
        cve_id: str,
    ) -> bool:

        return self.exists(cve_id)

    ####################################################################
    # Length
    ####################################################################

    def __len__(self):

        return len(self.cves)
        ####################################################################
    # EPSS Support
    ####################################################################

    def epss_score(
        self,
        cve: CVEModel,
    ) -> float:

        """
        Placeholder for EPSS integration.
        Returns 0.0 until EPSS dataset is loaded.
        """

        return getattr(
            cve,
            "epss",
            0.0,
        )

    ####################################################################
    # Known Exploited Vulnerability
    ####################################################################

    def is_known_exploited(
        self,
        cve: CVEModel,
    ) -> bool:

        return bool(
            getattr(
                cve,
                "kev",
                False,
            )
        )

    ####################################################################
    # Risk Score
    ####################################################################

    def calculate_risk_score(
        self,
        cve: CVEModel,
    ) -> float:

        score = cve.cvss.base_score

        epss = self.epss_score(cve)

        kev_bonus = 2.0 if self.is_known_exploited(cve) else 0.0

        risk = score + (epss * 10) + kev_bonus

        return round(
            min(risk, 10.0),
            2,
        )

    ####################################################################
    # Prioritize CVEs
    ####################################################################

    def prioritize(
        self,
        cves: list[CVEModel],
    ) -> list[CVEModel]:

        return sorted(

            cves,

            key=lambda x: self.calculate_risk_score(x),

            reverse=True,
        )

    ####################################################################
    # Top Risk
    ####################################################################

    def top_risk(
        self,
        limit: int = 20,
    ) -> list[CVEModel]:

        return self.prioritize(
            self.cves,
        )[:limit]

    ####################################################################
    # Clear Cache
    ####################################################################

    def clear_cache(self) -> None:

        self.lookup_cache.clear()

    ####################################################################
    # Clear Database
    ####################################################################

    def clear(self) -> None:

        self.cves.clear()

        self.cve_index.clear()

        self.vendor_index.clear()

        self.product_index.clear()

        self.cpe_index.clear()

        self.cwe_index.clear()

        self.lookup_cache.clear()

    ####################################################################
    # Refresh
    ####################################################################

    def refresh(self) -> None:

        self.logger.info(
            "Refreshing CVE database..."
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
    # Export
    ####################################################################

    def export_json(
        self,
        path: str | Path,
    ) -> None:

        path = Path(path)

        with open(
            path,
            "w",
            encoding="utf-8",
        ) as fp:

            json.dump(

                [

                    c.model_dump(
                        mode="json",
                    )

                    for c in self.cves

                ],

                fp,

                indent=4,

                ensure_ascii=False,
            )

    ####################################################################
    # Import
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

            self.add_cve(row)

    ####################################################################
    # Statistics
    ####################################################################

    def stats(
        self,
    ) -> dict[str, Any]:

        return {

            "service":
                self.service_name,

            "loaded":
                len(self.cves),

            "feeds":
                self.feed_count,

            "cache":
                len(self.lookup_cache),

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

            "feed_count":
                self.feed_count,

            "cve_count":
                len(self.cves),

            "cache":
                len(self.lookup_cache),

            "loaded_at":
                self.loaded_at.isoformat()
                if self.loaded_at
                else None,
        }

    ####################################################################
    # Process
    ####################################################################

    def process(
        self,
        cve_ids: list[str],
    ) -> list[CVEModel]:

        return self.lookup_many(
            cve_ids,
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
    # Representation
    ####################################################################

    def __repr__(
        self,
    ) -> str:

        return (
            f"<CVEService "
            f"count={len(self.cves)}>"
        )
    