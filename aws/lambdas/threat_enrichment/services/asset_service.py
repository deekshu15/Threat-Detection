"""
Enterprise Asset Service

Provides enterprise asset context enrichment.

Features
--------
• Asset Inventory
• CMDB Integration
• Business Criticality
• Ownership
• Environment
• Tags
• Asset Search
• Fast Indexes
• Asset Enrichment

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

from ..logger import get_logger

from ..models.asset import (
    AssetModel,
    AssetType,
    Criticality,
)

from .base_service import BaseService


class AssetService(BaseService):

    service_name = "AssetService"

    ####################################################################
    # Initialization
    ####################################################################

    def __init__(
        self,
        asset_directory: str | Path | None = None,
    ):

        super().__init__()

        self.logger = get_logger(
            "AssetService"
        )

        self.lock = Lock()

        self.asset_directory = (

            Path(asset_directory)

            if asset_directory

            else Path("data/assets")

        )

        ###############################################################
        # Storage
        ###############################################################

        self.assets: list[AssetModel] = []

        ###############################################################
        # Fast Indexes
        ###############################################################

        self.hostname_index: dict[
            str,
            AssetModel,
        ] = {}

        self.ip_index: dict[
            str,
            AssetModel,
        ] = {}

        self.owner_index = defaultdict(list)

        self.department_index = defaultdict(list)

        self.environment_index = defaultdict(list)

        self.type_index = defaultdict(list)

        self.tag_index = defaultdict(list)

        ###############################################################
        # Cache
        ###############################################################

        self.lookup_cache = {}

        ###############################################################
        # Metadata
        ###############################################################

        self.loaded_at = None

        self.feed_count = 0

        ###############################################################
        # Statistics
        ###############################################################

        self.stats_data = {

            "assets": 0,

            "lookups": 0,

            "hits": 0,

            "misses": 0,

            "owners": 0,

            "departments": 0,

            "environments": 0,

            "tags": 0,
        }

    ####################################################################
    # Initialize
    ####################################################################

    def initialize(self):

        super().initialize()

        self.load_assets()

    ####################################################################
    # Feed Discovery
    ####################################################################

    def discover_files(self):

        if not self.asset_directory.exists():

            return []

        return sorted(

            self.asset_directory.glob(
                "*.json"
            )

        )

    ####################################################################
    # Load Assets
    ####################################################################

    def load_assets(self):

        files = self.discover_files()

        self.feed_count = len(files)

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

        if isinstance(
            data,
            dict,
        ):

            rows = data.get(
                "assets",
                [],
            )

        else:

            rows = data

        for row in rows:

            self.add_asset(row)

    ####################################################################
    # Add Asset
    ####################################################################

    def add_asset(
        self,
        asset: AssetModel | dict[str, Any],
    ):

        if isinstance(
            asset,
            dict,
        ):

            asset = AssetModel(
                **asset
            )

        hostname = (
            asset.hostname
            .lower()
            .strip()
        )

        self.assets.append(
            asset
        )

        self.hostname_index[
            hostname
        ] = asset

        if asset.ip_address:

            self.ip_index[
                asset.ip_address
            ] = asset

        if asset.owner:

            self.owner_index[
                asset.owner.lower()
            ].append(asset)

        if asset.department:

            self.department_index[
                asset.department.lower()
            ].append(asset)

        if asset.environment:

            self.environment_index[
                asset.environment.lower()
            ].append(asset)

        self.type_index[
            asset.asset_type
        ].append(asset)

        for tag in asset.tags:

            self.tag_index[
                tag.lower()
            ].append(asset)

        self.stats_data[
            "assets"
        ] += 1

        self.stats_data[
            "owners"
        ] = len(
            self.owner_index
        )

        self.stats_data[
            "departments"
        ] = len(
            self.department_index
        )

        self.stats_data[
            "environments"
        ] = len(
            self.environment_index
        )

        self.stats_data[
            "tags"
        ] = len(
            self.tag_index
        )
        ####################################################################
    # Lookup by Hostname
    ####################################################################

    def lookup_hostname(
        self,
        hostname: str,
    ) -> AssetModel | None:

        if not hostname:
            return None

        hostname = hostname.lower().strip()

        self.stats_data["lookups"] += 1

        cached = self.lookup_cache.get(
            hostname
        )

        if cached is not None:

            self.stats_data["hits"] += 1

            return cached

        asset = self.hostname_index.get(
            hostname
        )

        if asset:

            self.stats_data["hits"] += 1

        else:

            self.stats_data["misses"] += 1

        self.lookup_cache[
            hostname
        ] = asset

        return asset

    ####################################################################
    # Lookup by IP
    ####################################################################

    def lookup_ip(
        self,
        ip: str,
    ) -> AssetModel | None:

        if not ip:
            return None

        self.stats_data["lookups"] += 1

        cached = self.lookup_cache.get(ip)

        if cached is not None:

            self.stats_data["hits"] += 1

            return cached

        asset = self.ip_index.get(ip)

        if asset:

            self.stats_data["hits"] += 1

        else:

            self.stats_data["misses"] += 1

        self.lookup_cache[ip] = asset

        return asset

    ####################################################################
    # Lookup Owner
    ####################################################################

    def lookup_owner(
        self,
        owner: str,
    ) -> list[AssetModel]:

        if not owner:
            return []

        return self.owner_index.get(
            owner.lower(),
            [],
        )

    ####################################################################
    # Lookup Department
    ####################################################################

    def lookup_department(
        self,
        department: str,
    ) -> list[AssetModel]:

        if not department:
            return []

        return self.department_index.get(
            department.lower(),
            [],
        )

    ####################################################################
    # Lookup Environment
    ####################################################################

    def lookup_environment(
        self,
        environment: str,
    ) -> list[AssetModel]:

        if not environment:
            return []

        return self.environment_index.get(
            environment.lower(),
            [],
        )

    ####################################################################
    # Lookup Asset Type
    ####################################################################

    def lookup_type(
        self,
        asset_type: AssetType,
    ) -> list[AssetModel]:

        return self.type_index.get(
            asset_type,
            [],
        )

    ####################################################################
    # Lookup Tag
    ####################################################################

    def lookup_tag(
        self,
        tag: str,
    ) -> list[AssetModel]:

        if not tag:
            return []

        return self.tag_index.get(
            tag.lower(),
            [],
        )

    ####################################################################
    # Critical Assets
    ####################################################################

    def critical_assets(
        self,
    ) -> list[AssetModel]:

        return [

            asset

            for asset in self.assets

            if asset.criticality
            == Criticality.CRITICAL

        ]

    ####################################################################
    # High Value Assets
    ####################################################################

    def high_assets(
        self,
    ) -> list[AssetModel]:

        return [

            asset

            for asset in self.assets

            if asset.criticality
            == Criticality.HIGH

        ]

    ####################################################################
    # Production Assets
    ####################################################################

    def production_assets(
        self,
    ) -> list[AssetModel]:

        return [

            asset

            for asset in self.assets

            if asset.production

        ]

    ####################################################################
    # Internet Facing Assets
    ####################################################################

    def internet_facing_assets(
        self,
    ) -> list[AssetModel]:

        return [

            asset

            for asset in self.assets

            if asset.internet_facing

        ]

    ####################################################################
    # Internal Assets
    ####################################################################

    def internal_assets(
        self,
    ) -> list[AssetModel]:

        return [

            asset

            for asset in self.assets

            if not asset.internet_facing

        ]

    ####################################################################
    # Exists
    ####################################################################

    def exists(
        self,
        hostname: str,
    ) -> bool:

        return (
            self.lookup_hostname(
                hostname
            )
            is not None
        )

    ####################################################################
    # Count
    ####################################################################

    def count(
        self,
    ) -> int:

        return len(self.assets)

    ####################################################################
    # Contains
    ####################################################################

    def __contains__(
        self,
        hostname: str,
    ) -> bool:

        return self.exists(hostname)

    ####################################################################
    # Length
    ####################################################################

    def __len__(
        self,
    ) -> int:

        return len(self.assets)
        ####################################################################
    # Search Assets
    ####################################################################

    def search(
        self,
        keyword: str,
    ) -> list[AssetModel]:

        if not keyword:
            return []

        keyword = keyword.lower()

        results = []

        for asset in self.assets:

            fields = [

                asset.hostname or "",
                asset.owner or "",
                asset.department or "",
                asset.environment or "",
                asset.operating_system or "",
                asset.asset_type.value,

            ]

            fields.extend(asset.tags)

            if any(
                keyword in str(field).lower()
                for field in fields
            ):
                results.append(asset)

        return results

    ####################################################################
    # Business Criticality Score
    ####################################################################

    def business_score(
        self,
        asset: AssetModel,
    ) -> float:

        score = 0.0

        criticality_scores = {

            Criticality.CRITICAL: 10.0,
            Criticality.HIGH: 8.0,
            Criticality.MEDIUM: 5.0,
            Criticality.LOW: 2.0,

        }

        score += criticality_scores.get(
            asset.criticality,
            1.0,
        )

        if asset.production:
            score += 2.0

        if asset.internet_facing:
            score += 2.0

        if asset.asset_type in {

            AssetType.SERVER,
            AssetType.DOMAIN_CONTROLLER,
            AssetType.DATABASE,

        }:
            score += 1.5

        return round(
            min(score, 10.0),
            2,
        )

    ####################################################################
    # Threat Context
    ####################################################################

    def threat_context(
        self,
        asset: AssetModel,
    ) -> dict[str, Any]:

        return {

            "hostname":
                asset.hostname,

            "owner":
                asset.owner,

            "department":
                asset.department,

            "environment":
                asset.environment,

            "criticality":
                asset.criticality.value,

            "business_score":
                self.business_score(asset),

            "internet_facing":
                asset.internet_facing,

            "production":
                asset.production,

            "asset_type":
                asset.asset_type.value,

            "tags":
                asset.tags,
        }

    ####################################################################
    # Risk Score
    ####################################################################

    def calculate_risk(
        self,
        asset: AssetModel,
        threat_score: float,
    ) -> float:

        business = self.business_score(asset)

        risk = (

            threat_score * 0.7

            +

            business * 0.3

        )

        return round(
            min(risk, 10.0),
            2,
        )

    ####################################################################
    # Enrich Asset
    ####################################################################

    def enrich_asset(
        self,
        asset: AssetModel,
    ) -> dict[str, Any]:

        return {

            "asset": asset,

            "context": self.threat_context(
                asset
            ),

            "business_score":
                self.business_score(asset),
        }

    ####################################################################
    # Enrich by Hostname
    ####################################################################

    def enrich_hostname(
        self,
        hostname: str,
    ) -> dict[str, Any] | None:

        asset = self.lookup_hostname(
            hostname
        )

        if asset is None:
            return None

        return self.enrich_asset(
            asset
        )

    ####################################################################
    # Batch Enrichment
    ####################################################################

    def enrich_many(
        self,
        hostnames: list[str],
    ) -> list[dict[str, Any]]:

        enriched = []

        for hostname in hostnames:

            result = self.enrich_hostname(
                hostname
            )

            if result:

                enriched.append(result)

        return enriched

    ####################################################################
    # Event Enrichment
    ####################################################################

    def enrich_event(
        self,
        event,
    ):

        if event.asset is None:

            return event

        hostname = getattr(
            event.asset,
            "hostname",
            None,
        )

        if not hostname:

            return event

        asset = self.lookup_hostname(
            hostname
        )

        if asset:

            event.asset = asset

        return event

    ####################################################################
    # Asset Summary
    ####################################################################

    def summary(
        self,
        asset: AssetModel,
    ) -> dict[str, Any]:

        return {

            "hostname":
                asset.hostname,

            "owner":
                asset.owner,

            "criticality":
                asset.criticality.value,

            "environment":
                asset.environment,

            "internet":
                asset.internet_facing,

            "production":
                asset.production,

            "business_score":
                self.business_score(asset),
        }
        ####################################################################
    # Export Assets
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

                    asset.model_dump(
                        mode="json"
                    )

                    for asset in self.assets

                ],

                fp,

                indent=4,

                ensure_ascii=False,

            )

    ####################################################################
    # Import Assets
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

        if isinstance(rows, dict):

            rows = rows.get(
                "assets",
                [],
            )

        for row in rows:

            self.add_asset(row)

    ####################################################################
    # Statistics
    ####################################################################

    def stats(
        self,
    ) -> dict[str, Any]:

        return {

            "service":
                self.service_name,

            "asset_count":
                len(self.assets),

            "cache_size":
                len(self.lookup_cache),

            "loaded_at":
                self.loaded_at.isoformat()
                if self.loaded_at
                else None,

            "feed_count":
                self.feed_count,

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

            "assets":
                len(self.assets),

            "cache":
                len(self.lookup_cache),

            "hostname_index":
                len(self.hostname_index),

            "ip_index":
                len(self.ip_index),

            "owner_index":
                len(self.owner_index),

            "department_index":
                len(self.department_index),

            "loaded_at":
                self.loaded_at.isoformat()
                if self.loaded_at
                else None,

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

        self.assets.clear()

        self.hostname_index.clear()

        self.ip_index.clear()

        self.owner_index.clear()

        self.department_index.clear()

        self.environment_index.clear()

        self.type_index.clear()

        self.tag_index.clear()

        self.lookup_cache.clear()

    ####################################################################
    # Refresh
    ####################################################################

    def refresh(
        self,
    ) -> None:

        self.logger.info(
            "Refreshing Asset Database..."
        )

        self.clear()

        self.load_assets()

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
        hostnames: list[str],
    ) -> list[dict[str, Any]]:

        return self.enrich_many(
            hostnames
        )

    ####################################################################
    # Diagnostic Summary
    ####################################################################

    def diagnostics(
        self,
    ) -> dict[str, Any]:

        return {

            "hostname_index":
                len(self.hostname_index),

            "ip_index":
                len(self.ip_index),

            "owner_index":
                len(self.owner_index),

            "department_index":
                len(self.department_index),

            "environment_index":
                len(self.environment_index),

            "type_index":
                len(self.type_index),

            "tag_index":
                len(self.tag_index),

            "lookup_cache":
                len(self.lookup_cache),

        }

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

    def __iter__(
        self,
    ):

        return iter(
            self.assets
        )

    def __getitem__(
        self,
        index: int,
    ) -> AssetModel:

        return self.assets[index]

    def __repr__(
        self,
    ) -> str:

        return (

            f"<AssetService "

            f"assets={len(self.assets)} "

            f"owners={len(self.owner_index)} "

            f"environments={len(self.environment_index)}>"

        )
    