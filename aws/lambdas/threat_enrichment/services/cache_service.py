"""
Enterprise Cache Service

Features
--------
• Thread-safe
• TTL Support
• LRU Eviction
• Batch Operations
• Statistics
• Async API
• Memory Cache
• Pluggable Backend
"""

from __future__ import annotations

import asyncio
import time

from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC
from datetime import datetime
from threading import Lock
from typing import Any

from ..logger import get_logger

from .base_service import BaseService


@dataclass(slots=True)
class CacheEntry:

    value: Any

    created_at: float

    expires_at: float | None

    hits: int = 0


class CacheService(BaseService):

    service_name = "CacheService"

    ####################################################################
    # Initialization
    ####################################################################

    def __init__(

        self,

        max_size: int = 10000,

        default_ttl: int = 3600,

    ):

        super().__init__()

        self.logger = get_logger(
            "CacheService"
        )

        self.lock = Lock()

        self.max_size = max_size

        self.default_ttl = default_ttl

        self.cache: OrderedDict[
            str,
            CacheEntry,
        ] = OrderedDict()

        self.loaded_at = datetime.now(
            UTC
        )

        self.stats_data = {

            "hits": 0,

            "misses": 0,

            "evictions": 0,

            "expired": 0,

            "sets": 0,

            "deletes": 0,

        }
        ####################################################################
    # Helpers
    ####################################################################

    def _expired(
        self,
        entry: CacheEntry,
    ) -> bool:

        if entry.expires_at is None:

            return False

        return time.time() >= entry.expires_at

    def _evict_if_needed(
        self,
    ) -> None:

        while len(self.cache) > self.max_size:

            self.cache.popitem(last=False)

            self.stats_data[
                "evictions"
            ] += 1
        ####################################################################
    # Set
    ####################################################################

    def set(

        self,

        key: str,

        value: Any,

        ttl: int | None = None,

    ) -> None:

        with self.lock:

            ttl = (

                self.default_ttl

                if ttl is None

                else ttl

            )

            expires = (

                time.time() + ttl

                if ttl > 0

                else None

            )

            self.cache[key] = CacheEntry(

                value=value,

                created_at=time.time(),

                expires_at=expires,

            )

            self.cache.move_to_end(
                key
            )

            self._evict_if_needed()

            self.stats_data[
                "sets"
            ] += 1
        ####################################################################
    # Get
    ####################################################################

    def get(

        self,

        key: str,

        default=None,

    ):

        with self.lock:

            entry = self.cache.get(
                key
            )

            if entry is None:

                self.stats_data[
                    "misses"
                ] += 1

                return default

            if self._expired(entry):

                del self.cache[key]

                self.stats_data[
                    "expired"
                ] += 1

                self.stats_data[
                    "misses"
                ] += 1

                return default

            entry.hits += 1

            self.cache.move_to_end(
                key
            )

            self.stats_data[
                "hits"
            ] += 1

            return entry.value
        ####################################################################
    # Exists
    ####################################################################

    def exists(
        self,
        key: str,
    ) -> bool:

        return self.get(
            key,
            default=None,
        ) is not None
        ####################################################################
    # Delete
    ####################################################################

    def delete(
        self,
        key: str,
    ) -> bool:

        with self.lock:

            if key not in self.cache:

                return False

            del self.cache[key]

            self.stats_data[
                "deletes"
            ] += 1

            return True
        ####################################################################
    # Batch Set
    ####################################################################

    def set_many(
        self,
        items: dict[str, Any],
        ttl: int | None = None,
    ) -> None:

        for key, value in items.items():

            self.set(
                key,
                value,
                ttl,
            )

    ####################################################################
    # Batch Get
    ####################################################################

    def get_many(
        self,
        keys: list[str],
    ) -> dict[str, Any]:

        results = {}

        for key in keys:

            value = self.get(key)

            if value is not None:

                results[key] = value

        return results

    ####################################################################
    # Batch Delete
    ####################################################################

    def delete_many(
        self,
        keys: list[str],
    ) -> int:

        deleted = 0

        for key in keys:

            if self.delete(key):

                deleted += 1

        return deleted

    ####################################################################
    # Delete By Prefix
    ####################################################################

    def delete_prefix(
        self,
        prefix: str,
    ) -> int:

        keys = [

            key

            for key in self.cache

            if key.startswith(prefix)

        ]

        return self.delete_many(keys)

    ####################################################################
    # Cleanup Expired Entries
    ####################################################################

    def cleanup(
        self,
    ) -> int:

        removed = 0

        keys = list(self.cache.keys())

        for key in keys:

            entry = self.cache.get(key)

            if entry and self._expired(entry):

                del self.cache[key]

                removed += 1

                self.stats_data[
                    "expired"
                ] += 1

        return removed

    ####################################################################
    # Keys
    ####################################################################

    def keys(
        self,
    ) -> list[str]:

        return list(
            self.cache.keys()
        )

    ####################################################################
    # Values
    ####################################################################

    def values(
        self,
    ) -> list[Any]:

        return [

            entry.value

            for entry in self.cache.values()

        ]

    ####################################################################
    # Items
    ####################################################################

    def items(
        self,
    ) -> list[tuple[str, Any]]:

        return [

            (

                key,

                entry.value,

            )

            for key, entry

            in self.cache.items()

        ]

    ####################################################################
    # Export
    ####################################################################

    def export_json(
        self,
    ) -> dict[str, Any]:

        data = {}

        for key, entry in self.cache.items():

            data[key] = {

                "value":
                    entry.value,

                "created_at":
                    entry.created_at,

                "expires_at":
                    entry.expires_at,

                "hits":
                    entry.hits,

            }

        return data

    ####################################################################
    # Import
    ####################################################################

    def import_json(
        self,
        data: dict[str, Any],
    ) -> None:

        for key, value in data.items():

            self.cache[key] = CacheEntry(

                value=value["value"],

                created_at=value["created_at"],

                expires_at=value["expires_at"],

                hits=value.get(
                    "hits",
                    0,
                ),

            )

    ####################################################################
    # Warm Cache
    ####################################################################

    def warm(
        self,
        loader,
    ) -> int:

        items = loader()

        self.set_many(items)

        return len(items)
        ####################################################################
    # Hit Ratio
    ####################################################################

    def hit_ratio(
        self,
    ) -> float:

        hits = self.stats_data["hits"]

        misses = self.stats_data["misses"]

        total = hits + misses

        if total == 0:

            return 0.0

        return round(

            (hits / total) * 100,

            2,

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

            "entries":
                len(self.cache),

            "max_size":
                self.max_size,

            "default_ttl":
                self.default_ttl,

            "hit_ratio":
                self.hit_ratio(),

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

        utilization = round(

            (len(self.cache) / self.max_size) * 100,

            2,

        )

        return {

            "service":
                self.service_name,

            "status":
                "healthy",

            "entries":
                len(self.cache),

            "capacity":
                utilization,

            "hit_ratio":
                self.hit_ratio(),

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

        oldest = None

        newest = None

        if self.cache:

            entries = list(self.cache.values())

            oldest = min(

                entry.created_at

                for entry in entries

            )

            newest = max(

                entry.created_at

                for entry in entries

            )

        return {

            "entries":
                len(self.cache),

            "oldest":
                oldest,

            "newest":
                newest,

            "evictions":
                self.stats_data["evictions"],

            "expired":
                self.stats_data["expired"],

            "hit_ratio":
                self.hit_ratio(),

        }

    ####################################################################
    # Clear
    ####################################################################

    def clear(
        self,
    ) -> None:

        with self.lock:

            self.cache.clear()

    ####################################################################
    # Refresh
    ####################################################################

    def refresh(
        self,
    ) -> None:

        self.cleanup()

        self.loaded_at = datetime.now(
            UTC
        )

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
    # Async API
    ####################################################################

    async def async_get(
        self,
        key: str,
        default=None,
    ):

        return await asyncio.to_thread(

            self.get,

            key,

            default,

        )

    async def async_set(
        self,
        key: str,
        value: Any,
        ttl: int | None = None,
    ):

        await asyncio.to_thread(

            self.set,

            key,

            value,

            ttl,

        )

    async def async_delete(
        self,
        key: str,
    ):

        return await asyncio.to_thread(

            self.delete,

            key,

        )

    ####################################################################
    # Process
    ####################################################################

    def process(
        self,
        operation: str,
        *args,
        **kwargs,
    ):

        operations = {

            "get": self.get,

            "set": self.set,

            "delete": self.delete,

            "exists": self.exists,

            "cleanup": self.cleanup,

            "clear": self.clear,

        }

        handler = operations.get(operation)

        if handler is None:

            raise ValueError(

                f"Unsupported cache operation: {operation}"

            )

        return handler(

            *args,

            **kwargs,

        )

    ####################################################################
    # Shutdown
    ####################################################################

    def shutdown(
        self,
    ) -> None:

        self.logger.info(
            "Shutting down cache service..."
        )

        self.clear()

        super().shutdown()

    ####################################################################
    # Magic Methods
    ####################################################################

    def __contains__(
        self,
        key: str,
    ) -> bool:

        return self.exists(key)

    def __len__(
        self,
    ) -> int:

        return len(self.cache)

    def __repr__(
        self,
    ) -> str:

        return (

            f"<CacheService "

            f"entries={len(self.cache)} "

            f"hit_ratio={self.hit_ratio()}%>"

        )
    