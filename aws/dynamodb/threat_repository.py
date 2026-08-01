"""
Threat Repository

Specialized repositories built on top of DynamoRepository.

Provides:

• Threat Events Repository
• IOC Repository
• CVE Repository
• MITRE Repository
• Asset Repository
• Pipeline Cache Repository
"""

from __future__ import annotations

import time

from typing import Any

from boto3.dynamodb.conditions import Attr
from boto3.dynamodb.conditions import Key

from .repository import DynamoRepository

from .tables import (
    ThreatEventsTable,
    IOCResultsTable,
    AssetsTable,
    MitreTable,
    CVETable,
    PipelineCacheTable,
)

###########################################################################
# Threat Events
###########################################################################

class ThreatRepository(

    DynamoRepository[dict]

):

    def __init__(self):

        super().__init__(

            ThreatEventsTable.name

        )
        
    def save_event(

        self,

        event: dict,

    ):

        return self.put(event)
    
    def get_event(

        self,

        event_id,

        timestamp,

    ):

        return self.get(

            "event_id",

            event_id,

            "timestamp",

            timestamp,

        )
        
    def delete_event(

        self,

        event_id,

        timestamp,

    ):

        return self.delete(

            {

                "event_id":

                event_id,

                "timestamp":

                timestamp,

            }

        )
        
    def event_history(

        self,

        event_id,

    ):

        return self.query(

            "event_id",

            event_id,

        )
        
    def events_by_severity(

        self,

        severity,

    ):

        return self.scan(

            Attr(

                "severity"

            ).eq(

                severity

            )

        )
        
    def events_above_score(

        self,

        score,

    ):

        return self.scan(

            Attr(

                "risk_score"

            ).gte(score)

        )
        
###########################################################################
# IOC Repository
###########################################################################

class IOCRepository(

    DynamoRepository[dict]

):

    def __init__(self):

        super().__init__(

            IOCResultsTable.name

        )
        
    def save(

        self,

        result,

    ):

        return self.put(result)
    
    def lookup(

        self,

        indicator,

        ioc_type,

    ):

        return self.get(

            "indicator",

            indicator,

            "ioc_type",

            ioc_type,

        )
        
    def verdict(

        self,

        verdict,

    ):

        return self.scan(

            Attr(

                "verdict"

            ).eq(

                verdict

            )

        )

    def confidence(

        self,

        minimum,

    ):

        return self.scan(

            Attr(

                "confidence"

            ).gte(

                minimum

            )

        )
        
###########################################################################
# CVE
###########################################################################

class CVERepository(

    DynamoRepository[dict]

):

    def __init__(self):

        super().__init__(

            CVETable.name

        )
        
    def save_cve(

        self,

        record,

    ):

        return self.put(record)
    
    def get_cve(

        self,

        cve_id,

    ):

        return self.get(

            "cve_id",

            cve_id,

        )
        
    def critical(

        self,

    ):

        return self.scan(

            Attr(

                "cvss"

            ).gte(9)

        )
        
    def vendor(

        self,

        vendor,

    ):

        return self.scan(

            Attr(

                "vendor"

            ).eq(

                vendor

            )

        )
        
###########################################################################
# MITRE
###########################################################################

class MitreRepository(

    DynamoRepository[dict]

):

    def __init__(self):

        super().__init__(

            MitreTable.name

        )
        
    def save(

        self,

        technique,

    ):

        return self.put(

            technique

        )
        
    def technique(

        self,

        technique_id,

    ):

        return self.get(

            "technique_id",

            technique_id,

        )
        
    def tactic(

        self,

        tactic,

    ):

        return self.scan(

            Attr(

                "tactic"

            ).eq(

                tactic

            )

        )
        
###########################################################################
# Assets
###########################################################################

class AssetRepository(

    DynamoRepository[dict]

):

    def __init__(self):

        super().__init__(

            AssetsTable.name

        )
        
    def save(

        self,

        asset,

    ):

        return self.put(

            asset

        )

    def asset(

        self,

        asset_id,

    ):

        return self.get(

            "asset_id",

            asset_id,

        )
        
    def critical(

        self,

    ):

        return self.scan(

            Attr(

                "critical"

            ).eq(True)

        )

    def owner(

        self,

        owner,

    ):

        return self.scan(

            Attr(

                "owner"

            ).eq(owner)

        )
        
###########################################################################
# Pipeline Cache
###########################################################################

class CacheRepository(

    DynamoRepository[dict]

):

    def __init__(self):

        super().__init__(

            PipelineCacheTable.name

        )
        
    def cache(

        self,

        key,

        value,

        ttl=300,

    ):

        return self.put(

            {

                "cache_key":

                key,

                "value":

                value,

                "expires_at":

                int(

                    time.time()

                )

                + ttl,

            }

        )
        
    def lookup(

        self,

        key,

    ):

        return self.get(

            "cache_key",

            key,

        )
        
    def invalidate(

        self,

        key,

    ):

        return self.delete(

            {

                "cache_key":

                key

            }

        )
        
###########################################################################
# Globals
###########################################################################

THREATS = ThreatRepository()

IOCS = IOCRepository()

CVES = CVERepository()

MITRE = MitreRepository()

ASSETS = AssetRepository()

CACHE = CacheRepository()

def diagnostics():

    return {

        "repositories": {

            "threats":

            THREATS.table_name,

            "ioc":

            IOCS.table_name,

            "cve":

            CVES.table_name,

            "mitre":

            MITRE.table_name,

            "assets":

            ASSETS.table_name,

            "cache":

            CACHE.table_name,

        }

    }
    
def self_test():

    return {

        "repositories": 6,

        "passed": True,

        "tables": diagnostics(),

    }
    
    