"""
DynamoDB Table Definitions
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class TableNames(str, Enum):

    THREAT_EVENTS = "ThreatEvents"

    IOC_RESULTS = "IOCResults"

    ASSETS = "Assets"

    MITRE_ATTACK = "MitreAttack"

    CVE_DATABASE = "CVEDatabase"

    PIPELINE_CACHE = "PipelineCache"


@dataclass(slots=True)
class KeySchema:

    partition_key: str

    sort_key: str | None = None


@dataclass(slots=True)
class TableDefinition:

    name: str

    partition_key: str

    sort_key: str | None

    billing_mode: str = "PAY_PER_REQUEST"

    stream_enabled: bool = False

    ttl_attribute: str | None = None
    
    
ThreatEventsTable = TableDefinition(

    name=TableNames.THREAT_EVENTS.value,

    partition_key="event_id",

    sort_key="timestamp",

    stream_enabled=True,
)

IOCResultsTable = TableDefinition(

    name=TableNames.IOC_RESULTS.value,

    partition_key="indicator",

    sort_key="ioc_type",
)

AssetsTable = TableDefinition(

    name=TableNames.ASSETS.value,

    partition_key="asset_id",

    sort_key=None,
)

MitreTable = TableDefinition(

    name=TableNames.MITRE_ATTACK.value,

    partition_key="technique_id",

    sort_key=None,
)

CVETable = TableDefinition(

    name=TableNames.CVE_DATABASE.value,

    partition_key="cve_id",

    sort_key=None,
)

PipelineCacheTable = TableDefinition(

    name=TableNames.PIPELINE_CACHE.value,

    partition_key="cache_key",

    sort_key=None,

    ttl_attribute="expires_at",
)

ALL_TABLES = [

    ThreatEventsTable,

    IOCResultsTable,

    AssetsTable,

    MitreTable,

    CVETable,

    PipelineCacheTable,
]

def get_table_definition(

    table_name: str,

):

    for table in ALL_TABLES:

        if table.name == table_name:

            return table

    raise ValueError(

        f"Unknown table {table_name}"

    )
    
def list_tables():

    return [

        table.name

        for table in ALL_TABLES

    ]
    
def self_test():

    return {

        "tables": list_tables(),

        "count": len(ALL_TABLES),

    }
    
