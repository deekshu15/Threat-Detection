"""
DynamoDB Package

This package provides:

- Table definitions
- Repository layer
- Threat repository
- Table creation utilities
"""

from .tables import (
    TableNames,
    ThreatEventsTable,
    IOCResultsTable,
    AssetsTable,
)

from .repository import DynamoRepository

from .threat_repository import ThreatRepository