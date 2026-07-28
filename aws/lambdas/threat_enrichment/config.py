"""
Enterprise Threat Enrichment Configuration

Central configuration used across the Threat Enrichment pipeline.

Author: NextCare AI
Python: 3.11+
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List
import os


# =============================================================================
# Project Paths
# =============================================================================

ROOT_DIR = Path(__file__).resolve().parents[3]

DATASETS_DIR = ROOT_DIR / "datasets"

RAW_DATA_DIR = DATASETS_DIR / "raw"

PROCESSED_DATA_DIR = DATASETS_DIR / "processed"

CACHE_DIR = ROOT_DIR / "cache"

LOG_DIR = ROOT_DIR / "logs"

MODELS_DIR = ROOT_DIR / "models"

TEMP_DIR = ROOT_DIR / "temp"

REPORTS_DIR = ROOT_DIR / "reports"


# =============================================================================
# Dataset Configuration
# =============================================================================

CVE_DATASET = (
    PROCESSED_DATA_DIR
    / "cve_reference.parquet"
)

IOC_DATASET = (
    RAW_DATA_DIR
    / "threat_feeds"
    / "ioc_feed.parquet"
)

MITRE_DATASET = (
    PROCESSED_DATA_DIR
    / "mitre_attack.parquet"
)

ASSET_DATASET = (
    PROCESSED_DATA_DIR
    / "asset_inventory.parquet"
)


# =============================================================================
# Logging
# =============================================================================

LOG_LEVEL = os.getenv(
    "LOG_LEVEL",
    "INFO"
)

LOG_FILE = LOG_DIR / "threat_enrichment.log"


# =============================================================================
# Pipeline Configuration
# =============================================================================

@dataclass(slots=True)
class PipelineConfig:

    enable_validation: bool = True

    enable_ioc_matching: bool = True

    enable_cve_lookup: bool = True

    enable_mitre_mapping: bool = True

    enable_asset_context: bool = True

    enable_behavior_analysis: bool = True

    enable_threat_scoring: bool = True

    enable_risk_engine: bool = True

    enable_logging: bool = True

    max_parallel_workers: int = 8

    cache_enabled: bool = True

    cache_size: int = 50000


# =============================================================================
# IOC Configuration
# =============================================================================

@dataclass(slots=True)
class IOCConfig:

    auto_reload: bool = False

    case_sensitive: bool = False

    enable_ip_matching: bool = True

    enable_domain_matching: bool = True

    enable_url_matching: bool = True

    enable_hash_matching: bool = True

    enable_filename_matching: bool = True

    supported_hashes: List[str] = field(
        default_factory=lambda: [
            "md5",
            "sha1",
            "sha256"
        ]
    )


# =============================================================================
# CVE Configuration
# =============================================================================

@dataclass(slots=True)
class CVEConfig:

    minimum_cvss: float = 0.0

    maximum_cvss: float = 10.0

    include_cwe: bool = True

    include_vendor: bool = True

    include_product: bool = True

    include_references: bool = True


# =============================================================================
# MITRE Configuration
# =============================================================================

@dataclass(slots=True)
class MITREConfig:

    include_tactics: bool = True

    include_techniques: bool = True

    include_subtechniques: bool = True

    include_detection: bool = True

    include_mitigation: bool = True


# =============================================================================
# Threat Scoring
# =============================================================================

@dataclass(slots=True)
class ThreatScoreConfig:

    max_score: int = 100

    ioc_weight: float = 0.30

    cve_weight: float = 0.20

    behavior_weight: float = 0.20

    asset_weight: float = 0.15

    ml_weight: float = 0.15


# =============================================================================
# Asset Configuration
# =============================================================================

@dataclass(slots=True)
class AssetConfig:

    default_criticality: str = "MEDIUM"

    internet_facing_multiplier: float = 1.25

    production_multiplier: float = 1.50

    domain_controller_multiplier: float = 2.00


# =============================================================================
# Runtime Configuration
# =============================================================================

PIPELINE = PipelineConfig()

IOC = IOCConfig()

CVE = CVEConfig()

MITRE = MITREConfig()

THREAT_SCORE = ThreatScoreConfig()

ASSET = AssetConfig()