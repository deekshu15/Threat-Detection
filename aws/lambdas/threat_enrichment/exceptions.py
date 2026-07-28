"""
Custom exceptions for the Threat Enrichment module.
"""

from __future__ import annotations


class ThreatEnrichmentError(Exception):
    """Base exception for the Threat Enrichment module."""


# ============================================================================
# Validation
# ============================================================================

class ValidationError(ThreatEnrichmentError):
    """Raised when an incoming event is invalid."""


class MissingFieldError(ValidationError):
    """Raised when a required field is missing."""


class InvalidFieldError(ValidationError):
    """Raised when a field contains invalid data."""


class InvalidIPAddressError(ValidationError):
    """Raised when an IP address is invalid."""


class InvalidPortError(ValidationError):
    """Raised when a port number is invalid."""


class InvalidTimestampError(ValidationError):
    """Raised when a timestamp cannot be parsed."""


# ============================================================================
# IOC
# ============================================================================

class IOCError(ThreatEnrichmentError):
    """Base IOC exception."""


class IOCFeedNotFoundError(IOCError):
    """Raised when the IOC dataset cannot be located."""


class IOCFeedFormatError(IOCError):
    """Raised when the IOC feed format is unsupported."""


class IOCLoadError(IOCError):
    """Raised when an IOC feed cannot be loaded."""


# ============================================================================
# CVE
# ============================================================================

class CVEError(ThreatEnrichmentError):
    """Base CVE exception."""


class CVEDatasetNotFoundError(CVEError):
    """Raised when the CVE dataset is missing."""


class CVELookupError(CVEError):
    """Raised when CVE lookup fails."""


# ============================================================================
# MITRE
# ============================================================================

class MITREError(ThreatEnrichmentError):
    """Base MITRE exception."""


class MITRELookupError(MITREError):
    """Raised when ATT&CK mapping fails."""


# ============================================================================
# Assets
# ============================================================================

class AssetContextError(ThreatEnrichmentError):
    """Raised when asset context cannot be determined."""


# ============================================================================
# Threat Scoring
# ============================================================================

class ThreatScoreError(ThreatEnrichmentError):
    """Raised when threat scoring fails."""


# ============================================================================
# Risk
# ============================================================================

class RiskCalculationError(ThreatEnrichmentError):
    """Raised when risk calculation fails."""


# ============================================================================
# Pipeline
# ============================================================================

class PipelineInitializationError(ThreatEnrichmentError):
    """Raised when the enrichment pipeline cannot start."""


class PipelineExecutionError(ThreatEnrichmentError):
    """Raised when the enrichment pipeline fails during execution."""