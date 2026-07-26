"""
Configuration settings for the NormalizeSecurityLogs Lambda.

This module centralizes all configuration values used across the project.
Values can be overridden using AWS Lambda Environment Variables.
"""

import os


class Config:
    """Application configuration."""

    # ------------------------------------------------------------------
    # AWS Configuration
    # ------------------------------------------------------------------
    AWS_REGION = os.getenv("AWS_REGION", "eu-north-1")

    # ------------------------------------------------------------------
    # S3 Buckets
    # ------------------------------------------------------------------
    RAW_BUCKET = os.getenv(
        "RAW_BUCKET",
        "ai-threat-raw-logs-deekshitha"
    )

    PROCESSED_BUCKET = os.getenv(
        "PROCESSED_BUCKET",
        "ai-threat-processed-deekshitha"
    )

    # ------------------------------------------------------------------
    # Processed Folder Prefixes
    # ------------------------------------------------------------------
    NORMALIZED_PREFIX = "normalized/"
    ENRICHED_PREFIX = "enriched/"
    MITRE_PREFIX = "mitre/"

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    
    # ------------------------------------------------------------------
    # Environment
    # ------------------------------------------------------------------
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

    # ------------------------------------------------------------------
    # Supported File Extensions
    # ------------------------------------------------------------------
    SUPPORTED_EXTENSIONS = (
        ".csv",
        ".json",
        ".parquet",
    )

    # ------------------------------------------------------------------
    # Supported Security Sources
    # ------------------------------------------------------------------
    SUPPORTED_SOURCES = (
        "windows",
        "linux",
        "ids",
        "firewall",
        "cve",
        "threat_feeds",
        "incident_records",
    )

    # ------------------------------------------------------------------
    # Output Format
    # ------------------------------------------------------------------
    OUTPUT_FORMAT = "parquet"

    # ------------------------------------------------------------------
    # Project Metadata
    # ------------------------------------------------------------------
    PROJECT_NAME = "AI-Assisted Threat Detection Dashboard"

    MODULE_NAME = "Security Data Aggregation & Threat Intelligence Layer"