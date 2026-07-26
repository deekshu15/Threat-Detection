import sys
from pathlib import Path

# Add the project root to the Python path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from config import Config


def test_aws_region_is_set():
    """AWS_REGION should exist and look like a real AWS region string."""
    assert Config.AWS_REGION, "AWS_REGION is empty or missing"
    assert isinstance(Config.AWS_REGION, str)


def test_raw_bucket_is_set():
    """RAW_BUCKET should exist and be a non-empty string."""
    assert Config.RAW_BUCKET, "RAW_BUCKET is empty or missing"
    assert isinstance(Config.RAW_BUCKET, str)


def test_processed_bucket_is_set():
    """PROCESSED_BUCKET should exist and be a non-empty string."""
    assert Config.PROCESSED_BUCKET, "PROCESSED_BUCKET is empty or missing"
    assert isinstance(Config.PROCESSED_BUCKET, str)


def test_log_level_is_valid():
    """LOG_LEVEL should be one of the standard logging levels."""
    valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    assert Config.LOG_LEVEL in valid_levels, (
        f"LOG_LEVEL is '{Config.LOG_LEVEL}', expected one of {valid_levels}"
    )


def test_environment_is_valid():
    """ENVIRONMENT should be one of the expected deployment stages."""
    valid_environments = {"development", "staging", "production"}
    assert Config.ENVIRONMENT in valid_environments, (
        f"ENVIRONMENT is '{Config.ENVIRONMENT}', expected one of {valid_environments}"
    )