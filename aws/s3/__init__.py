"""
Amazon S3 Package

High-level storage layer for the AI-Assisted Threat Detection Dashboard.

Modules
-------
buckets.py      -> Bucket management
storage.py      -> Storage service
uploader.py     -> Upload helpers
downloader.py   -> Download helpers
lifecycle.py    -> Lifecycle configuration
policies.py     -> Bucket policies
"""

from .buckets import (
    BUCKETS as BUCKETS,
    BucketNames as BucketNames,
    bucket_exists as bucket_exists,
    create_all_buckets as create_all_buckets,
    s3 as s3,
)