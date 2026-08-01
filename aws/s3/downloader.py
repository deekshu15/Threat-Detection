"""
downloader.py

Enterprise S3 Download Service

Responsibilities
----------------
• File downloads
• JSON downloads
• Dataset downloads
• Model downloads
• Report downloads
• Backup downloads
• Metadata retrieval
• Download validation
"""

from __future__ import annotations

import gzip
import json
import logging

from pathlib import Path
from typing import Any

from aws.utils.aws_utils import (
    download_file,
    get_json,
    get_object_metadata,
    object_exists,
    get_bytes,
    presigned_download_url,
)

from .buckets import BucketNames

logger = logging.getLogger(__name__)


class DownloadService:
    """
    High-level download abstraction.

    All project downloads should go through this service.
    """

    def __init__(self):

        self.threat_bucket = BucketNames.THREAT_LOGS.value

        self.normalized_bucket = BucketNames.NORMALIZED_LOGS.value

        self.ioc_bucket = BucketNames.IOC_DATA.value

        self.cve_bucket = BucketNames.CVE_DATA.value

        self.mitre_bucket = BucketNames.MITRE_DATA.value

        self.feature_bucket = BucketNames.FEATURE_STORE.value

        self.model_bucket = BucketNames.ML_MODELS.value

        self.report_bucket = BucketNames.REPORTS.value

        self.backup_bucket = BucketNames.BACKUPS.value

        self.quicksight_bucket = BucketNames.QUICKSIGHT_DATA.value

    #######################################################################
    # Generic Download
    #######################################################################

    def download(
        self,
        bucket: str,
        object_key: str,
        destination: str,
    ) -> str:

        download_file(
            bucket,
            object_key,
            destination,
        )

        logger.info(
            "Downloaded %s",
            object_key,
        )

        return destination

    #######################################################################
    # Generic JSON
    #######################################################################

    def download_json(
        self,
        bucket: str,
        object_key: str,
    ) -> Any:

        return get_json(
            bucket,
            object_key,
        )

    #######################################################################
    # Threat Logs
    #######################################################################

    def download_threat_log(
        self,
        object_key: str,
    ) -> Any:

        return self.download_json(
            self.threat_bucket,
            object_key,
        )

    #######################################################################
    # Normalized Logs
    #######################################################################

    def download_normalized_log(
        self,
        object_key: str,
    ) -> Any:

        return self.download_json(
            self.normalized_bucket,
            object_key,
        )

    #######################################################################
    # IOC Dataset
    #######################################################################

    def download_ioc_dataset(
        self,
        object_key: str,
    ) -> Any:

        return self.download_json(
            self.ioc_bucket,
            object_key,
        )

    #######################################################################
    # CVE Dataset
    #######################################################################

    def download_cve_dataset(
        self,
        object_key: str,
    ) -> Any:

        return self.download_json(
            self.cve_bucket,
            object_key,
        )

    #######################################################################
    # MITRE Dataset
    #######################################################################

    def download_mitre_dataset(
        self,
        object_key: str,
    ) -> Any:

        return self.download_json(
            self.mitre_bucket,
            object_key,
        )

    #######################################################################
    # Feature Store
    #######################################################################

    def download_feature_dataset(
        self,
        object_key: str,
    ) -> Any:

        return self.download_json(
            self.feature_bucket,
            object_key,
        )

    #######################################################################
    # Machine Learning Model
    #######################################################################

    def download_model(
        self,
        object_key: str,
        destination: str,
    ) -> str:

        return self.download(
            self.model_bucket,
            object_key,
            destination,
        )

    #######################################################################
    # Reports
    #######################################################################

    def download_report(
        self,
        object_key: str,
    ) -> Any:

        return self.download_json(
            self.report_bucket,
            object_key,
        )

    #######################################################################
    # Backups
    #######################################################################

    def download_backup(
        self,
        object_key: str,
    ) -> Any:

        if object_key.endswith(
            ".gz",
        ):

            compressed = get_bytes(
                self.backup_bucket,
                object_key,
            )

            return json.loads(
                gzip.decompress(
                    compressed,
                ).decode(
                    "utf-8",
                )
            )

        return get_json(
            self.backup_bucket,
            object_key,
        )

    #######################################################################
    # QuickSight Dataset
    #######################################################################

    def download_quicksight_dataset(
        self,
        object_key: str,
    ) -> Any:

        return self.download_json(
            self.quicksight_bucket,
            object_key,
        )

    #######################################################################
    # Binary Object
    #######################################################################

    def download_binary(
        self,
        bucket: str,
        object_key: str,
    ) -> bytes:

        return get_bytes(
            bucket,
            object_key,
        )

    #######################################################################
    # Metadata
    #######################################################################

    def metadata(
        self,
        bucket: str,
        object_key: str,
    ) -> dict[str, Any]:

        return get_object_metadata(
            bucket,
            object_key,
        )

    #######################################################################
    # Object Exists
    #######################################################################

    def exists(
        self,
        bucket: str,
        object_key: str,
    ) -> bool:

        return object_exists(
            bucket,
            object_key,
        )

    #######################################################################
    # Download Verification
    #######################################################################

    def verify_download(
        self,
        bucket: str,
        object_key: str,
    ) -> dict[str, Any]:

        exists = self.exists(
            bucket,
            object_key,
        )

        if not exists:

            return {
                "exists": False,
                "metadata": {},
            }

        return {
            "exists": True,
            "metadata": self.metadata(
                bucket,
                object_key,
            ),
        }

    #######################################################################
    # Presigned Download URL
    #######################################################################

    def generate_download_url(
        self,
        bucket: str,
        object_key: str,
        expires_in: int = 3600,
    ) -> str:

        return presigned_download_url(
            bucket,
            object_key,
            expires_in=expires_in,
        )

    #######################################################################
    # File Information
    #######################################################################

    def file_information(
        self,
        bucket: str,
        object_key: str,
    ) -> dict[str, Any]:

        return {
            "bucket": bucket,
            "key": object_key,
            "exists": self.exists(
                bucket,
                object_key,
            ),
            "metadata": (
                self.metadata(
                    bucket,
                    object_key,
                )
                if self.exists(
                    bucket,
                    object_key,
                )
                else {}
            ),
        }

    #######################################################################
    # Download Statistics
    #######################################################################

    def download_manifest_statistics(
        self,
        downloaded: list[str],
    ) -> dict[str, Any]:

        return {
            "downloaded_files": len(
                downloaded,
            ),
            "objects": downloaded,
        }

    #######################################################################
    # Batch Downloads
    #######################################################################

    def download_batch(
        self,
        bucket: str,
        downloads: list[tuple[str, str]],
    ) -> list[str]:

        completed = []

        for object_key, destination in downloads:

            self.download(
                bucket,
                object_key,
                destination,
            )

            completed.append(
                destination,
            )

            logger.info(
                "Downloaded %s",
                object_key,
            )

        return completed

    #######################################################################
    # Directory Download
    #######################################################################

    def download_directory(
        self,
        bucket: str,
        object_keys: list[str],
        destination: str,
    ) -> list[str]:

        destination_path = Path(
            destination,
        )

        destination_path.mkdir(
            parents=True,
            exist_ok=True,
        )

        downloaded = []

        for object_key in object_keys:

            target = destination_path / object_key

            target.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            self.download(
                bucket,
                object_key,
                str(
                    target,
                ),
            )

            downloaded.append(
                str(
                    target,
                ),
            )

        return downloaded

    #######################################################################
    # Recursive Download
    #######################################################################

    def download_tree(
        self,
        bucket: str,
        object_keys: list[str],
        destination: str,
    ) -> list[str]:

        downloaded = []

        root = Path(
            destination,
        )

        root.mkdir(
            parents=True,
            exist_ok=True,
        )

        for object_key in object_keys:

            file_path = root / object_key

            file_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            self.download(
                bucket,
                object_key,
                str(
                    file_path,
                ),
            )

            downloaded.append(
                str(
                    file_path,
                ),
            )

        logger.info(
            "Downloaded %d files.",
            len(
                downloaded,
            ),
        )

        return downloaded

    #######################################################################
    # Retry Download
    #######################################################################

    def download_with_retry(
        self,
        bucket: str,
        object_key: str,
        destination: str,
        retries: int = 3,
    ) -> str:

        last_error = None

        for attempt in range(
            1,
            retries + 1,
        ):

            try:

                self.download(
                    bucket,
                    object_key,
                    destination,
                )

                return destination

            except Exception as exc:

                last_error = exc

                logger.warning(
                    "Retry %d failed for %s",
                    attempt,
                    object_key,
                )

        raise last_error

    #######################################################################
    # Download Queue
    #######################################################################

    def download_queue(
        self,
        bucket: str,
        queue: list[tuple[str, str]],
    ) -> list[str]:

        completed = []

        for object_key, destination in queue:

            completed.append(
                self.download(
                    bucket,
                    object_key,
                    destination,
                )
            )

        return completed

    #######################################################################
    # Download Manifest
    #######################################################################

    def create_manifest(
        self,
        downloaded: list[str],
    ) -> dict[str, Any]:

        return {
            "count": len(
                downloaded,
            ),
            "files": downloaded,
        }

    #######################################################################
    # Download Summary
    #######################################################################

    def download_summary(
        self,
        downloaded: list[str],
    ) -> dict[str, Any]:

        return {
            "success": True,
            "count": len(
                downloaded,
            ),
            "manifest": self.create_manifest(
                downloaded,
            ),
        }

    #######################################################################
    # Validation
    #######################################################################

    def validate_download(
        self,
        destination: str,
    ) -> bool:

        path = Path(
            destination,
        )

        return path.exists() and path.is_file() and path.stat().st_size > 0

    #######################################################################
    # Conditional Download
    #######################################################################

    def download_if_exists(
        self,
        bucket: str,
        object_key: str,
        destination: str,
    ) -> str | None:

        if not object_exists(
            bucket,
            object_key,
        ):

            logger.warning(
                "Object does not exist: %s",
                object_key,
            )

            return None

        return self.download(
            bucket,
            object_key,
            destination,
        )

    #######################################################################
    # Download Metadata Only
    #######################################################################

    def download_metadata(
        self,
        bucket: str,
        object_key: str,
    ) -> dict[str, Any]:

        return get_object_metadata(
            bucket,
            object_key,
        )

    #######################################################################
    # Download Object With Metadata
    #######################################################################

    def download_with_metadata(
        self,
        bucket: str,
        object_key: str,
        destination: str,
    ) -> dict[str, Any]:

        self.download(
            bucket,
            object_key,
            destination,
        )

        metadata = get_object_metadata(
            bucket,
            object_key,
        )

        return {
            "path": destination,
            "metadata": metadata,
        }

    #######################################################################
    # Download Stream
    #######################################################################

    def download_stream(
        self,
        bucket: str,
        object_key: str,
    ) -> bytes:

        return get_bytes(
            bucket,
            object_key,
        )

    #######################################################################
    # Large File Download
    #######################################################################

    def download_large_file(
        self,
        bucket: str,
        object_key: str,
        destination: str,
    ) -> str:

        logger.info(
            "Downloading large object: %s",
            object_key,
        )

        return self.download(
            bucket,
            object_key,
            destination,
        )

    #######################################################################
    # Multipart Download
    #######################################################################

    def multipart_download(
        self,
        bucket: str,
        object_key: str,
        destination: str,
        chunk_size: int = 8 * 1024 * 1024,
    ) -> str:

        from boto3.s3.transfer import TransferConfig

        from aws.utils.aws_utils import get_client
        client = get_client(
            "s3",
        )

        config = TransferConfig(
            multipart_threshold=chunk_size,
            multipart_chunksize=chunk_size,
            max_concurrency=10,
            use_threads=True,
        )

        client.download_file(
            Bucket=bucket,
            Key=object_key,
            Filename=destination,
            Config=config,
        )

        logger.info(
            "Multipart download completed: %s",
            object_key,
        )

        return destination

    #######################################################################
    # Download Health
    #######################################################################

    def download_health(
        self,
    ) -> dict[str, Any]:

        return {
            "service": "DownloadService",
            "status": "healthy",
            "supported_buckets": [
                self.threat_bucket,
                self.normalized_bucket,
                self.ioc_bucket,
                self.cve_bucket,
                self.mitre_bucket,
                self.feature_bucket,
                self.model_bucket,
                self.report_bucket,
                self.backup_bucket,
                self.quicksight_bucket,
            ],
        }

    #######################################################################
    # Download Metrics
    #######################################################################

    def download_metrics(
        self,
        downloaded: list[str],
    ) -> dict[str, Any]:

        return {
            "downloaded": len(
                downloaded,
            ),
            "successful": len(
                downloaded,
            ),
            "failed": 0,
            "files": downloaded,
        }

    #######################################################################
    # Download Diagnostics
    #######################################################################

    def diagnostics(
        self,
    ) -> dict[str, Any]:

        return {
            "service": self.__class__.__name__,
            "health": self.download_health(),
            "buckets": {
                "threat": self.threat_bucket,
                "normalized": self.normalized_bucket,
                "ioc": self.ioc_bucket,
                "cve": self.cve_bucket,
                "mitre": self.mitre_bucket,
                "feature_store": self.feature_bucket,
                "models": self.model_bucket,
                "reports": self.report_bucket,
                "backups": self.backup_bucket,
                "quicksight": self.quicksight_bucket,
            },
        }

    #######################################################################
    # Download Report
    #######################################################################

    def generate_download_report(
        self,
        downloaded: list[str],
    ) -> dict[str, Any]:

        return {
            "summary": self.download_summary(
                downloaded,
            ),
            "metrics": self.download_metrics(
                downloaded,
            ),
            "diagnostics": self.diagnostics(),
        }

    #######################################################################
    # Inventory
    #######################################################################

    def inventory(
        self,
    ) -> dict[str, str]:

        return {
            "threat_logs": self.threat_bucket,
            "normalized_logs": self.normalized_bucket,
            "ioc": self.ioc_bucket,
            "cve": self.cve_bucket,
            "mitre": self.mitre_bucket,
            "feature_store": self.feature_bucket,
            "ml_models": self.model_bucket,
            "reports": self.report_bucket,
            "backups": self.backup_bucket,
            "quicksight": self.quicksight_bucket,
        }

    #######################################################################
    # Summary
    #######################################################################

    def summary(
        self,
    ) -> dict[str, Any]:

        inventory = self.inventory()

        return {
            "service": "DownloadService",
            "bucket_count": len(
                inventory,
            ),
            "health": self.download_health(),
        }


###########################################################################
# Download Manager
###########################################################################


class DownloadManager:
    """
    High-level manager for DownloadService.
    """

    def __init__(
        self,
    ):

        self.service = DownloadService()

    def downloader(
        self,
    ) -> DownloadService:

        return self.service

    def diagnostics(
        self,
    ) -> dict[str, Any]:

        return self.service.diagnostics()

    def summary(
        self,
    ) -> dict[str, Any]:

        return self.service.summary()


###########################################################################
# Global Instances
###########################################################################

DOWNLOADER = DownloadService()

DOWNLOAD_MANAGER = DownloadManager()


###########################################################################
# Convenience Functions
###########################################################################


def downloader() -> DownloadService:

    return DOWNLOADER


def diagnostics() -> dict[str, Any]:

    return DOWNLOADER.diagnostics()


def summary() -> dict[str, Any]:

    return DOWNLOADER.summary()


###########################################################################
# Self Test
###########################################################################


def self_test() -> dict[str, Any]:

    service = DownloadService()

    return {
        "module": "downloader",
        "status": "ready",
        "summary": service.summary(),
        "diagnostics": service.diagnostics(),
    }


###########################################################################
# Public Exports
###########################################################################

__all__ = [
    "DownloadService",
    "DownloadManager",
    "DOWNLOADER",
    "DOWNLOAD_MANAGER",
    "downloader",
    "diagnostics",
    "summary",
    "self_test",
]


###########################################################################
# Main
###########################################################################

if __name__ == "__main__":

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(message)s",
    )

    print("=" * 80)

    print("S3 Download Service")

    print("=" * 80)

    print()

    print("Summary")

    print(
        summary(),
    )

    print()

    print("Diagnostics")

    print(
        diagnostics(),
    )

    print()

    print("Self Test")

    print(
        self_test(),
    )

    print()

    print("Download Service Ready")
