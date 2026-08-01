"""
storage.py

High-Level Storage Service

Responsibilities
----------------
• Store structured datasets
• Store threat logs
• Store reports
• Store ML models
• Store backups
• Store feature datasets
• Metadata management
• Storage diagnostics
"""

from __future__ import annotations

import json
import gzip
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from aws.utils.aws_utils import (
    upload_file,
    download_file,
    put_json,
    get_json,
    object_exists,
    delete_object,
    copy_object,
    get_object_metadata,
    presigned_download_url,
)

from .buckets import (
    BucketNames,
    bucket_exists,
)

logger = logging.getLogger(__name__)


class StorageService:
    """
    High-level storage abstraction built on top of aws_utils.

    This class knows WHERE different types of project data
    should be stored.
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
    # Internal Helpers
    #######################################################################

    @staticmethod
    def timestamp() -> str:

        return datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    @staticmethod
    def today() -> str:

        return datetime.utcnow().strftime("%Y/%m/%d")

    @staticmethod
    def ensure_json_extension(
        key: str,
    ) -> str:

        if key.endswith(".json"):

            return key

        return key + ".json"

    @staticmethod
    def ensure_gzip_extension(
        key: str,
    ) -> str:

        if key.endswith(".gz"):

            return key

        return key + ".gz"

    @staticmethod
    def compress_json(
        data: Any,
    ) -> bytes:

        payload = json.dumps(
            data,
            ensure_ascii=False,
            default=str,
            indent=2,
        ).encode("utf-8")

        return gzip.compress(
            payload,
        )

    #######################################################################
    # Threat Logs
    #######################################################################

    def threat_log_key(
        self,
        filename: str,
    ) -> str:

        return f"{self.today()}/" f"{filename}"

    def save_threat_log(
        self,
        filename: str,
        data: Any,
    ) -> str:

        key = self.ensure_json_extension(
            self.threat_log_key(
                filename,
            )
        )

        put_json(
            self.threat_bucket,
            key,
            data,
        )

        logger.info(
            "Threat log stored: %s",
            key,
        )

        return key

    def load_threat_log(
        self,
        key: str,
    ) -> Any:

        return get_json(
            self.threat_bucket,
            key,
        )

    #######################################################################
    # Normalized Logs
    #######################################################################

    def normalized_log_key(
        self,
        filename: str,
    ) -> str:

        return f"{self.today()}/" f"{filename}"

    def save_normalized_log(
        self,
        filename: str,
        data: Any,
    ) -> str:

        key = self.ensure_json_extension(
            self.normalized_log_key(
                filename,
            )
        )

        put_json(
            self.normalized_bucket,
            key,
            data,
        )

        return key

    def load_normalized_log(
        self,
        key: str,
    ) -> Any:

        return get_json(
            self.normalized_bucket,
            key,
        )

    #######################################################################
    # IOC Dataset
    #######################################################################

    def save_ioc_dataset(
        self,
        name: str,
        data: Any,
    ) -> str:

        key = self.ensure_json_extension(
            name,
        )

        put_json(
            self.ioc_bucket,
            key,
            data,
        )

        return key

    def load_ioc_dataset(
        self,
        key: str,
    ) -> Any:

        return get_json(
            self.ioc_bucket,
            key,
        )

    #######################################################################
    # CVE Dataset
    #######################################################################

    def save_cve_dataset(
        self,
        name: str,
        data: Any,
    ) -> str:

        key = self.ensure_json_extension(
            name,
        )

        put_json(
            self.cve_bucket,
            key,
            data,
        )

        return key

    def load_cve_dataset(
        self,
        key: str,
    ) -> Any:

        return get_json(
            self.cve_bucket,
            key,
        )

    #######################################################################
    # MITRE Dataset
    #######################################################################

    def save_mitre_dataset(
        self,
        name: str,
        data: Any,
    ) -> str:

        key = self.ensure_json_extension(
            name,
        )

        put_json(
            self.mitre_bucket,
            key,
            data,
        )

        logger.info(
            "MITRE dataset stored: %s",
            key,
        )

        return key

    def load_mitre_dataset(
        self,
        key: str,
    ) -> Any:

        return get_json(
            self.mitre_bucket,
            key,
        )

    #######################################################################
    # Feature Store
    #######################################################################

    def save_feature_dataset(
        self,
        name: str,
        data: Any,
    ) -> str:

        key = self.ensure_json_extension(
            name,
        )

        put_json(
            self.feature_bucket,
            key,
            data,
        )

        logger.info(
            "Feature dataset stored: %s",
            key,
        )

        return key

    def load_feature_dataset(
        self,
        key: str,
    ) -> Any:

        return get_json(
            self.feature_bucket,
            key,
        )

    #######################################################################
    # Machine Learning Models
    #######################################################################

    def save_model(
        self,
        local_model_path: str,
        model_name: str,
    ) -> str:

        key = "models/" + model_name

        upload_file(
            local_model_path,
            self.model_bucket,
            key,
        )

        logger.info(
            "Model uploaded: %s",
            key,
        )

        return key

    def download_model(
        self,
        model_key: str,
        destination: str,
    ) -> str:

        download_file(
            self.model_bucket,
            model_key,
            destination,
        )

        return destination

    #######################################################################
    # Reports
    #######################################################################

    def save_report(
        self,
        report_name: str,
        report: Any,
    ) -> str:

        key = "reports/" + self.ensure_json_extension(
            report_name,
        )

        put_json(
            self.report_bucket,
            key,
            report,
        )

        logger.info(
            "Report stored: %s",
            key,
        )

        return key

    def load_report(
        self,
        report_key: str,
    ) -> Any:

        return get_json(
            self.report_bucket,
            report_key,
        )

    #######################################################################
    # Backups
    #######################################################################

    def save_backup(
        self,
        backup_name: str,
        data: Any,
        compress: bool = False,
    ) -> str:

        if compress:

            key = self.ensure_gzip_extension(
                backup_name,
            )

            payload = self.compress_json(
                data,
            )

            from utils.aws_utils import put_object

            put_object(
                self.backup_bucket,
                key,
                payload,
                content_type="application/gzip",
            )

        else:

            key = self.ensure_json_extension(
                backup_name,
            )

            put_json(
                self.backup_bucket,
                key,
                data,
            )

        logger.info(
            "Backup stored: %s",
            key,
        )

        return key

    def load_backup(
        self,
        key: str,
    ) -> Any:

        if key.endswith(".gz"):

            from utils.aws_utils import get_object

            raw = get_object(
                self.backup_bucket,
                key,
            )

            return json.loads(
                gzip.decompress(
                    raw,
                ).decode("utf-8")
            )

        return get_json(
            self.backup_bucket,
            key,
        )

    #######################################################################
    # QuickSight Datasets
    #######################################################################

    def save_quicksight_dataset(
        self,
        dataset_name: str,
        data: Any,
    ) -> str:

        key = "datasets/" + self.ensure_json_extension(
            dataset_name,
        )

        put_json(
            self.quicksight_bucket,
            key,
            data,
        )

        logger.info(
            "QuickSight dataset stored: %s",
            key,
        )

        return key

    def load_quicksight_dataset(
        self,
        key: str,
    ) -> Any:

        return get_json(
            self.quicksight_bucket,
            key,
        )

    #######################################################################
    # Generic JSON Storage
    #######################################################################

    def save_json(
        self,
        bucket: str,
        key: str,
        data: Any,
    ) -> str:

        key = self.ensure_json_extension(
            key,
        )

        put_json(
            bucket,
            key,
            data,
        )

        logger.info(
            "JSON object stored: %s/%s",
            bucket,
            key,
        )

        return key

    def load_json(
        self,
        bucket: str,
        key: str,
    ) -> Any:

        return get_json(
            bucket,
            key,
        )

    #######################################################################
    # Generic File Storage
    #######################################################################

    def upload(
        self,
        bucket: str,
        local_path: str,
        object_key: str,
    ) -> str:

        upload_file(
            local_path,
            bucket,
            object_key,
        )

        logger.info(
            "Uploaded file: %s",
            object_key,
        )

        return object_key

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
            "Downloaded file: %s",
            object_key,
        )

        return destination

    #######################################################################
    # Object Operations
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

    def metadata(
        self,
        bucket: str,
        object_key: str,
    ) -> dict[str, Any]:

        return get_object_metadata(
            bucket,
            object_key,
        )

    def delete(
        self,
        bucket: str,
        object_key: str,
    ) -> bool:

        delete_object(
            bucket,
            object_key,
        )

        logger.info(
            "Deleted object: %s",
            object_key,
        )

        return True

    def copy(
        self,
        source_bucket: str,
        source_key: str,
        destination_bucket: str,
        destination_key: str,
    ) -> str:

        copy_object(
            source_bucket,
            source_key,
            destination_bucket,
            destination_key,
        )

        logger.info(
            "Copied %s -> %s",
            source_key,
            destination_key,
        )

        return destination_key

    #######################################################################
    # Secure Access
    #######################################################################

    def presigned_url(
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
    # Statistics
    #######################################################################

    def bucket_mapping(
        self,
    ) -> dict[str, Any]:

        return {
            "buckets": {
                "threat": self.threat_bucket,
                "normalized": self.normalized_bucket,
                "ioc": self.ioc_bucket,
                "cve": self.cve_bucket,
                "mitre": self.mitre_bucket,
                "features": self.feature_bucket,
                "models": self.model_bucket,
                "reports": self.report_bucket,
                "backups": self.backup_bucket,
                "quicksight": self.quicksight_bucket,
            }
        }

    #######################################################################
    # Bulk Upload
    #######################################################################

    def upload_directory(
        self,
        bucket: str,
        local_directory: str,
        prefix: str = "",
    ) -> list[str]:

        uploaded = []

        directory = Path(
            local_directory,
        )

        if not directory.exists():

            raise FileNotFoundError(directory)

        for file in directory.rglob("*"):

            if not file.is_file():

                continue

            key = (
                f"{prefix}/{file.relative_to(directory)}"
                if prefix
                else str(file.relative_to(directory))
            ).replace(
                "\\",
                "/",
            )

            upload_file(
                str(file),
                bucket,
                key,
            )

            uploaded.append(
                key,
            )

            logger.info(
                "Uploaded %s",
                key,
            )

        return uploaded

    #######################################################################
    # Bulk Download
    #######################################################################

    def download_directory(
        self,
        bucket: str,
        objects: list[str],
        destination: str,
    ) -> list[str]:

        downloaded = []

        destination_path = Path(
            destination,
        )

        destination_path.mkdir(
            parents=True,
            exist_ok=True,
        )

        for key in objects:

            target = destination_path / key

            target.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            download_file(
                bucket,
                key,
                str(target),
            )

            downloaded.append(
                str(target),
            )

            logger.info(
                "Downloaded %s",
                key,
            )

        return downloaded

    #######################################################################
    # Batch JSON Storage
    #######################################################################

    def save_json_batch(
        self,
        bucket: str,
        documents: dict[str, Any],
    ) -> list[str]:

        stored = []

        for key, value in documents.items():

            object_key = self.ensure_json_extension(
                key,
            )

            put_json(
                bucket,
                object_key,
                value,
            )

            stored.append(
                object_key,
            )

        logger.info(
            "Stored %d JSON documents.",
            len(stored),
        )

        return stored

    #######################################################################
    # Batch Delete
    #######################################################################

    def delete_batch(
        self,
        bucket: str,
        object_keys: list[str],
    ) -> int:

        deleted = 0

        for key in object_keys:

            try:

                delete_object(
                    bucket,
                    key,
                )

                deleted += 1

            except Exception:

                logger.exception(
                    "Failed deleting %s",
                    key,
                )

        return deleted

    #######################################################################
    # Batch Copy
    #######################################################################

    def copy_batch(
        self,
        source_bucket: str,
        destination_bucket: str,
        mappings: dict[str, str],
    ) -> list[str]:

        copied = []

        for source_key, destination_key in mappings.items():

            copy_object(
                source_bucket,
                source_key,
                destination_bucket,
                destination_key,
            )

            copied.append(
                destination_key,
            )

        logger.info(
            "Copied %d objects.",
            len(copied),
        )

        return copied

    #######################################################################
    # Archive Export
    #######################################################################

    def archive_dataset(
        self,
        bucket: str,
        dataset_name: str,
        dataset: Any,
    ) -> str:

        key = "archive/" + self.ensure_gzip_extension(
            dataset_name,
        )

        payload = self.compress_json(
            dataset,
        )

        from utils.aws_utils import put_object

        put_object(
            bucket,
            key,
            payload,
            content_type="application/gzip",
        )

        logger.info(
            "Archived dataset: %s",
            key,
        )

        return key

    #######################################################################
    # Dataset Restore
    #######################################################################

    def restore_archive(
        self,
        bucket: str,
        archive_key: str,
    ) -> Any:

        if not archive_key.endswith(
            ".gz",
        ):

            raise ValueError("Archive must be a gzip (.gz) file.")

        from utils.aws_utils import get_object

        compressed = get_object(
            bucket,
            archive_key,
        )

        data = gzip.decompress(
            compressed,
        )

        return json.loads(
            data.decode(
                "utf-8",
            )
        )

    #######################################################################
    # Dataset Export
    #######################################################################

    def export_dataset(
        self,
        bucket: str,
        object_key: str,
        destination: str,
    ) -> str:

        destination_path = Path(
            destination,
        )

        destination_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        download_file(
            bucket,
            object_key,
            str(
                destination_path,
            ),
        )

        logger.info(
            "Dataset exported to %s",
            destination,
        )

        return str(
            destination_path,
        )

    #######################################################################
    # Dataset Import
    #######################################################################

    def import_dataset(
        self,
        bucket: str,
        source: str,
        object_key: str,
    ) -> str:

        upload_file(
            source,
            bucket,
            object_key,
        )

        logger.info(
            "Dataset imported: %s",
            object_key,
        )

        return object_key

    #######################################################################
    # Project Backup
    #######################################################################

    def backup_project(
        self,
        backup_name: str,
        project_data: dict[str, Any],
    ) -> str:

        timestamp = self.timestamp()

        key = "project-backups/" f"{backup_name}_{timestamp}.json"

        put_json(
            self.backup_bucket,
            key,
            project_data,
        )

        logger.info(
            "Project backup created: %s",
            key,
        )

        return key

    #######################################################################
    # Project Restore
    #######################################################################

    def restore_project(
        self,
        backup_key: str,
    ) -> dict[str, Any]:

        return get_json(
            self.backup_bucket,
            backup_key,
        )

    #######################################################################
    # Cleanup
    #######################################################################

    def cleanup_objects(
        self,
        bucket: str,
        object_keys: list[str],
    ) -> dict[str, Any]:

        deleted = []

        failed = []

        for key in object_keys:

            try:

                delete_object(
                    bucket,
                    key,
                )

                deleted.append(
                    key,
                )

            except Exception:

                logger.exception(
                    "Failed deleting %s",
                    key,
                )

                failed.append(
                    key,
                )

        return {
            "deleted": deleted,
            "failed": failed,
            "deleted_count": len(
                deleted,
            ),
            "failed_count": len(
                failed,
            ),
        }

    #######################################################################
    # Object Verification
    #######################################################################

    def verify_object(
        self,
        bucket: str,
        object_key: str,
    ) -> dict[str, Any]:

        exists = object_exists(
            bucket,
            object_key,
        )

        if not exists:

            return {
                "exists": False,
                "metadata": {},
            }

        metadata = get_object_metadata(
            bucket,
            object_key,
        )

        return {
            "exists": True,
            "metadata": metadata,
        }

    #######################################################################
    # Integrity Check
    #######################################################################

    def verify_objects(
        self,
        bucket: str,
        object_keys: list[str],
    ) -> dict[str, Any]:

        verified = []

        missing = []

        for key in object_keys:

            if object_exists(
                bucket,
                key,
            ):

                verified.append(
                    key,
                )

            else:

                missing.append(
                    key,
                )

        return {
            "verified": verified,
            "missing": missing,
            "verified_count": len(
                verified,
            ),
            "missing_count": len(
                missing,
            ),
        }

    #######################################################################
    # Storage Report
    #######################################################################

    def storage_report(
        self,
    ) -> dict[str, Any]:

        return {
            "threat_bucket": self.threat_bucket,
            "normalized_bucket": self.normalized_bucket,
            "ioc_bucket": self.ioc_bucket,
            "cve_bucket": self.cve_bucket,
            "mitre_bucket": self.mitre_bucket,
            "feature_bucket": self.feature_bucket,
            "model_bucket": self.model_bucket,
            "report_bucket": self.report_bucket,
            "backup_bucket": self.backup_bucket,
            "quicksight_bucket": self.quicksight_bucket,
        }

    #######################################################################
    # Storage Health
    #######################################################################

    def health_check(
        self,
    ) -> dict[str, Any]:

        buckets = {
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

        report = {}

        overall = True

        for name, bucket in buckets.items():

            exists = bucket_exists(
                bucket,
            )

            report[name] = {
                "bucket": bucket,
                "exists": exists,
            }

            if not exists:

                overall = False

        return {
            "healthy": overall,
            "buckets": report,
        }

    #######################################################################
    # Storage Inventory
    #######################################################################

    def inventory(
        self,
    ) -> dict[str, Any]:

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
    # Bucket Validation
    #######################################################################

    def validate_storage(
        self,
    ) -> dict[str, Any]:

        validation = {}

        valid = True

        for name, bucket in self.inventory().items():

            exists = bucket_exists(
                bucket,
            )

            validation[name] = exists

            if not exists:

                valid = False

        return {
            "valid": valid,
            "results": validation,
        }

    #######################################################################
    # Storage Metrics
    #######################################################################

    def metrics(
        self,
    ) -> dict[str, Any]:

        inventory = self.inventory()

        validation = self.validate_storage()

        return {
            "bucket_count": len(
                inventory,
            ),
            "available": sum(validation["results"].values()),
            "missing": len(
                inventory,
            )
            - sum(validation["results"].values()),
        }

    #######################################################################
    # Diagnostics
    #######################################################################

    def diagnostics(
        self,
    ) -> dict[str, Any]:

        return {
            "inventory": self.inventory(),
            "validation": self.validate_storage(),
            "health": self.health_check(),
            "metrics": self.metrics(),
        }

    #######################################################################
    # Storage Summary
    #######################################################################

    def summary(
        self,
    ) -> dict[str, Any]:

        diagnostics = self.diagnostics()

        return {
            "healthy": diagnostics["health"]["healthy"],
            "bucket_count": diagnostics["metrics"]["bucket_count"],
            "available": diagnostics["metrics"]["available"],
            "missing": diagnostics["metrics"]["missing"],
        }

    #######################################################################
    # Report Generator
    #######################################################################

    def generate_report(
        self,
    ) -> dict[str, Any]:

        return {
            "timestamp": self.timestamp(),
            "summary": self.summary(),
            "diagnostics": self.diagnostics(),
            "storage": self.storage_report(),
        }


###########################################################################
# Storage Manager
###########################################################################


class StorageManager:
    """
    Singleton-style manager that exposes the project's
    StorageService.
    """

    def __init__(
        self,
    ):

        self.storage = StorageService()

    #######################################################################
    # Accessor
    #######################################################################

    def get_storage(
        self,
    ) -> StorageService:

        return self.storage

    #######################################################################
    # Diagnostics
    #######################################################################

    def diagnostics(
        self,
    ) -> dict[str, Any]:

        return self.storage.diagnostics()

    #######################################################################
    # Summary
    #######################################################################

    def summary(
        self,
    ) -> dict[str, Any]:

        return self.storage.summary()

    #######################################################################
    # Health
    #######################################################################

    def health(
        self,
    ) -> dict[str, Any]:

        return self.storage.health_check()

    #######################################################################
    # Inventory
    #######################################################################

    def inventory(
        self,
    ) -> dict[str, Any]:

        return self.storage.inventory()

    #######################################################################
    # Metrics
    #######################################################################

    def metrics(
        self,
    ) -> dict[str, Any]:

        return self.storage.metrics()


###########################################################################
# Global Storage Objects
###########################################################################

STORAGE = StorageService()

STORAGE_MANAGER = StorageManager()


###########################################################################
# Convenience Functions
###########################################################################


def storage() -> StorageService:

    return STORAGE


def diagnostics() -> dict[str, Any]:

    return STORAGE.diagnostics()


def summary() -> dict[str, Any]:

    return STORAGE.summary()


def inventory() -> dict[str, Any]:

    return STORAGE.inventory()


def health() -> dict[str, Any]:

    return STORAGE.health_check()


def metrics() -> dict[str, Any]:

    return STORAGE.metrics()


###########################################################################
# Self Test
###########################################################################


def self_test() -> dict[str, Any]:

    service = StorageService()

    health_report = service.health_check()

    validation = service.validate_storage()

    diagnostics_report = service.diagnostics()

    return {
        "module": "storage",
        "passed": validation["valid"],
        "summary": service.summary(),
        "health": health_report,
        "diagnostics": diagnostics_report,
    }


###########################################################################
# Main
###########################################################################

if __name__ == "__main__":

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(message)s",
    )

    print("=" * 80)

    print("S3 Storage Service")

    print("=" * 80)

    print()

    print("Inventory")

    print(inventory())

    print()

    print("Metrics")

    print(metrics())

    print()

    print("Health")

    print(health())

    print()

    print("Diagnostics")

    print(diagnostics())

    print()

    print("Summary")

    print(summary())

    print()

    print("Self Test")

    print(self_test())

    print()

    print("Storage Service Ready")


__all__ = [
    "StorageService",
    "StorageManager",
    "STORAGE",
    "STORAGE_MANAGER",
]
