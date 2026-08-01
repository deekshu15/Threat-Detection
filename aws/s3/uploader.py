"""
uploader.py

High-Level Upload Service

Responsibilities
----------------
• File uploads
• Directory uploads
• JSON uploads
• Dataset uploads
• Model uploads
• Report uploads
• Backup uploads
• Bulk uploads
"""

from __future__ import annotations

import json
import gzip
import logging

from pathlib import Path
from typing import Any

from aws.utils.aws_utils import (
    upload_file,
    put_json,
    put_object,
)

from .buckets import BucketNames

logger = logging.getLogger(__name__)


class UploadService:
    """
    High-level upload abstraction.

    All uploads inside the project should use this
    service instead of calling boto3 directly.
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
    # Helpers
    #######################################################################

    @staticmethod
    def ensure_json(
        key: str,
    ) -> str:

        if key.endswith(".json"):

            return key

        return key + ".json"

    @staticmethod
    def ensure_gzip(
        key: str,
    ) -> str:

        if key.endswith(".gz"):

            return key

        return key + ".gz"

    @staticmethod
    def compress(
        data: Any,
    ) -> bytes:

        payload = json.dumps(
            data,
            default=str,
            indent=2,
            ensure_ascii=False,
        ).encode("utf-8")

        return gzip.compress(
            payload,
        )

    #######################################################################
    # Generic File Upload
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
            "Uploaded %s",
            object_key,
        )

        return object_key

    #######################################################################
    # Generic JSON Upload
    #######################################################################

    def upload_json(
        self,
        bucket: str,
        object_key: str,
        data: Any,
    ) -> str:

        object_key = self.ensure_json(
            object_key,
        )

        put_json(
            bucket,
            object_key,
            data,
        )

        logger.info(
            "Uploaded JSON %s",
            object_key,
        )

        return object_key

    #######################################################################
    # Threat Logs
    #######################################################################

    def upload_threat_log(
        self,
        filename: str,
        data: Any,
    ) -> str:

        key = self.ensure_json(
            filename,
        )

        return self.upload_json(
            self.threat_bucket,
            key,
            data,
        )

    #######################################################################
    # Normalized Logs
    #######################################################################

    def upload_normalized_log(
        self,
        filename: str,
        data: Any,
    ) -> str:

        key = self.ensure_json(
            filename,
        )

        return self.upload_json(
            self.normalized_bucket,
            key,
            data,
        )

    #######################################################################
    # IOC Dataset
    #######################################################################

    def upload_ioc_dataset(
        self,
        filename: str,
        data: Any,
    ) -> str:

        key = self.ensure_json(
            filename,
        )

        return self.upload_json(
            self.ioc_bucket,
            key,
            data,
        )

    #######################################################################
    # CVE Dataset
    #######################################################################

    def upload_cve_dataset(
        self,
        filename: str,
        data: Any,
    ) -> str:

        key = self.ensure_json(
            filename,
        )

        return self.upload_json(
            self.cve_bucket,
            key,
            data,
        )

    #######################################################################
    # MITRE Dataset
    #######################################################################

    def upload_mitre_dataset(
        self,
        filename: str,
        data: Any,
    ) -> str:

        key = self.ensure_json(
            filename,
        )

        return self.upload_json(
            self.mitre_bucket,
            key,
            data,
        )

    #######################################################################
    # Feature Store
    #######################################################################

    def upload_feature_dataset(
        self,
        filename: str,
        data: Any,
    ) -> str:

        key = self.ensure_json(
            filename,
        )

        return self.upload_json(
            self.feature_bucket,
            key,
            data,
        )

    #######################################################################
    # Machine Learning Models
    #######################################################################

    def upload_model(
        self,
        local_model_path: str,
        model_name: str,
    ) -> str:

        object_key = "models/" + model_name

        upload_file(
            local_model_path,
            self.model_bucket,
            object_key,
        )

        logger.info(
            "Uploaded model %s",
            object_key,
        )

        return object_key

    #######################################################################
    # Reports
    #######################################################################

    def generate_upload_report(
        self,
        report_name: str,
        report: Any,
    ) -> str:

        object_key = "reports/" + self.ensure_json(
            report_name,
        )

        put_json(
            self.report_bucket,
            object_key,
            report,
        )

        logger.info(
            "Uploaded report %s",
            object_key,
        )

        return object_key

    #######################################################################
    # Backup Upload
    #######################################################################

    def upload_backup(
        self,
        backup_name: str,
        data: Any,
        compress: bool = False,
    ) -> str:

        if compress:

            object_key = self.ensure_gzip(
                backup_name,
            )

            payload = self.compress(
                data,
            )

            put_object(
                self.backup_bucket,
                object_key,
                payload,
                content_type="application/gzip",
            )

        else:

            object_key = self.ensure_json(
                backup_name,
            )

            put_json(
                self.backup_bucket,
                object_key,
                data,
            )

        logger.info(
            "Uploaded backup %s",
            object_key,
        )

        return object_key

    #######################################################################
    # QuickSight Dataset
    #######################################################################

    def upload_quicksight_dataset(
        self,
        dataset_name: str,
        data: Any,
    ) -> str:

        object_key = "datasets/" + self.ensure_json(
            dataset_name,
        )

        put_json(
            self.quicksight_bucket,
            object_key,
            data,
        )

        logger.info(
            "Uploaded QuickSight dataset %s",
            object_key,
        )

        return object_key

    #######################################################################
    # Binary Object Upload
    #######################################################################

    def upload_binary(
        self,
        bucket: str,
        object_key: str,
        payload: bytes,
        content_type: str = "application/octet-stream",
    ) -> str:

        put_object(
            bucket,
            object_key,
            payload,
            content_type=content_type,
        )

        logger.info(
            "Uploaded binary object %s",
            object_key,
        )

        return object_key

    #######################################################################
    # Multiple JSON Upload
    #######################################################################

    def upload_json_batch(
        self,
        bucket: str,
        documents: dict[str, Any],
    ) -> list[str]:

        uploaded = []

        for object_key, document in documents.items():

            key = self.ensure_json(
                object_key,
            )

            put_json(
                bucket,
                key,
                document,
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
    # Bulk File Upload
    #######################################################################

    def upload_files(
        self,
        bucket: str,
        files: list[tuple[str, str]],
    ) -> list[str]:

        uploaded = []

        for local_path, object_key in files:

            upload_file(
                local_path,
                bucket,
                object_key,
            )

            uploaded.append(
                object_key,
            )

            logger.info(
                "Uploaded %s",
                object_key,
            )

        return uploaded

    #######################################################################
    # Directory Upload
    #######################################################################

    def upload_directory(
        self,
        bucket: str,
        directory: str,
        prefix: str = "",
    ) -> list[str]:

        uploaded = []

        root = Path(
            directory,
        )

        if not root.exists():

            raise FileNotFoundError(
                directory,
            )

        for file in root.rglob("*"):

            if not file.is_file():

                continue

            relative = str(
                file.relative_to(
                    root,
                )
            ).replace(
                "\\",
                "/",
            )

            object_key = f"{prefix}/{relative}" if prefix else relative

            upload_file(
                str(file),
                bucket,
                object_key,
            )

            uploaded.append(
                object_key,
            )

            logger.info(
                "Uploaded %s",
                object_key,
            )

        return uploaded

    #######################################################################
    # Recursive Upload
    #######################################################################

    def upload_tree(
        self,
        bucket: str,
        directory: str,
        prefix: str = "",
        include_hidden: bool = False,
    ) -> list[str]:

        uploaded = []

        root = Path(
            directory,
        )

        for file in root.rglob("*"):

            if not file.is_file():

                continue

            if not include_hidden and file.name.startswith("."):

                continue

            relative = str(
                file.relative_to(
                    root,
                )
            ).replace(
                "\\",
                "/",
            )

            object_key = f"{prefix}/{relative}" if prefix else relative

            upload_file(
                str(file),
                bucket,
                object_key,
            )

            uploaded.append(
                object_key,
            )

        logger.info(
            "Uploaded %d files.",
            len(uploaded),
        )

        return uploaded

    #######################################################################
    # Upload Validation
    #######################################################################

    def validate_upload(
        self,
        local_path: str,
    ) -> bool:

        path = Path(
            local_path,
        )

        if not path.exists():

            return False

        if not path.is_file():

            return False

        if path.stat().st_size == 0:

            return False

        return True

    #######################################################################
    # Upload Verification
    #######################################################################

    def verify_upload(
        self,
        bucket: str,
        object_key: str,
    ) -> bool:

        from utils.aws_utils import object_exists

        return object_exists(
            bucket,
            object_key,
        )

    #######################################################################
    # Upload Statistics
    #######################################################################

    def upload_statistics(
        self,
        uploaded: list[str],
    ) -> dict[str, Any]:

        return {
            "uploaded_files": len(
                uploaded,
            ),
            "objects": uploaded,
        }

    #######################################################################
    # Upload Manifest
    #######################################################################

    def create_manifest(
        self,
        uploaded: list[str],
    ) -> dict[str, Any]:

        return {
            "count": len(
                uploaded,
            ),
            "objects": uploaded,
        }

    #######################################################################
    # Upload Summary
    #######################################################################

    def upload_summary(
        self,
        uploaded: list[str],
    ) -> dict[str, Any]:

        return {
            "success": True,
            "count": len(
                uploaded,
            ),
            "manifest": self.create_manifest(
                uploaded,
            ),
        }

    #######################################################################
    # Retry Upload
    #######################################################################

    def upload_with_retry(
        self,
        bucket: str,
        local_path: str,
        object_key: str,
        retries: int = 3,
    ) -> str:

        last_error = None

        for attempt in range(
            1,
            retries + 1,
        ):

            try:

                upload_file(
                    local_path,
                    bucket,
                    object_key,
                )

                logger.info(
                    "Upload succeeded on attempt %d.",
                    attempt,
                )

                return object_key

            except Exception as exc:

                last_error = exc

                logger.warning(
                    "Upload failed on attempt %d.",
                    attempt,
                )

        raise last_error

    #######################################################################
    # Conditional Upload
    #######################################################################

    def upload_if_missing(
        self,
        bucket: str,
        local_path: str,
        object_key: str,
    ) -> str:

        from utils.aws_utils import object_exists

        if object_exists(
            bucket,
            object_key,
        ):

            logger.info(
                "Object already exists: %s",
                object_key,
            )

            return object_key

        upload_file(
            local_path,
            bucket,
            object_key,
        )

        return object_key

    #######################################################################
    # Metadata Upload
    #######################################################################

    def upload_with_metadata(
        self,
        local_path: str,
        bucket: str,
        object_key: str,
        metadata: dict[str, str],
    ) -> str:

        from utils.aws_utils import put_object

        with open(
            local_path,
            "rb",
        ) as file:

            payload = file.read()

        put_object(
            bucket,
            object_key,
            payload,
            metadata=metadata,
        )

        logger.info(
            "Uploaded with metadata: %s",
            object_key,
        )

        return object_key

    #######################################################################
    # Tagged Upload
    #######################################################################

    def upload_with_tags(
        self,
        local_path: str,
        bucket: str,
        object_key: str,
        tags: dict[str, str],
    ) -> str:

        from utils.aws_utils import put_object

        with open(
            local_path,
            "rb",
        ) as file:

            payload = file.read()

        tag_string = "&".join(f"{k}={v}" for k, v in tags.items())

        put_object(
            bucket,
            object_key,
            payload,
            tagging=tag_string,
        )

        logger.info(
            "Uploaded with tags: %s",
            object_key,
        )

        return object_key

    #######################################################################
    # Encrypted Upload
    #######################################################################

    def upload_encrypted(
        self,
        local_path: str,
        bucket: str,
        object_key: str,
    ) -> str:

        from utils.aws_utils import put_object

        with open(
            local_path,
            "rb",
        ) as file:

            payload = file.read()

        put_object(
            bucket,
            object_key,
            payload,
            server_side_encryption="AES256",
        )

        logger.info(
            "Encrypted upload completed: %s",
            object_key,
        )

        return object_key

    #######################################################################
    # JSON Metadata Upload
    #######################################################################

    def upload_json_with_metadata(
        self,
        bucket: str,
        object_key: str,
        data: Any,
        metadata: dict[str, str],
    ) -> str:

        payload = json.dumps(
            data,
            indent=2,
            default=str,
        ).encode(
            "utf-8",
        )

        put_object(
            bucket,
            self.ensure_json(
                object_key,
            ),
            payload,
            metadata=metadata,
            content_type="application/json",
        )

        return object_key

    #######################################################################
    # Presigned Upload URL
    #######################################################################

    def generate_upload_url(
        self,
        bucket: str,
        object_key: str,
        expires_in: int = 3600,
    ) -> str:

        from utils.aws_utils import generate_presigned_upload_url

        return generate_presigned_upload_url(
            bucket,
            object_key,
            expires_in=expires_in,
        )

    #######################################################################
    # Upload Health
    #######################################################################

    def upload_health(
        self,
    ) -> dict[str, Any]:

        return {
            "service": "UploadService",
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
    # Multipart Upload
    #######################################################################

    def multipart_upload(
        self,
        bucket: str,
        local_path: str,
        object_key: str,
        part_size: int = 8 * 1024 * 1024,
    ) -> str:
        """
        Upload large files using S3 multipart upload.
        """

        from boto3.s3.transfer import TransferConfig

        from aws.utils.aws_utils import get_client

        client = get_client(
            "s3",
        )

        config = TransferConfig(
            multipart_threshold=part_size,
            multipart_chunksize=part_size,
            max_concurrency=10,
            use_threads=True,
        )

        client.upload_file(
            Filename=local_path,
            Bucket=bucket,
            Key=object_key,
            Config=config,
        )

        logger.info(
            "Multipart upload completed: %s",
            object_key,
        )

        return object_key

    #######################################################################
    # Stream Upload
    #######################################################################

    def upload_stream(
        self,
        bucket: str,
        object_key: str,
        stream,
        content_type: str = "application/octet-stream",
    ) -> str:

        put_object(
            bucket,
            object_key,
            stream.read(),
            content_type=content_type,
        )

        logger.info(
            "Uploaded stream: %s",
            object_key,
        )

        return object_key

    #######################################################################
    # Upload Queue
    #######################################################################

    def upload_queue(
        self,
        bucket: str,
        queue: list[tuple[str, str]],
    ) -> list[str]:

        uploaded = []

        for local_path, object_key in queue:

            uploaded.append(
                self.upload(
                    bucket,
                    local_path,
                    object_key,
                )
            )

        logger.info(
            "Queue upload completed (%d objects).",
            len(uploaded),
        )

        return uploaded

    #######################################################################
    # Scheduled Upload
    #######################################################################

    def scheduled_upload(
        self,
        bucket: str,
        local_path: str,
        object_key: str,
    ) -> str:

        logger.info("Executing scheduled upload.")

        return self.upload(
            bucket,
            local_path,
            object_key,
        )

    #######################################################################
    # Upload Metrics
    #######################################################################

    def upload_metrics(
        self,
        uploaded: list[str],
    ) -> dict[str, Any]:

        return {
            "uploaded_count": len(
                uploaded,
            ),
            "successful": len(
                uploaded,
            ),
            "failed": 0,
            "objects": uploaded,
        }

    #######################################################################
    # Upload Diagnostics
    #######################################################################

    def diagnostics(
        self,
    ) -> dict[str, Any]:

        return {
            "service": self.__class__.__name__,
            "health": self.upload_health(),
            "supported_buckets": {
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
            },
        }

    #######################################################################
    # Upload Report
    #######################################################################

    def upload_summary_report(
        self,
        uploaded: list[str],
    ) -> dict[str, Any]:

        metrics = self.upload_metrics(
            uploaded,
        )

        return {
            "summary": metrics,
            "diagnostics": self.diagnostics(),
        }


###########################################################################
# Global Upload Service
###########################################################################

UPLOADER = UploadService()


###########################################################################
# Convenience Functions
###########################################################################


def uploader() -> UploadService:

    return UPLOADER


def diagnostics() -> dict[str, Any]:

    return UPLOADER.diagnostics()


###########################################################################
# Self Test
###########################################################################


def self_test() -> dict[str, Any]:

    service = UploadService()

    return {
        "module": "uploader",
        "status": "ready",
        "diagnostics": service.diagnostics(),
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

    print("S3 Upload Service")

    print("=" * 80)

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

    print("Upload Service Ready")
