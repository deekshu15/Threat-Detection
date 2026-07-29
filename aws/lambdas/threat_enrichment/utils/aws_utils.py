"""
AWS Utility Layer

Centralized helpers for AWS services used by the threat enrichment platform.

Features
--------
• AWS Session Management
• Client / Resource Creation
• Standardized AWS Error Handling
• S3 Upload / Download
• S3 JSON Operations
• S3 Object Management
• S3 Pagination
• S3 Presigned URLs
"""

from __future__ import annotations

import json
import logging
import os

from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator

try:
    import boto3

    from botocore.config import Config
    from botocore.exceptions import (
        BotoCoreError,
        ClientError,
        NoCredentialsError,
        PartialCredentialsError,
    )

except ImportError as exc:
    raise RuntimeError(
        "boto3 is required for aws_utils.py. "
        "Install it with: pip install boto3"
    ) from exc


logger = logging.getLogger(__name__)

###########################################################################
# Configuration
###########################################################################

DEFAULT_REGION = os.getenv(
    "AWS_REGION",
    os.getenv(
        "AWS_DEFAULT_REGION",
        "us-east-1",
    ),
)


DEFAULT_CONNECT_TIMEOUT = float(
    os.getenv(
        "AWS_CONNECT_TIMEOUT",
        "5",
    )
)


DEFAULT_READ_TIMEOUT = float(
    os.getenv(
        "AWS_READ_TIMEOUT",
        "30",
    )
)


DEFAULT_MAX_ATTEMPTS = int(
    os.getenv(
        "AWS_MAX_ATTEMPTS",
        "5",
    )
)


AWS_CONFIG = Config(
    region_name=DEFAULT_REGION,

    connect_timeout=DEFAULT_CONNECT_TIMEOUT,

    read_timeout=DEFAULT_READ_TIMEOUT,

    retries={
        "max_attempts": DEFAULT_MAX_ATTEMPTS,
        "mode": "adaptive",
    },
)

###########################################################################
# Exceptions
###########################################################################

class AWSUtilityError(Exception):
    """
    Base exception raised by AWS utility operations.
    """

    def __init__(
        self,
        message: str,
        *,
        service: str | None = None,
        operation: str | None = None,
        error_code: str | None = None,
    ):

        super().__init__(message)

        self.service = service
        self.operation = operation
        self.error_code = error_code

    def to_dict(self) -> dict[str, Any]:

        return {
            "message": str(self),
            "service": self.service,
            "operation": self.operation,
            "error_code": self.error_code,
        }
        
    ###########################################################################
# Error Handling
###########################################################################

def _raise_aws_error(
    exc: Exception,
    *,
    service: str,
    operation: str,
) -> None:

    if isinstance(exc, ClientError):

        error = (
            exc.response
            .get("Error", {})
        )

        code = error.get(
            "Code",
            "Unknown",
        )

        message = error.get(
            "Message",
            str(exc),
        )

        logger.exception(
            "AWS %s.%s failed [%s]: %s",
            service,
            operation,
            code,
            message,
        )

        raise AWSUtilityError(
            message,
            service=service,
            operation=operation,
            error_code=code,
        ) from exc

    if isinstance(
        exc,
        (
            NoCredentialsError,
            PartialCredentialsError,
        ),
    ):

        logger.exception(
            "AWS credentials error during %s.%s",
            service,
            operation,
        )

        raise AWSUtilityError(
            "AWS credentials are unavailable or incomplete.",
            service=service,
            operation=operation,
            error_code="CredentialsError",
        ) from exc

    if isinstance(
        exc,
        BotoCoreError,
    ):

        logger.exception(
            "AWS SDK error during %s.%s",
            service,
            operation,
        )

        raise AWSUtilityError(
            str(exc),
            service=service,
            operation=operation,
            error_code=type(exc).__name__,
        ) from exc

    raise exc

###########################################################################
# Session
###########################################################################

@lru_cache(maxsize=8)
def get_session(
    region_name: str | None = None,
    profile_name: str | None = None,
):

    kwargs: dict[str, Any] = {}

    if region_name:
        kwargs["region_name"] = region_name

    if profile_name:
        kwargs["profile_name"] = profile_name

    return boto3.Session(
        **kwargs
    )
    
    ###########################################################################
# Client Factory
###########################################################################

@lru_cache(maxsize=64)
def get_client(
    service_name: str,
    region_name: str | None = None,
):

    session = get_session(
        region_name=region_name,
    )

    return session.client(
        service_name,
        config=AWS_CONFIG,
    )


def get_resource(
    service_name: str,
    region_name: str | None = None,
):

    session = get_session(
        region_name=region_name,
    )

    return session.resource(
        service_name,
        config=AWS_CONFIG,
    )
    
    ###########################################################################
# AWS Identity
###########################################################################

def get_caller_identity() -> dict[str, Any]:

    client = get_client(
        "sts"
    )

    try:

        response = (
            client.get_caller_identity()
        )

        return {
            "account":
                response.get("Account"),

            "arn":
                response.get("Arn"),

            "user_id":
                response.get("UserId"),
        }

    except Exception as exc:

        _raise_aws_error(
            exc,
            service="sts",
            operation="GetCallerIdentity",
        )
        
###########################################################################
# S3
###########################################################################

def s3_client():

    return get_client(
        "s3"
    )
    
    def bucket_exists(
        bucket: str,
    ) -> bool:

        client = s3_client()

        try:

            client.head_bucket(
            Bucket=bucket
           )

            return True

        except ClientError as exc:

            code = (
            exc.response
            .get("Error", {})
            .get("Code")
            )

            if code in {
                "404",
                "NoSuchBucket",
            }:

                return False

            _raise_aws_error(
                exc,
                service="s3",
                operation="HeadBucket",
            )

        return False
    
def object_exists(
    bucket: str,
    key: str,
) -> bool:

    client = s3_client()

    try:

        client.head_object(
            Bucket=bucket,
            Key=key,
        )

        return True

    except ClientError as exc:

        code = (
            exc.response
            .get("Error", {})
            .get("Code")
        )

        status = (
            exc.response
            .get(
                "ResponseMetadata",
                {},
            )
            .get("HTTPStatusCode")
        )

        if (
            code in {
                "404",
                "NoSuchKey",
                "NotFound",
            }
            or status == 404
        ):

            return False

        _raise_aws_error(
            exc,
            service="s3",
            operation="HeadObject",
        )

    return False
 
 
def upload_file(
    local_path: str | Path,
    bucket: str,
    key: str,
    *,
    extra_args: dict[str, Any] | None = None,
) -> dict[str, Any]:

    client = s3_client()

    path = Path(
        local_path
    )

    if not path.is_file():

        raise FileNotFoundError(
            f"File not found: {path}"
        )

    try:

        client.upload_file(
            str(path),
            bucket,
            key,
            ExtraArgs=extra_args or {},
        )

        return {
            "bucket": bucket,
            "key": key,
            "size": path.stat().st_size,
            "uri": f"s3://{bucket}/{key}",
        }

    except Exception as exc:

        _raise_aws_error(
            exc,
            service="s3",
            operation="UploadFile",
        )
        
def download_file(
    bucket: str,
    key: str,
    destination: str | Path,
) -> Path:

    client = s3_client()

    destination = Path(
        destination
    )

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:

        client.download_file(
            bucket,
            key,
            str(destination),
        )

        return destination

    except Exception as exc:

        _raise_aws_error(
            exc,
            service="s3",
            operation="DownloadFile",
        )


def put_bytes(
    bucket: str,
    key: str,
    data: bytes,
    *,
    content_type: str = "application/octet-stream",
    metadata: dict[str, str] | None = None,
) -> dict[str, Any]:

    client = s3_client()

    try:

        response = client.put_object(
            Bucket=bucket,
            Key=key,
            Body=data,
            ContentType=content_type,
            Metadata=metadata or {},
        )

        return {
            "bucket": bucket,
            "key": key,
            "etag": response.get("ETag"),
            "version_id":
                response.get("VersionId"),
        }

    except Exception as exc:

        _raise_aws_error(
            exc,
            service="s3",
            operation="PutObject",
        )
        
def get_bytes(
    bucket: str,
    key: str,
) -> bytes:

    client = s3_client()

    try:

        response = client.get_object(
            Bucket=bucket,
            Key=key,
        )

        return (
            response["Body"]
            .read()
        )

    except Exception as exc:

        _raise_aws_error(
            exc,
            service="s3",
            operation="GetObject",
        )
        
###########################################################################
# S3 JSON
###########################################################################

def put_json(
    bucket: str,
    key: str,
    data: Any,
    *,
    indent: int | None = None,
) -> dict[str, Any]:

    payload = json.dumps(
        data,
        ensure_ascii=False,
        indent=indent,
        default=str,
    ).encode(
        "utf-8"
    )

    return put_bytes(
        bucket,
        key,
        payload,
        content_type="application/json",
    )


def get_json(
    bucket: str,
    key: str,
) -> Any:

    payload = get_bytes(
        bucket,
        key,
    )

    return json.loads(
        payload.decode(
            "utf-8"
        )
    )
    
###########################################################################
# S3 Delete
###########################################################################

def delete_object(
    bucket: str,
    key: str,
) -> bool:

    client = s3_client()

    try:

        client.delete_object(
            Bucket=bucket,
            Key=key,
        )

        return True

    except Exception as exc:

        _raise_aws_error(
            exc,
            service="s3",
            operation="DeleteObject",
        )
        
def delete_objects(
    bucket: str,
    keys: list[str],
) -> dict[str, Any]:

    if not keys:

        return {
            "deleted": [],
            "errors": [],
        }

    client = s3_client()

    deleted = []
    errors = []

    # S3 DeleteObjects accepts at most
    # 1000 keys per request.
    for start in range(
        0,
        len(keys),
        1000,
    ):

        chunk = keys[
            start:start + 1000
        ]

        try:

            response = (
                client.delete_objects(
                    Bucket=bucket,
                    Delete={
                        "Objects": [
                            {
                                "Key": key
                            }
                            for key
                            in chunk
                        ],
                        "Quiet": False,
                    },
                )
            )

            deleted.extend(
                response.get(
                    "Deleted",
                    [],
                )
            )

            errors.extend(
                response.get(
                    "Errors",
                    [],
                )
            )

        except Exception as exc:

            _raise_aws_error(
                exc,
                service="s3",
                operation="DeleteObjects",
            )

    return {
        "deleted": deleted,
        "errors": errors,
    }
    
###########################################################################
# S3 Metadata
###########################################################################

def object_metadata(
    bucket: str,
    key: str,
) -> dict[str, Any]:

    client = s3_client()

    try:

        response = client.head_object(
            Bucket=bucket,
            Key=key,
        )

        return {
            "content_length":
                response.get(
                    "ContentLength"
                ),

            "content_type":
                response.get(
                    "ContentType"
                ),

            "etag":
                response.get(
                    "ETag"
                ),

            "last_modified":
                response.get(
                    "LastModified"
                ),

            "metadata":
                response.get(
                    "Metadata",
                    {},
                ),

            "version_id":
                response.get(
                    "VersionId"
                ),
        }

    except Exception as exc:

        _raise_aws_error(
            exc,
            service="s3",
            operation="HeadObject",
        )
        
###########################################################################
# S3 Pagination
###########################################################################

def iter_objects(
    bucket: str,
    prefix: str = "",
) -> Iterator[dict[str, Any]]:

    client = s3_client()

    try:

        paginator = (
            client.get_paginator(
                "list_objects_v2"
            )
        )

        for page in paginator.paginate(
            Bucket=bucket,
            Prefix=prefix,
        ):

            for item in page.get(
                "Contents",
                [],
            ):

                yield item

    except Exception as exc:

        _raise_aws_error(
            exc,
            service="s3",
            operation="ListObjectsV2",
        )
        
def list_object_keys(
    bucket: str,
    prefix: str = "",
) -> list[str]:

    return [
        item["Key"]

        for item in iter_objects(
            bucket,
            prefix,
        )
    ]
    
 ###########################################################################
# Presigned URLs
###########################################################################

def presigned_download_url(
    bucket: str,
    key: str,
    expires_in: int = 3600,
) -> str:

    client = s3_client()

    try:

        return client.generate_presigned_url(
            "get_object",

            Params={
                "Bucket": bucket,
                "Key": key,
            },

            ExpiresIn=expires_in,
        )

    except Exception as exc:

        _raise_aws_error(
            exc,
            service="s3",
            operation="GeneratePresignedGetObject",
        )


def presigned_upload_url(
    bucket: str,
    key: str,
    expires_in: int = 3600,
) -> str:

    client = s3_client()

    try:

        return client.generate_presigned_url(
            "put_object",

            Params={
                "Bucket": bucket,
                "Key": key,
            },

            ExpiresIn=expires_in,
        )

    except Exception as exc:

        _raise_aws_error(
            exc,
            service="s3",
            operation="GeneratePresignedPutObject",
        )
        
###########################################################################
# S3 Copy
###########################################################################

def copy_object(
    source_bucket: str,
    source_key: str,
    destination_bucket: str,
    destination_key: str,
) -> dict[str, Any]:

    client = s3_client()

    try:

        response = client.copy_object(
            Bucket=destination_bucket,

            Key=destination_key,

            CopySource={
                "Bucket": source_bucket,
                "Key": source_key,
            },
        )

        return {
            "source":
                f"s3://{source_bucket}/{source_key}",

            "destination":
                f"s3://{destination_bucket}/{destination_key}",

            "etag":
                response
                .get(
                    "CopyObjectResult",
                    {},
                )
                .get("ETag"),
        }

    except Exception as exc:

        _raise_aws_error(
            exc,
            service="s3",
            operation="CopyObject",
        )
        

###########################################################################
# SQS
###########################################################################

def sqs_client():
    return get_client("sqs")


def send_sqs_message(
    queue_url: str,
    message: Any,
    *,
    delay_seconds: int = 0,
    message_attributes: dict[str, Any] | None = None,
    message_group_id: str | None = None,
    message_deduplication_id: str | None = None,
) -> dict[str, Any]:
    """
    Send a single message to an SQS queue.

    For dict/list payloads, the message is automatically JSON encoded.
    """

    if not 0 <= delay_seconds <= 900:
        raise ValueError(
            "delay_seconds must be between 0 and 900."
        )

    client = sqs_client()

    body = (
        message
        if isinstance(message, str)
        else json.dumps(
            message,
            ensure_ascii=False,
            default=str,
        )
    )

    params: dict[str, Any] = {
        "QueueUrl": queue_url,
        "MessageBody": body,
        "DelaySeconds": delay_seconds,
    }

    if message_attributes:
        params["MessageAttributes"] = message_attributes

    if message_group_id is not None:
        params["MessageGroupId"] = message_group_id

    if message_deduplication_id is not None:
        params["MessageDeduplicationId"] = (
            message_deduplication_id
        )

    try:
        response = client.send_message(
            **params
        )

        return {
            "message_id":
                response.get("MessageId"),

            "md5":
                response.get("MD5OfMessageBody"),

            "sequence_number":
                response.get("SequenceNumber"),
        }

    except Exception as exc:
        _raise_aws_error(
            exc,
            service="sqs",
            operation="SendMessage",
        )
        
def receive_sqs_messages(
    queue_url: str,
    *,
    max_messages: int = 10,
    wait_time_seconds: int = 10,
    visibility_timeout: int | None = None,
    message_attribute_names: list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Receive up to 10 messages from SQS.
    """

    if not 1 <= max_messages <= 10:
        raise ValueError(
            "max_messages must be between 1 and 10."
        )

    if not 0 <= wait_time_seconds <= 20:
        raise ValueError(
            "wait_time_seconds must be between 0 and 20."
        )

    client = sqs_client()

    params: dict[str, Any] = {
        "QueueUrl": queue_url,
        "MaxNumberOfMessages": max_messages,
        "WaitTimeSeconds": wait_time_seconds,
        "AttributeNames": ["All"],
        "MessageAttributeNames":
            message_attribute_names or ["All"],
    }

    if visibility_timeout is not None:
        params["VisibilityTimeout"] = visibility_timeout

    try:
        response = client.receive_message(
            **params
        )

        return response.get(
            "Messages",
            [],
        )

    except Exception as exc:
        _raise_aws_error(
            exc,
            service="sqs",
            operation="ReceiveMessage",
        )

def parse_sqs_body(
    message: dict[str, Any],
) -> Any:
    """
    Attempt to deserialize an SQS message body as JSON.
    Falls back to the original string.
    """

    body = message.get(
        "Body",
        ""
    )

    try:
        return json.loads(body)

    except (
        json.JSONDecodeError,
        TypeError,
    ):
        return body
    
def delete_sqs_message(
    queue_url: str,
    receipt_handle: str,
) -> bool:

    client = sqs_client()

    try:
        client.delete_message(
            QueueUrl=queue_url,
            ReceiptHandle=receipt_handle,
        )

        return True

    except Exception as exc:
        _raise_aws_error(
            exc,
            service="sqs",
            operation="DeleteMessage",
        )
        

def change_sqs_visibility(
    queue_url: str,
    receipt_handle: str,
    visibility_timeout: int,
) -> bool:

    if not 0 <= visibility_timeout <= 43200:
        raise ValueError(
            "visibility_timeout must be between 0 and 43200 seconds."
        )

    client = sqs_client()

    try:
        client.change_message_visibility(
            QueueUrl=queue_url,
            ReceiptHandle=receipt_handle,
            VisibilityTimeout=visibility_timeout,
        )

        return True

    except Exception as exc:
        _raise_aws_error(
            exc,
            service="sqs",
            operation="ChangeMessageVisibility",
        )  
        
        
###########################################################################
# SQS Batch Send
###########################################################################

def send_sqs_batch(
    queue_url: str,
    messages: list[Any],
) -> dict[str, Any]:

    client = sqs_client()

    successful: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []

    for start in range(
        0,
        len(messages),
        10,
    ):
        chunk = messages[
            start:start + 10
        ]

        entries = []

        for index, message in enumerate(
            chunk,
            start=start,
        ):
            if isinstance(message, dict) and (
                "MessageBody" in message
            ):
                entry = dict(message)

                entry.setdefault(
                    "Id",
                    str(index),
                )

            else:
                body = (
                    message
                    if isinstance(message, str)
                    else json.dumps(
                        message,
                        ensure_ascii=False,
                        default=str,
                    )
                )

                entry = {
                    "Id": str(index),
                    "MessageBody": body,
                }

            entries.append(entry)

        try:
            response = (
                client.send_message_batch(
                    QueueUrl=queue_url,
                    Entries=entries,
                )
            )

            successful.extend(
                response.get(
                    "Successful",
                    [],
                )
            )

            failed.extend(
                response.get(
                    "Failed",
                    [],
                )
            )

        except Exception as exc:
            _raise_aws_error(
                exc,
                service="sqs",
                operation="SendMessageBatch",
            )

    return {
        "successful": successful,
        "failed": failed,
        "successful_count":
            len(successful),
        "failed_count":
            len(failed),
    }
    
###########################################################################
# SQS Batch Delete
###########################################################################

def delete_sqs_batch(
    queue_url: str,
    messages: list[dict[str, Any]],
) -> dict[str, Any]:

    client = sqs_client()

    successful: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []

    for start in range(
        0,
        len(messages),
        10,
    ):
        chunk = messages[
            start:start + 10
        ]

        entries = []

        for index, message in enumerate(
            chunk,
            start=start,
        ):
            receipt_handle = (
                message.get(
                    "ReceiptHandle"
                )
            )

            if not receipt_handle:
                continue

            entries.append({
                "Id": str(index),
                "ReceiptHandle":
                    receipt_handle,
            })

        if not entries:
            continue

        try:
            response = (
                client.delete_message_batch(
                    QueueUrl=queue_url,
                    Entries=entries,
                )
            )

            successful.extend(
                response.get(
                    "Successful",
                    [],
                )
            )

            failed.extend(
                response.get(
                    "Failed",
                    [],
                )
            )

        except Exception as exc:
            _raise_aws_error(
                exc,
                service="sqs",
                operation="DeleteMessageBatch",
            )

    return {
        "successful": successful,
        "failed": failed,
        "successful_count":
            len(successful),
        "failed_count":
            len(failed),
    }
    
###########################################################################
# SQS Queue Pagination
###########################################################################

def iter_sqs_queues(
    prefix: str | None = None,
) -> Iterator[str]:

    client = sqs_client()

    try:
        paginator = (
            client.get_paginator(
                "list_queues"
            )
        )

        params = {}

        if prefix:
            params[
                "QueueNamePrefix"
            ] = prefix

        for page in paginator.paginate(
            **params
        ):
            yield from page.get(
                "QueueUrls",
                [],
            )

    except Exception as exc:
        _raise_aws_error(
            exc,
            service="sqs",
            operation="ListQueues",
        )


def list_sqs_queues(
    prefix: str | None = None,
) -> list[str]:

    return list(
        iter_sqs_queues(
            prefix
        )
    )
    
def get_sqs_attributes(
    queue_url: str,
) -> dict[str, Any]:

    client = sqs_client()

    try:
        response = (
            client.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=["All"],
            )
        )

        return response.get(
            "Attributes",
            {},
        )

    except Exception as exc:
        _raise_aws_error(
            exc,
            service="sqs",
            operation="GetQueueAttributes",
        )
        
###########################################################################
# SNS
###########################################################################

def sns_client():
    return get_client("sns")

def publish_sns(
    topic_arn: str,
    message: Any,
    *,
    subject: str | None = None,
    message_attributes: dict[str, Any] | None = None,
    message_group_id: str | None = None,
    message_deduplication_id: str | None = None,
) -> dict[str, Any]:

    client = sns_client()

    body = (
        message
        if isinstance(message, str)
        else json.dumps(
            message,
            ensure_ascii=False,
            default=str,
        )
    )

    params: dict[str, Any] = {
        "TopicArn": topic_arn,
        "Message": body,
    }

    if subject:
        params["Subject"] = subject

    if message_attributes:
        params[
            "MessageAttributes"
        ] = message_attributes

    if message_group_id:
        params[
            "MessageGroupId"
        ] = message_group_id

    if message_deduplication_id:
        params[
            "MessageDeduplicationId"
        ] = message_deduplication_id

    try:
        response = client.publish(
            **params
        )

        return {
            "message_id":
                response.get(
                    "MessageId"
                ),

            "sequence_number":
                response.get(
                    "SequenceNumber"
                ),
        }

    except Exception as exc:
        _raise_aws_error(
            exc,
            service="sns",
            operation="Publish",
        )
        
def iter_sns_topics() -> Iterator[str]:

    client = sns_client()

    try:
        paginator = (
            client.get_paginator(
                "list_topics"
            )
        )

        for page in paginator.paginate():

            for topic in page.get(
                "Topics",
                [],
            ):
                arn = topic.get(
                    "TopicArn"
                )

                if arn:
                    yield arn

    except Exception as exc:
        _raise_aws_error(
            exc,
            service="sns",
            operation="ListTopics",
        )


def list_sns_topics() -> list[str]:

    return list(
        iter_sns_topics()
    )
    
    
def iter_sns_subscriptions(
    topic_arn: str,
) -> Iterator[dict[str, Any]]:

    client = sns_client()

    try:
        paginator = (
            client.get_paginator(
                "list_subscriptions_by_topic"
            )
        )

        for page in paginator.paginate(
            TopicArn=topic_arn
        ):
            yield from page.get(
                "Subscriptions",
                [],
            )

    except Exception as exc:
        _raise_aws_error(
            exc,
            service="sns",
            operation="ListSubscriptionsByTopic",
        )
        
###########################################################################
# EventBridge
###########################################################################

def eventbridge_client():
    return get_client(
        "events"
    )
    
def publish_event(
    source: str,
    detail_type: str,
    detail: Any,
    *,
    event_bus_name: str = "default",
    resources: list[str] | None = None,
) -> dict[str, Any]:

    result = publish_events([
        {
            "Source": source,
            "DetailType": detail_type,
            "Detail": (
                detail
                if isinstance(detail, str)
                else json.dumps(
                    detail,
                    ensure_ascii=False,
                    default=str,
                )
            ),
            "EventBusName":
                event_bus_name,

            **(
                {
                    "Resources":
                        resources
                }
                if resources
                else {}
            ),
        }
    ])

    if result["entries"]:
        return result["entries"][0]

    return {}

def publish_events(
    events: list[dict[str, Any]],
) -> dict[str, Any]:

    client = eventbridge_client()

    entries_result = []
    failed_count = 0

    for start in range(
        0,
        len(events),
        10,
    ):
        chunk = events[
            start:start + 10
        ]

        prepared = []

        for event in chunk:
            item = dict(event)

            detail = item.get(
                "Detail"
            )

            if not isinstance(
                detail,
                str,
            ):
                item["Detail"] = (
                    json.dumps(
                        detail,
                        ensure_ascii=False,
                        default=str,
                    )
                )

            prepared.append(item)

        try:
            response = client.put_events(
                Entries=prepared
            )

            failed_count += (
                response.get(
                    "FailedEntryCount",
                    0,
                )
            )

            entries_result.extend(
                response.get(
                    "Entries",
                    [],
                )
            )

        except Exception as exc:
            _raise_aws_error(
                exc,
                service="events",
                operation="PutEvents",
            )

    failures = [
        entry
        for entry
        in entries_result
        if entry.get("ErrorCode")
    ]

    return {
        "entries":
            entries_result,

        "failed_count":
            failed_count,

        "failures":
            failures,

        "successful_count":
            len(entries_result)
            - len(failures),
    }
    
def iter_event_buses() -> Iterator[
    dict[str, Any]
]:

    client = eventbridge_client()

    try:
        paginator = (
            client.get_paginator(
                "list_event_buses"
            )
        )

        for page in paginator.paginate():

            yield from page.get(
                "EventBuses",
                [],
            )

    except Exception as exc:
        _raise_aws_error(
            exc,
            service="events",
            operation="ListEventBuses",
        )


def list_event_buses() -> list[
    dict[str, Any]
]:

    return list(
        iter_event_buses()
    )
    
def iter_event_rules(
    *,
    event_bus_name: str = "default",
    prefix: str | None = None,
) -> Iterator[dict[str, Any]]:

    client = eventbridge_client()

    params: dict[str, Any] = {
        "EventBusName":
            event_bus_name,
    }

    if prefix:
        params[
            "NamePrefix"
        ] = prefix

    try:
        paginator = (
            client.get_paginator(
                "list_rules"
            )
        )

        for page in paginator.paginate(
            **params
        ):
            yield from page.get(
                "Rules",
                [],
            )

    except Exception as exc:
        _raise_aws_error(
            exc,
            service="events",
            operation="ListRules",
        )
        
###########################################################################
# Lambda
###########################################################################

def lambda_client():
    return get_client(
        "lambda"
    )
    
def invoke_lambda(
    function_name: str,
    payload: Any | None = None,
    *,
    invocation_type: str = "RequestResponse",
    qualifier: str | None = None,
    log_type: str = "None",
) -> dict[str, Any]:

    valid_types = {
        "RequestResponse",
        "Event",
        "DryRun",
    }

    if invocation_type not in valid_types:
        raise ValueError(
            "invocation_type must be "
            "'RequestResponse', 'Event', or 'DryRun'."
        )

    client = lambda_client()

    params: dict[str, Any] = {
        "FunctionName":
            function_name,

        "InvocationType":
            invocation_type,

        "LogType":
            log_type,
    }

    if qualifier:
        params["Qualifier"] = qualifier

    if payload is not None:
        encoded_payload = (
            payload
            if isinstance(
                payload,
                bytes,
            )
            else json.dumps(
                payload,
                ensure_ascii=False,
                default=str,
            ).encode("utf-8")
        )

        params["Payload"] = (
            encoded_payload
        )

    try:
        response = client.invoke(
            **params
        )

        result: dict[str, Any] = {
            "status_code":
                response.get(
                    "StatusCode"
                ),

            "function_error":
                response.get(
                    "FunctionError"
                ),

            "executed_version":
                response.get(
                    "ExecutedVersion"
                ),

            "log_result":
                response.get(
                    "LogResult"
                ),

            "payload":
                None,
        }

        response_payload = (
            response.get(
                "Payload"
            )
        )

        if response_payload is not None:

            raw = (
                response_payload.read()
            )

            if raw:

                decoded = raw.decode(
                    "utf-8"
                )

                try:
                    result["payload"] = (
                        json.loads(
                            decoded
                        )
                    )

                except json.JSONDecodeError:
                    result[
                        "payload"
                    ] = decoded

        return result

    except Exception as exc:
        _raise_aws_error(
            exc,
            service="lambda",
            operation="Invoke",
        )
        
def invoke_lambda_sync(
    function_name: str,
    payload: Any | None = None,
    *,
    qualifier: str | None = None,
) -> Any:

    response = invoke_lambda(
        function_name,
        payload,
        invocation_type="RequestResponse",
        qualifier=qualifier,
    )

    if response.get(
        "function_error"
    ):
        raise AWSUtilityError(
            (
                "Lambda function returned "
                f"{response['function_error']}: "
                f"{response.get('payload')}"
            ),
            service="lambda",
            operation="Invoke",
            error_code=response[
                "function_error"
            ],
        )

    return response.get(
        "payload"
    )
    
def invoke_lambda_async(
    function_name: str,
    payload: Any | None = None,
    *,
    qualifier: str | None = None,
) -> dict[str, Any]:

    return invoke_lambda(
        function_name,
        payload,
        invocation_type="Event",
        qualifier=qualifier,
    )
    
def iter_lambda_functions() -> Iterator[
    dict[str, Any]
]:

    client = lambda_client()

    try:
        paginator = (
            client.get_paginator(
                "list_functions"
            )
        )

        for page in paginator.paginate():

            yield from page.get(
                "Functions",
                [],
            )

    except Exception as exc:
        _raise_aws_error(
            exc,
            service="lambda",
            operation="ListFunctions",
        )


def list_lambda_functions() -> list[
    dict[str, Any]
]:

    return list(
        iter_lambda_functions()
    )
    
    
def get_lambda_function(
    function_name: str,
    *,
    qualifier: str | None = None,
) -> dict[str, Any]:

    client = lambda_client()

    params: dict[str, Any] = {
        "FunctionName":
            function_name
    }

    if qualifier:
        params[
            "Qualifier"
        ] = qualifier

    try:
        return client.get_function(
            **params
        )

    except Exception as exc:
        _raise_aws_error(
            exc,
            service="lambda",
            operation="GetFunction",
        )
        
###########################################################################
# Lambda Batch
###########################################################################

def invoke_lambda_batch(
    function_name: str,
    payloads: list[Any],
    *,
    asynchronous: bool = False,
    continue_on_error: bool = True,
) -> dict[str, Any]:

    successful = []
    failed = []

    for index, payload in enumerate(
        payloads
    ):

        try:
            if asynchronous:

                result = (
                    invoke_lambda_async(
                        function_name,
                        payload,
                    )
                )

            else:

                result = (
                    invoke_lambda_sync(
                        function_name,
                        payload,
                    )
                )

            successful.append({
                "index": index,
                "result": result,
            })

        except Exception as exc:

            failed.append({
                "index": index,
                "error": str(exc),
                "type":
                    type(exc).__name__,
            })

            if not continue_on_error:
                raise

    return {
        "successful":
            successful,

        "failed":
            failed,

        "successful_count":
            len(successful),

        "failed_count":
            len(failed),
    }
    
###########################################################################
# Generic Pagination
###########################################################################

def paginate(
    service_name: str,
    operation_name: str,
    *,
    result_key: str,
    region_name: str | None = None,
    **kwargs,
) -> Iterator[Any]:

    client = get_client(
        service_name,
        region_name,
    )

    try:
        paginator = (
            client.get_paginator(
                operation_name
            )
        )

        for page in paginator.paginate(
            **kwargs
        ):
            yield from page.get(
                result_key,
                [],
            )

    except Exception as exc:
        _raise_aws_error(
            exc,
            service=service_name,
            operation=operation_name,
        )
        
###########################################################################
# Generic AWS Operation
###########################################################################

def aws_call(
    service_name: str,
    operation_name: str,
    *,
    region_name: str | None = None,
    **kwargs,
) -> dict[str, Any]:

    client = get_client(
        service_name,
        region_name,
    )

    operation = getattr(
        client,
        operation_name,
        None,
    )

    if operation is None:
        raise ValueError(
            f"AWS service '{service_name}' "
            f"does not expose operation "
            f"'{operation_name}'."
        )

    try:
        return operation(
            **kwargs
        )

    except Exception as exc:
        _raise_aws_error(
            exc,
            service=service_name,
            operation=operation_name,
        )
        
###########################################################################
# Messaging Diagnostics
###########################################################################

def messaging_diagnostics() -> dict[str, Any]:

    return {
        "sqs": {
            "client":
                "available",

            "batch_size":
                10,

            "long_poll_max_seconds":
                20,

            "visibility_max_seconds":
                43200,
        },

        "sns": {
            "client":
                "available",

            "topic_pagination":
                True,

            "subscription_pagination":
                True,
        },

        "eventbridge": {
            "client":
                "available",

            "put_events_batch_size":
                10,

            "event_bus_pagination":
                True,

            "rule_pagination":
                True,
        },

        "lambda": {
            "client":
                "available",

            "sync_invocation":
                True,

            "async_invocation":
                True,

            "dry_run":
                True,

            "function_pagination":
                True,
        },
    }
    
###########################################################################
# Diagnostics
###########################################################################

def diagnostics() -> dict[str, Any]:

    result = {
        "module":
            "aws_utils",

        "region":
            DEFAULT_REGION,

        "connect_timeout":
            DEFAULT_CONNECT_TIMEOUT,

        "read_timeout":
            DEFAULT_READ_TIMEOUT,

        "max_attempts":
            DEFAULT_MAX_ATTEMPTS,

        "services": {
            "s3":
                True,

            "sqs":
                True,

            "sns":
                True,

            "eventbridge":
                True,

            "lambda":
                True,

            "sts":
                True,
        },

        "messaging":
            messaging_diagnostics(),

        "identity":
            None,

        "identity_error":
            None,
    }

    try:
        result[
            "identity"
        ] = get_caller_identity()

    except Exception as exc:
        result[
            "identity_error"
        ] = str(exc)

    return result

###########################################################################
# Cache Management
###########################################################################

def clear_aws_client_cache() -> None:

    get_client.cache_clear()

    get_session.cache_clear()
    

###########################################################################
# Self Test
###########################################################################

def self_test() -> dict[str, Any]:

    result = {
        "passed": True,
        "boto3":
            True,

        "region":
            DEFAULT_REGION,

        "clients": {},
    }

    services = [
        "s3",
        "sqs",
        "sns",
        "events",
        "lambda",
        "sts",
    ]

    for service in services:

        try:
            client = get_client(
                service
            )

            result[
                "clients"
            ][service] = (
                client is not None
            )

        except Exception as exc:

            result["passed"] = False

            result[
                "clients"
            ][service] = {
                "available": False,
                "error": str(exc),
            }

    return result

