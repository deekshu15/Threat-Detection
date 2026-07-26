"""
lambda_function.py

AWS Lambda entry point for Threat Enrichment.

Pipeline

MITRE Mapper
      │
      ▼
Threat Enrichment Lambda
      │
      ▼
Enriched Security Event
"""

import json
import logging
import traceback
from typing import Any, Dict

from aws.lambdas.threat_enrichment.enrichment import enrich_event

# ------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------

logger = logging.getLogger()
logger.setLevel(logging.INFO)


# ------------------------------------------------------------------
# Response Helpers
# ------------------------------------------------------------------

def success_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Standard success response.
    """

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "success": True,
                "message": "Threat enrichment completed successfully.",
                "data": data,
            },
            default=str,
        ),
    }


def error_response(message: str, status_code: int = 500) -> Dict[str, Any]:
    """
    Standard error response.
    """

    return {
        "statusCode": status_code,
        "body": json.dumps(
            {
                "success": False,
                "message": message,
            }
        ),
    }


# ------------------------------------------------------------------
# Event Extraction
# ------------------------------------------------------------------

def extract_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract security event from Lambda invocation.

    Supports:
    - Direct invocation
    - API Gateway
    """

    if "body" in event:

        body = event["body"]

        if isinstance(body, str):
            return json.loads(body)

        return body

    return event


# ------------------------------------------------------------------
# Lambda Handler
# ------------------------------------------------------------------

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda entry point.
    """

    logger.info("Threat Enrichment Lambda Started")

    try:

        security_event = extract_event(event)

        logger.info(
            "Received Event: %s",
            json.dumps(security_event, default=str),
        )

        enriched_event = enrich_event(security_event)

        logger.info("Threat enrichment completed successfully.")

        return success_response(enriched_event)

    except ValueError as ex:

        logger.error(str(ex))

        return error_response(str(ex), 400)

    except TypeError as ex:

        logger.error(str(ex))

        return error_response(str(ex), 400)

    except Exception as ex:

        logger.error(traceback.format_exc())

        return error_response(
            f"Internal Server Error: {str(ex)}",
            500,
        )