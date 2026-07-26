"""
Feature Engineering Lambda

AWS Lambda entry point for the
Feature Engineering pipeline.

Flow

Lambda Event
      │
      ▼
Feature Pipeline
      │
      ▼
ML Ready Features
      │
      ▼
Return to ML Engine

Author:
AI Threat Detection Dashboard
"""

from __future__ import annotations

import json
import logging
from typing import Dict, List

from .feature_pipeline import (
    process_event,
    process_events,
)

logger = logging.getLogger()

logger.setLevel(logging.INFO)
# ---------------------------------------------------------
# Response
# ---------------------------------------------------------

def success_response(
    body,
):

    return {

        "statusCode": 200,

        "body": json.dumps(

            body,

            default=str,

        ),

    }


def error_response(
    message,
):

    return {

        "statusCode": 500,

        "body": json.dumps(

            {

                "success": False,

                "error": str(message),

            }

        ),

    }
# ---------------------------------------------------------
# Parse Event
# ---------------------------------------------------------

def parse_event(
    event,
):

    #
    # Direct invocation
    #

    if isinstance(

        event,

        dict,

    ):

        if "records" in event:

            return event["records"]

        return event

    #
    # JSON string
    #

    if isinstance(

        event,

        str,

    ):

        return json.loads(

            event

        )

    raise ValueError(

        "Unsupported event."

    )
# ---------------------------------------------------------
# Lambda Handler
# ---------------------------------------------------------

def lambda_handler(
    event,
    context,
):

    try:

        payload = parse_event(event)

        #
        # Batch Processing
        #

        if isinstance(payload, list):

            logger.info(

                "Processing %d events.",

                len(payload),

            )

            results = process_events(

                payload

            )

            return success_response(

                {

                    "success": True,

                    "batch_size": len(results),

                    "results": results,

                }

            )

        #
        # Single Event
        #

        logger.info(

            "Processing single event."

        )

        result = process_event(

            payload

        )

        return success_response(

            {

                "success": True,

                "result": result,

            }

        )

    except Exception as exc:

        logger.exception(

            "Feature Engineering Pipeline Failed"

        )

        return error_response(

            exc

        )


# ---------------------------------------------------------
# Local Testing
# ---------------------------------------------------------

if __name__ == "__main__":

    sample_event = {

        "event_id": "EVT-1001",

        "timestamp": "2026-07-25T10:15:30",

        "src_ip": "192.168.1.10",

        "dest_ip": "8.8.8.8",

        "protocol": "TCP",

        "severity": "HIGH",

        "event_category": "Malware",

        "asset_criticality": "CRITICAL",

        "threat_score": 95,

        "cvss_score": 9.8,

        "matched_ioc": True,

        "mitre_technique_id": "T1486",

        "mitre_tactic": "Impact",

        "user": "admin",

        "host": "server01",

        "src_port": 50555,

        "dest_port": 443,

    }

    response = lambda_handler(

        sample_event,

        None,

    )

    print(response)