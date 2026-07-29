"""
Enterprise Threat Enrichment Lambda

Supports

• EventBridge
• SQS
• SNS
• API Gateway
• Direct Invocation

Cold Start

    Initialize services once

Warm Invocation

    Reuse initialized services
"""

from __future__ import annotations

import json
import traceback

from datetime import UTC
from datetime import datetime

from logger import get_logger

from validators.validator_factory import ValidatorFactory

from validators.event_validator import EventValidator

from services.ioc_service import IOCService
from services.cve_service import CVEService
from services.mitre_service import MITREService
from services.asset_service import AssetService
from services.behavior_service import BehaviorService
from services.threat_score_service import ThreatScoreService
from services.enrichment_pipeline import EnrichmentPipeline
from services.cache_service import CacheService

from models.event import ThreatEvent

logger = get_logger("Lambda")
####################################################################
# Global Services
####################################################################

CACHE = CacheService()

IOC = IOCService()

CVE = CVEService()

MITRE = MITREService()

ASSET = AssetService()

BEHAVIOR = BehaviorService()

VALIDATOR = ValidatorFactory()

VALIDATOR.register(

    "default",

    EventValidator(),

)

THREAT_SCORE = ThreatScoreService(

    IOC,

    CVE,

    MITRE,

    ASSET,

    BEHAVIOR,

)

PIPELINE = EnrichmentPipeline(

    VALIDATOR,

    IOC,

    CVE,

    MITRE,

    ASSET,

    BEHAVIOR,

    THREAT_SCORE,

)
####################################################################
# Cold Start
####################################################################

_initialized = False


def initialize():

    global _initialized

    if _initialized:

        return

    logger.info(
        "Initializing services..."
    )

    IOC.initialize()

    CVE.initialize()

    MITRE.initialize()

    ASSET.initialize()

    BEHAVIOR.initialize()

    CACHE.initialize()

    THREAT_SCORE.initialize()

    PIPELINE.initialize()

    _initialized = True

    logger.info(
        "Initialization completed."
    )


initialize()
####################################################################
# Response
####################################################################

def success_response(
    body,
):

    return {

        "statusCode": 200,

        "headers": {

            "Content-Type":
                "application/json",

        },

        "body": json.dumps(

            body,

            default=str,

        ),

    }


def error_response(

    message,

    status=500,

):

    return {

        "statusCode": status,

        "headers": {

            "Content-Type":
                "application/json",

        },

        "body": json.dumps({

            "success": False,

            "error": message,

        }),

    }
    ####################################################################
# Parse Event
####################################################################

def parse_event(

    event,

):

    #
    # API Gateway
    #

    if "body" in event:

        body = event["body"]

        if isinstance(body, str):

            body = json.loads(body)

        return body

    #
    # Direct Lambda
    #

    if isinstance(event, dict):

        return event

    raise ValueError(

        "Unsupported event format."

    )
    ####################################################################
    # Build ThreatEvent
    ####################################################################

def build_event(

    payload,

):

    return ThreatEvent.from_dict(

        payload

    )
     ####################################################################
# Execute Pipeline
####################################################################

def process_payload(
    payload,
):

    event = build_event(
        payload
    )

    enriched = PIPELINE.process(
        event
    )

    return enriched.to_api_response()
####################################################################
# Detect Event Source
####################################################################

def detect_source(
    event,
) -> str:

    if "Records" not in event:

        return "DIRECT"

    record = event["Records"][0]

    source = record.get(
        "eventSource",
        ""
    )

    if source == "aws:sqs":

        return "SQS"

    if source == "aws:sns":

        return "SNS"

    if source == "aws:kinesis":

        return "KINESIS"

    return "UNKNOWN"
####################################################################
# Batch Processing
####################################################################

def process_records(
    records,
):

    results = []

    for record in records:

        #
        # SQS
        #

        if "body" in record:

            payload = json.loads(
                record["body"]
            )

        #
        # SNS
        #

        elif "Sns" in record:

            payload = json.loads(

                record["Sns"]["Message"]

            )

        else:

            continue

        results.append(

            process_payload(
                payload
            )

        )

    return results
####################################################################
# Lambda Handler
####################################################################

def lambda_handler(
    event,
    context,
):

    started = datetime.now(
        UTC
    )

    request_id = getattr(
        context,
        "aws_request_id",
        None,
    )

    logger.info(

        "Request started",

        extra={

            "request_id":
                request_id,

        },

    )

    try:

        ###############################################################
        # Batch Sources
        ###############################################################

        if "Records" in event:

            results = process_records(

                event["Records"]

            )

        ###############################################################
        # API Gateway / EventBridge / Direct
        ###############################################################

        else:

            payload = parse_event(
                event
            )

            results = process_payload(
                payload
            )

        ###############################################################
        # Success
        ###############################################################

        duration = (

            datetime.now(
                UTC
            )

            - started

        ).total_seconds() * 1000

        return success_response({

            "success": True,

            "request_id":
                request_id,

            "processed_at":

                datetime.now(
                    UTC
                ).isoformat(),

            "processing_time_ms":

                round(duration, 2),

            "result":

                results,

        })

    except Exception as exc:

        logger.exception(

            traceback.format_exc()

        )

        return error_response(

            str(exc),

            500,

        )
    ####################################################################
# Runtime Metrics
####################################################################

def runtime_metrics():

    return {

        "pipeline":

            PIPELINE.stats(),

        "cache":

            CACHE.stats(),

        "ioc":

            IOC.stats(),

        "cve":

            CVE.stats(),

        "mitre":

            MITRE.stats(),

        "asset":

            ASSET.stats(),

        "behavior":

            BEHAVIOR.stats(),

        "threat_score":

            THREAT_SCORE.stats(),

    }
    
    ####################################################################
# Health
####################################################################

def health():

    return {

        "status":
            "healthy",

        "timestamp":

            datetime.now(
                UTC
            ).isoformat(),

        "services": {

            "pipeline":

                PIPELINE.health(),

            "cache":

                CACHE.health(),

            "ioc":

                IOC.health(),

            "cve":

                CVE.health(),

            "mitre":

                MITRE.health(),

            "asset":

                ASSET.health(),

            "behavior":

                BEHAVIOR.health(),

            "threat_score":

                THREAT_SCORE.health(),

        },

    }
    ####################################################################
# Version
####################################################################

VERSION = "1.0.0"

BUILD_DATE = "2026-07-29"

####################################################################
# Warmup
####################################################################

def warmup():

    return {

        "success": True,

        "message": "Lambda warm.",

        "initialized": _initialized,

        "timestamp": datetime.now(
            UTC
        ).isoformat(),

    }

####################################################################
# Refresh Services
####################################################################

def refresh_services():

    IOC.refresh()

    CVE.refresh()

    MITRE.refresh()

    ASSET.refresh()

    BEHAVIOR.refresh()

    CACHE.refresh()

    THREAT_SCORE.refresh()

    PIPELINE.refresh()

    return {

        "success": True,

        "message": "Services refreshed.",

    }

####################################################################
# Diagnostics
####################################################################

def diagnostics():

    return {

        "version": VERSION,

        "build_date": BUILD_DATE,

        "pipeline":

            PIPELINE.diagnostics(),

        "cache":

            CACHE.diagnostics(),

        "ioc":

            IOC.diagnostics(),

        "cve":

            CVE.diagnostics(),

        "mitre":

            MITRE.diagnostics(),

        "asset":

            ASSET.diagnostics(),

        "behavior":

            BEHAVIOR.diagnostics(),

        "threat_score":

            THREAT_SCORE.diagnostics(),

    }

####################################################################
# Configuration
####################################################################

def configuration():

    return {

        "version":
            VERSION,

        "build_date":
            BUILD_DATE,

        "services": [

            "validator",

            "ioc",

            "cve",

            "mitre",

            "asset",

            "behavior",

            "threat_score",

            "pipeline",

            "cache",

        ],

        "initialized":

            _initialized,

    }

####################################################################
# Administrative Operations
####################################################################

def admin_operation(

    operation: str,

):

    operations = {

        "health":

            health,

        "metrics":

            runtime_metrics,

        "diagnostics":

            diagnostics,

        "configuration":

            configuration,

        "refresh":

            refresh_services,

        "warmup":

            warmup,

    }

    handler = operations.get(

        operation

    )

    if handler is None:

        raise ValueError(

            f"Unsupported admin operation: {operation}"

        )

    return handler()

####################################################################
# Shutdown
####################################################################

def shutdown():

    logger.info(

        "Shutting down services..."

    )

    PIPELINE.shutdown()

    THREAT_SCORE.shutdown()

    BEHAVIOR.shutdown()

    ASSET.shutdown()

    MITRE.shutdown()

    CVE.shutdown()

    IOC.shutdown()

    CACHE.shutdown()

####################################################################
# Cleanup Hook
####################################################################

import atexit

atexit.register(

    shutdown

)
