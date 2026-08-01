"""
producers.py

Enterprise AWS Kinesis Producers

Responsibilities
----------------
• Put single record
• Put batch records
• JSON producer
• Bytes producer
• Producer statistics
"""

from __future__ import annotations

import json
import logging

from typing import Any

from aws.utils.aws_utils import get_client

logger = logging.getLogger(__name__)


###########################################################################
# Client
###########################################################################

def kinesis():

    """
    Return Kinesis client.
    """

    return get_client(

        "kinesis",

    )


###########################################################################
# Producer Service
###########################################################################

class ProducerService:

    """
    High-level Kinesis Producer.
    """

    def __init__(

        self,

    ):

        self.client = kinesis()

        self.records_sent = 0

        self.failed_records = 0


    #######################################################################
    # Put Record
    #######################################################################

    def put_record(

        self,

        stream_name: str,

        partition_key: str,

        data: bytes,

    ) -> dict[str, Any]:

        response = self.client.put_record(

            StreamName=stream_name,

            PartitionKey=partition_key,

            Data=data,

        )

        self.records_sent += 1

        logger.info(

            "Record written to %s",

            stream_name,

        )

        return response


    #######################################################################
    # Put JSON
    #######################################################################

    def put_json(

        self,

        stream_name: str,

        partition_key: str,

        payload: dict[str, Any],

    ) -> dict[str, Any]:

        return self.put_record(

            stream_name,

            partition_key,

            json.dumps(

                payload,

                default=str,

            ).encode(),

        )


    #######################################################################
    # Put Bytes
    #######################################################################

    def put_bytes(

        self,

        stream_name: str,

        partition_key: str,

        payload: bytes,

    ) -> dict[str, Any]:

        return self.put_record(

            stream_name,

            partition_key,

            payload,

        )


    #######################################################################
    # Put Batch
    #######################################################################

    def put_records(

        self,

        stream_name: str,

        records: list[dict[str, Any]],

    ) -> dict[str, Any]:

        response = self.client.put_records(

            StreamName=stream_name,

            Records=records,

        )

        self.records_sent += len(records)

        self.failed_records += response.get(

            "FailedRecordCount",

            0,

        )

        logger.info(

            "Batch sent to %s",

            stream_name,

        )

        return response
    
    #######################################################################
    # Producer Statistics
    #######################################################################

    def statistics(

        self,

    ) -> dict[str, int]:

        return {

            "records_sent": self.records_sent,

            "failed_records": self.failed_records,

            "successful_records": (

                self.records_sent

                - self.failed_records

            ),

        }


    #######################################################################
    # Reset Statistics
    #######################################################################

    def reset_statistics(

        self,

    ) -> None:

        self.records_sent = 0

        self.failed_records = 0

        logger.info(

            "Producer statistics reset",

        )


    #######################################################################
    # Health Check
    #######################################################################

    def health(

        self,

    ) -> dict[str, Any]:

        try:

            self.client.list_streams(

                Limit=1,

            )

            return {

                "healthy": True,

                "service": "kinesis",

            }

        except Exception as exc:

            return {

                "healthy": False,

                "service": "kinesis",

                "error": str(exc),

            }


    #######################################################################
    # Diagnostics
    #######################################################################

    def diagnostics(

        self,

    ) -> dict[str, Any]:

        health = self.health()

        stats = self.statistics()

        return {

            **health,

            **stats,

        }


###########################################################################
# Singleton
###########################################################################

PRODUCER_SERVICE = ProducerService()