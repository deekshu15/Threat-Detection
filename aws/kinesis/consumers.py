"""
consumers.py

Enterprise AWS Kinesis Consumers

Responsibilities
----------------
• Get shard iterator
• Read records
• Iterator management
• Consumer diagnostics
"""

from __future__ import annotations

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
# Consumer Service
###########################################################################

class ConsumerService:

    """
    High-level Kinesis Consumer.
    """

    def __init__(

        self,

    ):

        self.client = kinesis()

        self.records_read = 0


    #######################################################################
    # Get Shard Iterator
    #######################################################################

    def shard_iterator(

        self,

        stream_name: str,

        shard_id: str,

        iterator_type: str = "LATEST",

        sequence_number: str | None = None,

    ) -> str:

        request = {

            "StreamName": stream_name,

            "ShardId": shard_id,

            "ShardIteratorType": iterator_type,

        }

        if (

            sequence_number

            is not None

        ):

            request[

                "StartingSequenceNumber"

            ] = sequence_number

        response = self.client.get_shard_iterator(

            **request,

        )

        return response["ShardIterator"]


    #######################################################################
    # Read Records
    #######################################################################

    def get_records(

        self,

        shard_iterator: str,

        limit: int = 100,

    ) -> dict[str, Any]:

        response = self.client.get_records(

            ShardIterator=shard_iterator,

            Limit=limit,

        )

        self.records_read += len(

            response.get(

                "Records",

                [],

            )

        )

        return response


    #######################################################################
    # Latest Iterator
    #######################################################################

    def latest_iterator(

        self,

        stream_name: str,

        shard_id: str,

    ) -> str:

        return self.shard_iterator(

            stream_name,

            shard_id,

            "LATEST",

        )


    #######################################################################
    # Trim Horizon Iterator
    #######################################################################

    def trim_horizon_iterator(

        self,

        stream_name: str,

        shard_id: str,

    ) -> str:

        return self.shard_iterator(

            stream_name,

            shard_id,

            "TRIM_HORIZON",

        )


    #######################################################################
    # At Sequence Number
    #######################################################################

    def at_sequence_number(

        self,

        stream_name: str,

        shard_id: str,

        sequence_number: str,

    ) -> str:

        return self.shard_iterator(

            stream_name,

            shard_id,

            "AT_SEQUENCE_NUMBER",

            sequence_number,

        )
        
    #######################################################################
    # After Sequence Number
    #######################################################################

    def after_sequence_number(

        self,

        stream_name: str,

        shard_id: str,

        sequence_number: str,

    ) -> str:

        return self.shard_iterator(

            stream_name,

            shard_id,

            "AFTER_SEQUENCE_NUMBER",

            sequence_number,

        )


    #######################################################################
    # At Timestamp
    #######################################################################

    def at_timestamp(

        self,

        stream_name: str,

        shard_id: str,

        timestamp,

    ) -> str:

        response = self.client.get_shard_iterator(

            StreamName=stream_name,

            ShardId=shard_id,

            ShardIteratorType="AT_TIMESTAMP",

            Timestamp=timestamp,

        )

        return response["ShardIterator"]


    #######################################################################
    # Consumer Statistics
    #######################################################################

    def statistics(

        self,

    ) -> dict[str, int]:

        return {

            "records_read": self.records_read,

        }


    #######################################################################
    # Reset Statistics
    #######################################################################

    def reset_statistics(

        self,

    ) -> None:

        self.records_read = 0

        logger.info(

            "Consumer statistics reset",

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

        return {

            **self.health(),

            **self.statistics(),

        }


###########################################################################
# Singleton
###########################################################################

CONSUMER_SERVICE = ConsumerService()