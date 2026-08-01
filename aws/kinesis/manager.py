"""
manager.py

Enterprise AWS Kinesis Manager

Provides a single entry point for all
Kinesis operations.

Components
----------
• StreamService
• ProducerService
• ConsumerService
• AnalyticsService
"""

from __future__ import annotations

from typing import Any

from .streams import STREAM_SERVICE
from .producers import PRODUCER_SERVICE
from .consumers import CONSUMER_SERVICE
from .analytics import ANALYTICS_SERVICE


###########################################################################
# Manager
###########################################################################

class KinesisManager:

    """
    Unified interface for AWS Kinesis.
    """

    def __init__(

        self,

    ):

        self.streams = STREAM_SERVICE

        self.producer = PRODUCER_SERVICE

        self.consumer = CONSUMER_SERVICE

        self.analytics = ANALYTICS_SERVICE


    #######################################################################
    # Stream Management
    #######################################################################

    def create_stream(

        self,

        stream_name: str,

        shard_count: int = 1,

    ) -> bool:

        return self.streams.create_stream(

            stream_name,

            shard_count,

        )


    def delete_stream(

        self,

        stream_name: str,

    ) -> bool:

        return self.streams.delete_stream(

            stream_name,

        )


    def list_streams(

        self,

    ) -> list[str]:

        return self.streams.list_streams()


    def stream_summary(

        self,

        stream_name: str,

    ) -> dict[str, Any]:

        return self.streams.summary(

            stream_name,

        )


    #######################################################################
    # Producer
    #######################################################################

    def put_json(

        self,

        stream_name: str,

        partition_key: str,

        payload: dict[str, Any],

    ) -> dict[str, Any]:

        return self.producer.put_json(

            stream_name,

            partition_key,

            payload,

        )


    def put_bytes(

        self,

        stream_name: str,

        partition_key: str,

        payload: bytes,

    ) -> dict[str, Any]:

        return self.producer.put_bytes(

            stream_name,

            partition_key,

            payload,

        )


    def put_records(

        self,

        stream_name: str,

        records: list[dict[str, Any]],

    ) -> dict[str, Any]:

        return self.producer.put_records(

            stream_name,

            records,

        )
        
    #######################################################################
    # Consumer
    #######################################################################

    def latest_iterator(

        self,

        stream_name: str,

        shard_id: str,

    ) -> str:

        return self.consumer.latest_iterator(

            stream_name,

            shard_id,

        )


    def get_records(

        self,

        shard_iterator: str,

        limit: int = 100,

    ) -> dict[str, Any]:

        return self.consumer.get_records(

            shard_iterator,

            limit,

        )


    #######################################################################
    # Analytics
    #######################################################################

    def analytics_summary(

        self,

        stream_name: str,

    ) -> dict[str, Any]:

        return self.analytics.summary(

            stream_name,

        )


    def health(

        self,

        stream_name: str,

    ) -> dict[str, Any]:

        return self.analytics.health(

            stream_name,

        )


    #######################################################################
    # Diagnostics
    #######################################################################

    def diagnostics(
        self,
    ) -> dict[str, Any]:

        try:

            return {

                "healthy": True,

                "streams": self.streams.diagnostics(),

                "producer": self.producer.diagnostics(),

                "consumer": self.consumer.diagnostics(),

            }

        except Exception as exc:

            return {

                "healthy": False,

                "streams": {},

                "producer": {},

                "consumer": {},

                "error": str(exc),

            }   

    #######################################################################
    # Summary
    #######################################################################

    def summary(
        self,
    ) -> dict[str, Any]:

        diagnostics = self.diagnostics()

        if not diagnostics.get("healthy", True):

            return {

                "service": "AWS Kinesis",

                "healthy": False,

                "error": diagnostics.get("error"),

            }

        return {

            "service": "AWS Kinesis",

            "healthy": (

                diagnostics["producer"]["healthy"]

                and

                diagnostics["consumer"]["healthy"]

            ),

            "stream_count":

            diagnostics["streams"]["stream_count"],

            "records_sent":

            diagnostics["producer"]["records_sent"],

            "records_read":

            diagnostics["consumer"]["records_read"],

        }
###########################################################################
# Singleton
###########################################################################

KINESIS = KinesisManager()