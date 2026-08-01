"""
analytics.py

Enterprise AWS Kinesis Analytics

Responsibilities
----------------
• Stream metrics
• Shard metrics
• Monitoring status
• Retention information
• Stream analytics
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
# Analytics Service
###########################################################################

class AnalyticsService:

    """
    High-level Kinesis analytics.
    """

    def __init__(

        self,

    ):

        self.client = kinesis()


    #######################################################################
    # Describe Stream
    #######################################################################

    def stream_summary(

        self,

        stream_name: str,

    ) -> dict[str, Any]:

        response = self.client.describe_stream_summary(

            StreamName=stream_name,

        )

        return response["StreamDescriptionSummary"]


    #######################################################################
    # Stream Metrics
    #######################################################################

    def stream_metrics(

        self,

        stream_name: str,

    ) -> dict[str, Any]:

        summary = self.stream_summary(

            stream_name,

        )

        return {

            "stream_name":

            summary.get(

                "StreamName",

            ),

            "status":

            summary.get(

                "StreamStatus",

            ),

            "open_shards":

            summary.get(

                "OpenShardCount",

            ),

            "retention_hours":

            summary.get(

                "RetentionPeriodHours",

            ),

            "stream_mode":

            summary.get(

                "StreamModeDetails",

                {},

            ).get(

                "StreamMode",

            ),

        }


    #######################################################################
    # Shard Metrics
    #######################################################################

    def shard_metrics(

        self,

        stream_name: str,

    ) -> dict[str, Any]:

        summary = self.stream_summary(

            stream_name,

        )

        return {

            "stream":

            summary.get(

                "StreamName",

            ),

            "open_shards":

            summary.get(

                "OpenShardCount",

            ),

            "status":

            summary.get(

                "StreamStatus",

            ),

        }


    #######################################################################
    # Enhanced Monitoring
    #######################################################################

    def monitoring_status(

        self,

        stream_name: str,

    ) -> list[dict[str, Any]]:

        summary = self.stream_summary(

            stream_name,

        )

        return summary.get(

            "EnhancedMonitoring",

            [],

        )
        
    #######################################################################
    # Retention Information
    #######################################################################

    def retention_information(

        self,

        stream_name: str,

    ) -> dict[str, Any]:

        summary = self.stream_summary(

            stream_name,

        )

        return {

            "stream":

            summary.get(

                "StreamName",

            ),

            "retention_hours":

            summary.get(

                "RetentionPeriodHours",

            ),

        }


    #######################################################################
    # Stream Health
    #######################################################################

    def health(

        self,

        stream_name: str,

    ) -> dict[str, Any]:

        summary = self.stream_summary(

            stream_name,

        )

        status = summary.get(

            "StreamStatus",

        )

        return {

            "healthy": status == "ACTIVE",

            "status": status,

            "stream": summary.get(

                "StreamName",

            ),

        }


    #######################################################################
    # Analytics Summary
    #######################################################################

    def summary(

        self,

        stream_name: str,

    ) -> dict[str, Any]:

        return {

            "metrics":

            self.stream_metrics(

                stream_name,

            ),

            "shards":

            self.shard_metrics(

                stream_name,

            ),

            "monitoring":

            self.monitoring_status(

                stream_name,

            ),

            "retention":

            self.retention_information(

                stream_name,

            ),

            "health":

            self.health(

                stream_name,

            ),

        }


    #######################################################################
    # Diagnostics
    #######################################################################

    def diagnostics(

        self,

        stream_name: str,

    ) -> dict[str, Any]:

        summary = self.stream_summary(

            stream_name,

        )

        return {

            "stream":

            summary.get(

                "StreamName",

            ),

            "status":

            summary.get(

                "StreamStatus",

            ),

            "open_shards":

            summary.get(

                "OpenShardCount",

            ),

            "retention_hours":

            summary.get(

                "RetentionPeriodHours",

            ),

            "enhanced_monitoring":

            summary.get(

                "EnhancedMonitoring",

                [],

            ),

            "stream_mode":

            summary.get(

                "StreamModeDetails",

                {},

            ).get(

                "StreamMode",

            ),

        }


###########################################################################
# Singleton
###########################################################################

ANALYTICS_SERVICE = AnalyticsService()