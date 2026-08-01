"""
AWS Kinesis Package

Enterprise Amazon Kinesis Services
"""

from .streams import (
    StreamService,
    STREAM_SERVICE,
)

from .producers import (
    ProducerService,
    PRODUCER_SERVICE,
)

from .consumers import (
    ConsumerService,
    CONSUMER_SERVICE,
)

from .analytics import (
    AnalyticsService,
    ANALYTICS_SERVICE,
)

from .manager import (
    KinesisManager,
    KINESIS,
)

__version__ = "1.0.0"

__all__ = [

    "StreamService",
    "STREAM_SERVICE",

    "ProducerService",
    "PRODUCER_SERVICE",

    "ConsumerService",
    "CONSUMER_SERVICE",

    "AnalyticsService",
    "ANALYTICS_SERVICE",

    "KinesisManager",
    "KINESIS",

]