"""
AWS SNS Package

Enterprise Amazon Simple Notification Service

Modules
-------
topics.py
publish.py
subscriptions.py
policies.py
manager.py
"""

from .topics import (
    TopicService,
    TopicManager,
    TOPIC_SERVICE,
    TOPIC_MANAGER,
)

from .publish import (
    PublisherService,
    PublisherManager,
    PUBLISHER_SERVICE,
    PUBLISHER_MANAGER,
)

from .subscriptions import (
    SubscriptionService,
    SubscriptionManager,
    SUBSCRIPTION_SERVICE,
    SUBSCRIPTION_MANAGER,
)

from .policies import (
    PolicyService,
    PolicyManager,
    POLICY_SERVICE,
    POLICY_MANAGER,
)

from .manager import (
    SNSManager,
    SNS,
)

__version__ = "1.0.0"

__author__ = "AI-Assisted Threat Detection Dashboard"

__all__ = [

    # Topics
    "TopicService",
    "TopicManager",
    "TOPIC_SERVICE",
    "TOPIC_MANAGER",

    # Publisher
    "PublisherService",
    "PublisherManager",
    "PUBLISHER_SERVICE",
    "PUBLISHER_MANAGER",

    # Subscriptions
    "SubscriptionService",
    "SubscriptionManager",
    "SUBSCRIPTION_SERVICE",
    "SUBSCRIPTION_MANAGER",

    # Policies
    "PolicyService",
    "PolicyManager",
    "POLICY_SERVICE",
    "POLICY_MANAGER",

    # Central Manager
    "SNSManager",
    "SNS",

]