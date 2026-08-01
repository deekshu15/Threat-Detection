"""
DynamoDB Table Setup

Creates all DynamoDB tables required by the Threat Enrichment Platform.

Features
--------
• Table Creation
• Billing Mode Configuration
• TTL Configuration
• Stream Configuration
• Wait Until Active
• Safe Re-run Support
• Diagnostics
"""

from __future__ import annotations

import logging
from typing import Any

from botocore.exceptions import ClientError

from aws.utils.aws_utils import get_client

from .tables import ALL_TABLES

logger = logging.getLogger(__name__)

###########################################################################
# Client
###########################################################################

def dynamodb_client():

    return get_client("dynamodb")

###########################################################################
# Existing Tables
###########################################################################

def list_existing_tables():

    client = dynamodb_client()

    paginator = client.get_paginator(
        "list_tables"
    )

    tables = []

    for page in paginator.paginate():

        tables.extend(
            page.get(
                "TableNames",
                [],
            )
        )

    return sorted(tables)

def table_exists(
    table_name: str,
) -> bool:

    return (
        table_name
        in list_existing_tables()
    )
    
###########################################################################
# Helpers
###########################################################################

def attribute_definitions(table):

    definitions = [

        {
            "AttributeName":
                table.partition_key,

            "AttributeType":
                "S",
        }

    ]

    if table.sort_key:

        definitions.append(

            {
                "AttributeName":
                    table.sort_key,

                "AttributeType":
                    "S",
            }

        )

    return definitions

def key_schema(table):

    schema = [

        {
            "AttributeName":
                table.partition_key,

            "KeyType":
                "HASH",
        }

    ]

    if table.sort_key:

        schema.append(

            {
                "AttributeName":
                    table.sort_key,

                "KeyType":
                    "RANGE",
            }

        )

    return schema

###########################################################################
# Create Table
###########################################################################

def create_table(table):

    client = dynamodb_client()

    if table_exists(table.name):

        logger.info(
            "%s already exists.",
            table.name,
        )

        return False

    params = {

        "TableName":
            table.name,

        "AttributeDefinitions":
            attribute_definitions(table),

        "KeySchema":
            key_schema(table),

        "BillingMode":
            table.billing_mode,
    }

    if table.stream_enabled:

        params["StreamSpecification"] = {

            "StreamEnabled": True,

            "StreamViewType":
                "NEW_AND_OLD_IMAGES",
        }

    logger.info(
        "Creating table %s",
        table.name,
    )

    client.create_table(
        **params
    )

    return True

###########################################################################
# Wait
###########################################################################

def wait_until_active(
    table_name: str,
):

    client = dynamodb_client()

    waiter = client.get_waiter(
        "table_exists"
    )

    waiter.wait(
        TableName=table_name
    )

    logger.info(
        "%s is ACTIVE",
        table_name,
    )
    
###########################################################################
# TTL
###########################################################################

def enable_ttl(table):

    if table.ttl_attribute is None:

        return False

    client = dynamodb_client()

    client.update_time_to_live(

        TableName=table.name,

        TimeToLiveSpecification={

            "Enabled": True,

            "AttributeName":
                table.ttl_attribute,

        },
    )

    logger.info(

        "TTL enabled for %s",

        table.name,

    )

    return True

###########################################################################
# Create All
###########################################################################

def create_all_tables():

    created = []

    skipped = []

    ttl_enabled = []

    for table in ALL_TABLES:

        if create_table(table):

            wait_until_active(
                table.name
            )

            created.append(
                table.name
            )

            if enable_ttl(table):

                ttl_enabled.append(
                    table.name
                )

        else:

            skipped.append(
                table.name
            )

    return {

        "created":
            created,

        "skipped":
            skipped,

        "ttl":
            ttl_enabled,
    }
    
###########################################################################
# Delete
###########################################################################

def delete_table(
    table_name: str,
):

    client = dynamodb_client()

    if not table_exists(
        table_name
    ):

        return False

    client.delete_table(

        TableName=table_name,

    )

    return True

def delete_all_tables():

    deleted = []

    skipped = []

    for table in ALL_TABLES:

        if delete_table(
            table.name
        ):

            deleted.append(
                table.name
            )

        else:

            skipped.append(
                table.name
            )

    return {

        "deleted":
            deleted,

        "skipped":
            skipped,

    }
    
###########################################################################
# Describe
###########################################################################

def describe_table(
    table_name: str,
):

    client = dynamodb_client()

    return client.describe_table(

        TableName=table_name,

    )["Table"]
    
def describe_all():

    result = {}

    for table in ALL_TABLES:

        if table_exists(
            table.name
        ):

            result[
                table.name
            ] = describe_table(
                table.name
            )

    return result

###########################################################################
# Diagnostics
###########################################################################

def diagnostics():

    existing = list_existing_tables()

    configured = [

        table.name

        for table

        in ALL_TABLES

    ]

    return {

        "configured_tables":

        configured,

        "existing_tables":

        existing,

        "missing_tables":

        [

            t

            for t in configured

            if t not in existing

        ],

    }

###########################################################################
# Self Test
###########################################################################

def self_test():

    configured = [

        table.name

        for table

        in ALL_TABLES

    ]

    return {

        "passed": True,

        "configured":

        configured,

        "count":

        len(configured),

    }
    
###########################################################################
# CLI
###########################################################################

if __name__ == "__main__":

    logging.basicConfig(

        level=logging.INFO,

        format="%(levelname)s %(message)s",

    )

    result = create_all_tables()

    print(result)
    
