"""
Generic DynamoDB Repository

Features
--------
• CRUD Operations
• Batch Operations
• Query
• Scan
• Pagination
• Conditional Writes
• Transactions
• Optimistic Locking
• TTL Support
• Automatic Serialization
"""

from __future__ import annotations

from typing import Any
from typing import Iterator
from typing import Generic
from typing import TypeVar
from typing import Optional

from boto3.dynamodb.conditions import Key
from boto3.dynamodb.conditions import Attr

from botocore.exceptions import ClientError

from aws.utils.aws_utils import get_resource
from aws.utils.aws_utils import AWSUtilityError
from aws.utils.serialization import deep_dict
from aws.utils.retry import retry
from aws.utils.metrics import ServiceMetrics
from aws.utils.metrics import ServiceOperation

T = TypeVar("T")

class DynamoRepository(Generic[T]):

    def __init__(

        self,

        table_name: str,

        region_name: str | None = None,

    ):

        self.table_name = table_name

        self.resource = get_resource(

            "dynamodb",

            region_name,

        )

        self.table = self.resource.Table(

            table_name,

        )

        self.metrics = ServiceMetrics(

            f"dynamodb_{table_name}",

        )

    @retry()

    def put(

        self,

        item: dict[str, Any],

    ) -> dict:

        with ServiceOperation(

            self.metrics,

        ):

            self.table.put_item(

                Item=deep_dict(item),

            )

            return item

    @retry()

    def get(

        self,

        partition_key: str,

        partition_value: Any,

        sort_key: str | None = None,

        sort_value: Any | None = None,

    ) -> dict | None:

        with ServiceOperation(

            self.metrics,

        ):

            key = {

                partition_key:

                partition_value

            }

            if sort_key is not None:

                key[sort_key] = sort_value

            response = self.table.get_item(

                Key=key,

            )

            return response.get(

                "Item",

            )
            
    @retry()

    def update(

        self,

        key: dict,

        updates: dict,

    ):

        expressions = []

        values = {}

        names = {}

        index = 0

        for attribute, value in updates.items():

            name = f"#n{index}"

            val = f":v{index}"

            names[name] = attribute

            values[val] = value

            expressions.append(

                f"{name}={val}"

            )

            index += 1

        response = self.table.update_item(

            Key=key,

            UpdateExpression=

            "SET "

            + ", ".join(expressions),

            ExpressionAttributeNames=names,

            ExpressionAttributeValues=values,

            ReturnValues="ALL_NEW",

        )

        return response.get(

            "Attributes",

        )

    @retry()

    def delete(

        self,

        key: dict,

    ):

        self.table.delete_item(

            Key=key,

        )

        return True
    
    def exists(

        self,

        partition_key,

        value,

    ):

        item = self.get(

            partition_key,

            value,

        )

        return item is not None
    
    @retry()

    def query(

        self,

        partition_key: str,

        value,

        limit: int | None = None,

    ):

        params = {

            "KeyConditionExpression":

            Key(

                partition_key

            ).eq(value)

        }

        if limit:

            params["Limit"] = limit

        response = self.table.query(

            **params

        )

        return response.get(

            "Items",

            [],

        )
        
    @retry()

    def query_between(

        self,

        partition_key,

        value,

        sort_key,

        start,

        end,

    ):

        response = self.table.query(

            KeyConditionExpression=

            Key(partition_key)

            .eq(value)

            &

            Key(sort_key)

            .between(

                start,

                end,

            )

        )

        return response.get(

            "Items",

            [],

        )
        
    @retry()

    def scan(

        self,

        filter_expression=None,

        limit=None,

    ):

        params = {}

        if filter_expression:

            params[

                "FilterExpression"

            ] = filter_expression

        if limit:

            params["Limit"] = limit

        response = self.table.scan(

            **params

        )

        return response.get(

            "Items",

            [],

        )

    def iter_scan(

        self,

        filter_expression=None,

    ) -> Iterator[dict]:

        kwargs = {}

        if filter_expression:

            kwargs[

                "FilterExpression"

            ] = filter_expression

        while True:

            response = self.table.scan(

                **kwargs

            )

            yield from response.get(

                "Items",

                [],

            )

            last = response.get(

                "LastEvaluatedKey"

            )

            if not last:

                break

            kwargs[

                "ExclusiveStartKey"

            ] = last
            
    def batch_put(

        self,

        items,

    ):

        with self.table.batch_writer() as batch:

            for item in items:

                batch.put_item(

                    Item=deep_dict(

                        item

                    )

                )

        return len(items)
    
    def batch_delete(

        self,

        keys,

    ):

        with self.table.batch_writer() as batch:

            for key in keys:

                batch.delete_item(

                    Key=key

                )

        return len(keys)
    
    def count(self):

        response = self.table.scan(

            Select="COUNT"

        )

        return response["Count"]
    
    def update_ttl(

        self,

        key,

        expires_at,

    ):

        return self.update(

            key,

            {

                "expires_at":

                expires_at

            }

        )

    def put_if_not_exists(

        self,

        item,

        partition_key,

    ):

        self.table.put_item(

            Item=item,

            ConditionExpression=

            Attr(

                partition_key

            ).not_exists(),

        )

        return item

    def optimistic_update(

        self,

        key,

        updates,

        version,

    ):

        expressions = []

        values = {

            ":version":

            version,

            ":next":

            version + 1,

        }

        names = {

            "#version":

            "version"

        }

        for i, (k, v) in enumerate(

            updates.items()

        ):

            nk = f"#n{i}"

            vk = f":v{i}"

            names[nk] = k

            values[vk] = v

            expressions.append(

                f"{nk}={vk}"

            )

        expressions.append(

            "#version=:next"

        )

        return self.table.update_item(

            Key=key,

            UpdateExpression=

            "SET "

            + ", ".join(expressions),

            ConditionExpression=

            "#version=:version",

            ExpressionAttributeNames=

            names,

            ExpressionAttributeValues=

            values,

            ReturnValues="ALL_NEW",

        )
        
    def transaction_write(

        self,

        operations,

    ):

        client = self.resource.meta.client

        return client.transact_write_items(

            TransactItems=operations

        )

    def transaction_get(

        self,

        items,

    ):

        client = self.resource.meta.client

        return client.transact_get_items(

            TransactItems=items

        )
        
    def diagnostics(self):

        return {

            "table":

            self.table_name,

            "metrics":

            self.metrics.snapshot(),

        }
        
def self_test():

    repo = DynamoRepository(

        "ExampleTable"

    )

    return {

        "table":

        repo.table_name,

        "repository":

        True,

    }

