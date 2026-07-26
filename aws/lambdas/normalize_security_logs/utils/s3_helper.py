"""
Amazon S3 Helper

Handles reading and writing datasets from Amazon S3.
"""

import io
import json

import boto3
import pandas as pd


class S3Helper:
    """Utility class for S3 operations."""

    def __init__(self):
        self.client = boto3.client("s3")

    def read_csv(self, bucket: str, key: str) -> pd.DataFrame:
        """
        Read a CSV file from S3.
        """
        response = self.client.get_object(
            Bucket=bucket,
            Key=key
        )

        return pd.read_csv(
            response["Body"],
            low_memory=False
        )

    def read_json(self, bucket: str, key: str):
        """
        Read a JSON file from S3.
        """
        response = self.client.get_object(
            Bucket=bucket,
            Key=key
        )

        return json.load(response["Body"])

    def read_parquet(self, bucket: str, key: str) -> pd.DataFrame:
        """
        Read a Parquet file from S3.
        """
        response = self.client.get_object(
            Bucket=bucket,
            Key=key
        )

        return pd.read_parquet(
            io.BytesIO(response["Body"].read())
        )

    def upload_parquet(
        self,
        dataframe: pd.DataFrame,
        bucket: str,
        key: str
    ):
        """
        Upload DataFrame as Parquet to S3.
        """
        buffer = io.BytesIO()

        dataframe.to_parquet(
            buffer,
            index=False
        )

        buffer.seek(0)

        self.client.put_object(
            Bucket=bucket,
            Key=key,
            Body=buffer.getvalue()
        )