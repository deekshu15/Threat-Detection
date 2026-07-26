"""
AWS Lambda Entry Point

Triggered whenever a new dataset is uploaded to the Raw S3 Bucket.
"""

import os
import pandas as pd

from config import Config
from utils.logger import get_logger
from utils.s3_helper import S3Helper
from processors.normalize import Normalizer

logger = get_logger(__name__)
s3_helper = S3Helper()


def lambda_handler(event, context):
    """
    Main Lambda handler.
    """

    try:

        logger.info("Lambda execution started.")

        # ----------------------------------------------------
        # Extract bucket and object key from S3 event
        # ----------------------------------------------------
        record = event["Records"][0]

        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]

        logger.info(f"Bucket : {bucket}")
        logger.info(f"Object : {key}")

        # ----------------------------------------------------
        # Read dataset
        # ----------------------------------------------------
        extension = os.path.splitext(key)[1].lower()

        if extension == ".csv":

            dataframe = s3_helper.read_csv(bucket, key)

        elif extension == ".json":

            dataframe = pd.DataFrame(
                s3_helper.read_json(bucket, key)
            )

        elif extension == ".parquet":

            dataframe = s3_helper.read_parquet(bucket, key)

        else:

            raise ValueError(
                f"Unsupported file type : {extension}"
            )

        logger.info(
            f"Loaded dataset with {len(dataframe)} records."
        )

        # ----------------------------------------------------
        # Normalize
        # ----------------------------------------------------
        normalized_df = Normalizer.normalize_dataframe(
            dataframe=dataframe,
            dataset_path=key
        )

        logger.info(
            f"Normalization completed ({len(normalized_df)} rows)."
        )

        # ----------------------------------------------------
        # Upload
        # ----------------------------------------------------
        output_key = (
            f"{Config.NORMALIZED_PREFIX}"
            f"{os.path.splitext(os.path.basename(key))[0]}.parquet"
        ) 

        s3_helper.upload_parquet(
            dataframe=normalized_df,
            bucket=Config.PROCESSED_BUCKET,
            key=output_key
        )

        logger.info(
            f"Uploaded : {output_key}"
        )

        return {
            "statusCode": 200,
            "body": {
                "message": "Normalization completed successfully.",
                "rows": len(normalized_df),
                "output": output_key
            }
        }

    except Exception as e:

        logger.exception("Lambda execution failed.")

        return {
            "statusCode": 500,
            "body": str(e)
        }