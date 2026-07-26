"""
lambda_function.py

AWS Lambda entry point for the Machine Learning Engine.
"""

import json
from typing import Any, Dict

from aws.lambdas.ml_engine.predictor import predict


def lambda_handler(
    event: Dict[str, Any],
    context: Any,
) -> Dict[str, Any]:
    """
    AWS Lambda handler for ML inference.

    Parameters
    ----------
    event : dict
        Feature Engineering output.

    context : object
        AWS Lambda context.

    Returns
    -------
    dict
        API Gateway response.
    """

    try:

        prediction = predict(event)

        return {
            "statusCode": 200,
            "body": json.dumps(prediction)
        }

    except Exception as e:

        return {
            "statusCode": 500,
            "body": json.dumps(
                {
                    "error": str(e)
                }
            )
        }