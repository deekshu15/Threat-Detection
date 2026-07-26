import json

from aws.lambdas.recommendation_engine.lambda_function import (
    lambda_handler,
)


def test_lambda(sample_incident):

    event = {

        "incident": sample_incident

    }

    response = lambda_handler(
        event,
        None,
    )

    assert response["statusCode"] == 200

    body = json.loads(
        response["body"]
    )

    assert body["status"] == "Success"

    assert "data" in body