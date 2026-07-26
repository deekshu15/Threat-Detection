from aws.lambdas.recommendation_engine.validator import validate_incident
from aws.lambdas.recommendation_engine.recommendation_generator import (
    generate_recommendations,
)


def test_recommendations(sample_incident):

    incident = validate_incident(sample_incident)

    result = generate_recommendations(
        incident
    )

    assert len(result.recommendations) > 0

    assert len(result.containment_actions) > 0

    assert len(result.recovery_actions) > 0