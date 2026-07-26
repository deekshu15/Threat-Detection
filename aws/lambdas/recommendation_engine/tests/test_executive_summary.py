from aws.lambdas.recommendation_engine.validator import validate_incident
from aws.lambdas.recommendation_engine.executive_summary import (
    generate_executive_summary,
)


def test_executive_summary(sample_incident):

    incident = validate_incident(sample_incident)

    result = generate_executive_summary(
        incident
    )

    assert result.headline

    assert result.business_impact

    assert result.operational_risk