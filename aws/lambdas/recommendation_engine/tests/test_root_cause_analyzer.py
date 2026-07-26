from aws.lambdas.recommendation_engine.validator import validate_incident
from aws.lambdas.recommendation_engine.root_cause_analyzer import (
    analyze_root_cause,
)


def test_root_cause(sample_incident):

    incident = validate_incident(sample_incident)

    result = analyze_root_cause(
        incident
    )

    assert result.probable_root_cause
    assert result.attack_origin
    assert result.overall_assessment