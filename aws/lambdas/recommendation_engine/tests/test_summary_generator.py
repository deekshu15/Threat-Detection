from aws.lambdas.recommendation_engine.validator import validate_incident
from aws.lambdas.recommendation_engine.summary_generator import (
    generate_summary,
)


def test_summary(sample_incident):

    incident = validate_incident(sample_incident)

    summary = generate_summary(
        incident
    )

    assert summary.title
    assert summary.short_summary
    assert summary.analyst_summary
    assert len(summary.key_findings) > 0