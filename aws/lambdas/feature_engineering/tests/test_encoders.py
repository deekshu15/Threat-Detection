import pytest

from aws.lambdas.feature_engineering.encoders import (
    FeatureEncoder,
)


def test_encode_source():
    assert FeatureEncoder.encode_source("windows") == 1


def test_encode_source_unknown():
    assert FeatureEncoder.encode_source("unknown") == -1


def test_encode_technique():
    assert FeatureEncoder.encode_technique("T1110") == 1110


def test_encode_unknown_technique():
    assert FeatureEncoder.encode_technique("T9999") == -1


def test_encode_asset():
    assert FeatureEncoder.encode_asset("High") == 3


def test_encode_unknown_asset():
    assert FeatureEncoder.encode_asset("Unknown") == 0


def test_encode_boolean_true():
    assert FeatureEncoder.encode_boolean(True) == 1


def test_encode_boolean_false():
    assert FeatureEncoder.encode_boolean(False) == 0


def test_encode_complete_event():

    encoded = FeatureEncoder.encode_event(
        source="windows",
        technique="T1110",
        asset="High",
        known_attack=True,
    )

    assert encoded["source_id"] == 1
    assert encoded["technique_id"] == 1110
    assert encoded["asset_score"] == 3
    assert encoded["known_attack"] == 1