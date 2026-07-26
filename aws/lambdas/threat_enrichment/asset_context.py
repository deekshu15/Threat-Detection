"""
asset_context.py

Asset Context Enrichment Module

Responsibilities:
- Identify affected asset type.
- Determine asset criticality.
- Map MITRE techniques to attack categories.
"""

from typing import Dict

from aws.lambdas.threat_enrichment.config import (
    ASSET_MAPPING,
    ATTACK_CATEGORY_MAPPING,
    DEFAULT_ASSET_TYPE,
    DEFAULT_CRITICALITY,
    DEFAULT_ATTACK_CATEGORY,
)


class AssetContext:

    @staticmethod
    def get_asset_information(source: str) -> Dict:
        """
        Get asset information based on source type.

        Args:
            source (str): Dataset source

        Returns:
            dict
        """

        if not source:
            return {
                "asset_type": DEFAULT_ASSET_TYPE,
                "asset_criticality": DEFAULT_CRITICALITY,
            }

        source = source.lower()

        asset = ASSET_MAPPING.get(source)

        if asset is None:
            return {
                "asset_type": DEFAULT_ASSET_TYPE,
                "asset_criticality": DEFAULT_CRITICALITY,
            }

        return {
            "asset_type": asset["asset_type"],
            "asset_criticality": asset["criticality"],
        }

    @staticmethod
    def get_attack_category(technique: str) -> str:
        """
        Determine attack category from MITRE Technique.

        Args:
            technique (str)

        Returns:
            str
        """

        if not technique:
            return DEFAULT_ATTACK_CATEGORY

        return ATTACK_CATEGORY_MAPPING.get(
            technique,
            DEFAULT_ATTACK_CATEGORY,
        )

    @classmethod
    def enrich(cls, event: Dict) -> Dict:
        """
        Build asset context.

        Args:
            event (dict)

        Returns:
            dict
        """

        source = event.get("source", "")

        mitre = event.get("mitre", {})

        technique = mitre.get("technique")

        asset = cls.get_asset_information(source)

        attack_category = cls.get_attack_category(
            technique
        )

        return {
            "asset_type": asset["asset_type"],
            "asset_criticality": asset["asset_criticality"],
            "attack_category": attack_category,
        }


def build_asset_context(event: Dict) -> Dict:
    """
    Convenience wrapper.

    Args:
        event (dict)

    Returns:
        dict
    """

    return AssetContext.enrich(event)