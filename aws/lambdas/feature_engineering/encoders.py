"""
Feature Engineering Encoders

Encodes categorical values into deterministic
numerical representations for ML.

Author:
AI Threat Detection Dashboard
"""

from __future__ import annotations

from typing import Dict, Optional

from .constants import (
    ASSET_ENCODING,
    MITRE_TACTIC_ENCODING,
    PROTOCOL_ENCODING,
    SEVERITY_ENCODING,
)

# ---------------------------------------------------------
# Event Category Encoding
# ---------------------------------------------------------

EVENT_CATEGORY_ENCODING = {
    "Authentication": 1,
    "Authorization": 2,
    "Malware": 3,
    "Network": 4,
    "Firewall": 5,
    "IDS": 6,
    "IPS": 7,
    "DNS": 8,
    "Web": 9,
    "Email": 10,
    "Cloud": 11,
    "System": 12,
    "Application": 13,
    "Vulnerability": 14,
    "Data Access": 15,
    "File Activity": 16,
    "Process": 17,
    "Registry": 18,
    "Persistence": 19,
    "Privilege Escalation": 20,
    "Discovery": 21,
    "Credential Access": 22,
    "Lateral Movement": 23,
    "Collection": 24,
    "Exfiltration": 25,
    "Impact": 26,
    "Unknown": 0,
}


# ---------------------------------------------------------
# Feature Encoder
# ---------------------------------------------------------

class FeatureEncoder:

    """
    Encodes categorical fields for ML.
    """

    # -----------------------------------------------------
    # Severity
    # -----------------------------------------------------

    def encode_severity(
        self,
        severity: Optional[str],
    ) -> int:

        if severity is None:
            return SEVERITY_ENCODING["UNKNOWN"]

        severity = severity.upper().strip()

        return SEVERITY_ENCODING.get(
            severity,
            SEVERITY_ENCODING["UNKNOWN"],
        )

    # -----------------------------------------------------
    # Protocol
    # -----------------------------------------------------

    def encode_protocol(
        self,
        protocol: Optional[str],
    ) -> int:

        if protocol is None:
            return PROTOCOL_ENCODING["OTHER"]

        protocol = protocol.upper().strip()

        return PROTOCOL_ENCODING.get(
            protocol,
            PROTOCOL_ENCODING["OTHER"],
        )

    # -----------------------------------------------------
    # Asset
    # -----------------------------------------------------

    @staticmethod
    def encode_source(source: Optional[str]) -> int:

        if source is None:
            return -1

        source = str(source).strip().lower()

        return {
            "windows": 1,
            "ids": 2,
            "linux": 3,
            "firewall": 4,
            "cve": 5,
        }.get(source, -1)

    @staticmethod
    def encode_technique(technique: Optional[str]) -> int:

        if technique is None:
            return -1

        text = str(technique).strip().upper()
        known_techniques = {
            1003,
            1053,
            1059,
            1110,
            1486,
        }

        if text.startswith("T") and text[1:].isdigit():
            value = int(text[1:])
            return value if value in known_techniques else -1
        if text.isdigit():
            value = int(text)
            return value if value in known_techniques else -1
        return -1

    @staticmethod
    def encode_asset(asset: Optional[str]) -> int:

        if asset is None:
            return ASSET_ENCODING["UNKNOWN"]

        asset = str(asset).upper().strip()

        return ASSET_ENCODING.get(
            asset,
            ASSET_ENCODING["UNKNOWN"],
        )

    # -----------------------------------------------------
    # MITRE
    # -----------------------------------------------------

    def encode_mitre_tactic(
        self,
        tactic: Optional[str],
    ) -> int:

        if tactic is None:
            return 0

        return MITRE_TACTIC_ENCODING.get(
            tactic.strip(),
            0,
        )

    # -----------------------------------------------------
    # Event Category
    # -----------------------------------------------------

    def encode_event_category(
        self,
        category: Optional[str],
    ) -> int:

        if category is None:
            return EVENT_CATEGORY_ENCODING["Unknown"]

        return EVENT_CATEGORY_ENCODING.get(
            category.strip(),
            EVENT_CATEGORY_ENCODING["Unknown"],
        )

    # -----------------------------------------------------
    # Boolean
    # -----------------------------------------------------

    @staticmethod
    def encode_boolean(value) -> int:

        if value in (
            True,
            1,
            "1",
            "true",
            "True",
            "TRUE",
            "yes",
            "YES",
            "Yes",
        ):
            return 1

        return 0

    # -----------------------------------------------------
    # CVSS
    # -----------------------------------------------------

    @staticmethod
    def normalize_cvss(score) -> float:

        if score is None:
            return 0.0

        try:
            score = float(score)
        except (TypeError, ValueError):
            return 0.0

        score = max(0.0, min(score, 10.0))

        return round(score / 10.0, 4)

    # -----------------------------------------------------
    # Threat Score
    # -----------------------------------------------------

    @staticmethod
    def normalize_threat_score(score) -> float:

        if score is None:
            return 0.0

        try:
            score = float(score)
        except (TypeError, ValueError):
            return 0.0

        score = max(0.0, min(score, 100.0))

        return round(score / 100.0, 4)

    # -----------------------------------------------------
    # Safe Numeric
    # -----------------------------------------------------

    @staticmethod
    def safe_numeric(
        value,
        default: float = 0.0,
    ) -> float:

        if value is None:
            return default

        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    # -----------------------------------------------------
    # Encode Event
    # -----------------------------------------------------

    @staticmethod
    def encode_event(*args, **kwargs) -> Dict:

        if args and isinstance(args[0], dict) and not kwargs:
            event = args[0]
            source = event.get("source")
            technique = event.get("technique") or event.get("mitre_technique_id")
            asset = event.get("asset") or event.get("asset_criticality")
            known_attack = event.get("known_attack") or event.get("matched_ioc")
        else:
            event = {}
            source = kwargs.get("source", args[0] if args else None)
            technique = kwargs.get("technique", args[1] if len(args) > 1 else None)
            asset = kwargs.get("asset", args[2] if len(args) > 2 else None)
            known_attack = kwargs.get("known_attack", args[3] if len(args) > 3 else None)

        return {
            "source_id": FeatureEncoder.encode_source(source),
            "technique_id": FeatureEncoder.encode_technique(technique),
            "asset_score": FeatureEncoder.encode_asset(asset),
            "known_attack": FeatureEncoder.encode_boolean(known_attack),
            **event,
        }


# ---------------------------------------------------------
# Singleton
# ---------------------------------------------------------

_encoder = FeatureEncoder()


def encode_event(
    event: Dict,
) -> Dict:

    return _encoder.encode_event(event)


# ---------------------------------------------------------
# Local Test
# ---------------------------------------------------------

if __name__ == "__main__":

    from pprint import pprint

    sample = {
        "severity": "HIGH",
        "protocol": "TCP",
        "asset_criticality": "CRITICAL",
        "mitre_tactic": "Execution",
        "event_category": "Malware",
        "cvss_score": 9.8,
        "matched_ioc": True,
        "threat_score": 95,
    }

    pprint(encode_event(sample))