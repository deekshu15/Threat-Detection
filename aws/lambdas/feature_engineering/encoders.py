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

    def encode_asset(
        self,
        asset: Optional[str],
    ) -> int:

        if asset is None:
            return ASSET_ENCODING["UNKNOWN"]

        asset = asset.upper().strip()

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

    def encode_event(
        self,
        event: Dict,
    ) -> Dict:

        encoded = dict(event)

        encoded["severity_encoded"] = self.encode_severity(
            event.get("severity")
        )

        encoded["protocol_encoded"] = self.encode_protocol(
            event.get("protocol")
        )

        encoded["asset_score"] = self.encode_asset(
            event.get("asset_criticality")
        )

        encoded["mitre_weight"] = self.encode_mitre_tactic(
            event.get("mitre_tactic")
        )

        encoded["event_category_encoded"] = self.encode_event_category(
            event.get("event_category")
        )

        encoded["cvss_normalized"] = self.normalize_cvss(
            event.get("cvss_score")
        )

        encoded["threat_score_normalized"] = self.normalize_threat_score(
            event.get("threat_score")
        )

        encoded["ioc_flag"] = self.encode_boolean(
            event.get("matched_ioc")
        )

        return encoded


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