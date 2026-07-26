"""
Threat Score Engine

Calculates the overall threat score for an enriched
security event.

Threat Score Components
-----------------------
- Event Severity
- CVSS Score
- IOC Match
- MITRE ATT&CK
- Asset Criticality
- Known Attack
- Event Category

Output
------
Threat Score (0-100)

Author:
AI Threat Detection Dashboard
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------
# Result
# ---------------------------------------------------------

@dataclass(slots=True)
class ThreatScoreResult:

    threat_score: float

    severity_score: float

    risk_weight: float

    confidence: float

    threat_level: str

    score_breakdown: Dict


# ---------------------------------------------------------
# Weight Configuration
# ---------------------------------------------------------

WEIGHTS = {

    "severity": 20,

    "cvss": 25,

    "ioc": 20,

    "mitre": 15,

    "asset": 10,

    "known_attack": 5,

    "event_category": 5,
}


SEVERITY_SCORE = {

    "LOW": 25,

    "MEDIUM": 50,

    "HIGH": 75,

    "CRITICAL": 100,

    "UNKNOWN": 20,
}


ASSET_SCORE = {

    "LOW": 20,

    "MEDIUM": 50,

    "HIGH": 80,

    "CRITICAL": 100,

    "UNKNOWN": 40,
}


EVENT_CATEGORY_SCORE = {

    "AUTHENTICATION": 40,

    "NETWORK": 50,

    "PROCESS": 70,

    "FILE": 65,

    "MALWARE": 95,

    "PRIVILEGE_ESCALATION": 100,

    "LATERAL_MOVEMENT": 95,

    "COMMAND_AND_CONTROL": 100,

    "EXFILTRATION": 100,

    "IMPACT": 100,

    "OTHER": 40,
}


# ---------------------------------------------------------
# Threat Score Engine
# ---------------------------------------------------------

class ThreatScoreEngine:

    """
    Calculates production-ready threat scores.
    """

    def calculate(
        self,
        event: Dict,
    ) -> ThreatScoreResult:

        severity = self._severity_score(
            event.get(
                "severity"
            )
        )

        cvss = self._cvss_score(
            event.get(
                "cvss_score"
            )
        )

        ioc = self._ioc_score(
            event.get(
                "matched_ioc"
            )
        )

        mitre = self._mitre_score(
            event.get(
                "technique_weight"
            )
        )

        asset = self._asset_score(
            event.get(
                "asset_criticality"
            )
        )

        attack = self._known_attack_score(
            event.get(
                "known_attack"
            )
        )

        category = self._category_score(
            event.get(
                "event_category"
            )
        )

        weighted_score = (

            severity * WEIGHTS["severity"]

            + cvss * WEIGHTS["cvss"]

            + ioc * WEIGHTS["ioc"]

            + mitre * WEIGHTS["mitre"]

            + asset * WEIGHTS["asset"]

            + attack * WEIGHTS["known_attack"]

            + category * WEIGHTS["event_category"]

        ) / 100

        threat_level = self._threat_level(
            weighted_score
        )

        confidence = self._confidence(
            event
        )

        return ThreatScoreResult(

            threat_score=round(
                weighted_score,
                2,
            ),

            severity_score=severity,

            risk_weight=round(
                weighted_score,
                2,
            ),

            confidence=confidence,

            threat_level=threat_level,

            score_breakdown={

                "severity": severity,

                "cvss": cvss,

                "ioc": ioc,

                "mitre": mitre,

                "asset": asset,

                "known_attack": attack,

                "category": category,
            },
        )
            # -----------------------------------------------------
    # Severity Score
    # -----------------------------------------------------

    def _severity_score(
        self,
        severity: Optional[str],
    ) -> float:

        if not severity:
            return SEVERITY_SCORE["UNKNOWN"]

        return SEVERITY_SCORE.get(
            str(severity).upper(),
            SEVERITY_SCORE["UNKNOWN"],
        )

    # -----------------------------------------------------
    # CVSS Score
    # -----------------------------------------------------

    def _cvss_score(
        self,
        cvss: Optional[float],
    ) -> float:

        if cvss is None:
            return 20

        try:

            value = float(cvss)

        except (
            TypeError,
            ValueError,
        ):

            return 20

        value = max(
            0.0,
            min(
                value,
                10.0,
            ),
        )

        return round(
            (value / 10.0) * 100,
            2,
        )

    # -----------------------------------------------------
    # IOC Score
    # -----------------------------------------------------

    def _ioc_score(
        self,
        matched_ioc,
    ) -> float:

        if matched_ioc:

            return 100

        return 0

    # -----------------------------------------------------
    # MITRE Score
    # -----------------------------------------------------

    def _mitre_score(
        self,
        technique_weight,
    ) -> float:

        if technique_weight is None:

            return 20

        try:

            score = float(
                technique_weight
            )

        except (
            TypeError,
            ValueError,
        ):

            return 20

        return max(
            0,
            min(
                score,
                100,
            ),
        )

    # -----------------------------------------------------
    # Asset Criticality
    # -----------------------------------------------------

    def _asset_score(
        self,
        asset,
    ) -> float:

        if not asset:

            return ASSET_SCORE["UNKNOWN"]

        return ASSET_SCORE.get(

            str(asset).upper(),

            ASSET_SCORE["UNKNOWN"]

        )

    # -----------------------------------------------------
    # Known Attack
    # -----------------------------------------------------

    def _known_attack_score(
        self,
        known_attack,
    ) -> float:

        if known_attack:

            return 100

        return 0

    # -----------------------------------------------------
    # Event Category
    # -----------------------------------------------------

    def _category_score(
        self,
        category,
    ) -> float:

        if not category:

            return EVENT_CATEGORY_SCORE["OTHER"]

        key = (

            str(category)

            .upper()

            .replace(
                " ",
                "_",
            )

        )

        return EVENT_CATEGORY_SCORE.get(

            key,

            EVENT_CATEGORY_SCORE["OTHER"]

        )
            # -----------------------------------------------------
    # Confidence Score
    # -----------------------------------------------------

    def _confidence(
        self,
        event: Dict,
    ) -> float:
        """
        Estimate confidence based on the amount of
        supporting enrichment evidence available.
        """

        score = 0

        if event.get("matched_ioc"):
            score += 25

        if event.get("cvss_score") is not None:
            score += 20

        if event.get("mitre_technique_id"):
            score += 20

        if event.get("known_attack"):
            score += 15

        if event.get("severity"):
            score += 10

        if event.get("asset_criticality"):
            score += 10

        return round(
            min(score, 100) / 100,
            2,
        )

    # -----------------------------------------------------
    # Threat Level
    # -----------------------------------------------------

    def _threat_level(
        self,
        score: float,
    ) -> str:

        if score >= 90:
            return "CRITICAL"

        if score >= 75:
            return "HIGH"

        if score >= 50:
            return "MEDIUM"

        if score >= 25:
            return "LOW"

        return "INFORMATIONAL"

    # -----------------------------------------------------
    # Batch Processing
    # -----------------------------------------------------

    def calculate_events(
        self,
        events,
    ):

        logger.info(

            "Calculating threat score for %d events.",

            len(events)

        )

        results = []

        for event in events:

            results.append(

                self.calculate(
                    event
                )

            )

        return results

    # -----------------------------------------------------
    # Statistics
    # -----------------------------------------------------

    def statistics(
        self,
        results,
    ):

        if not results:

            return {

                "total_events": 0,

                "average_score": 0,

                "highest_score": 0,

                "lowest_score": 0,

                "distribution": {},
            }

        scores = [

            r.threat_score

            for r in results

        ]

        distribution = {

            "CRITICAL": 0,

            "HIGH": 0,

            "MEDIUM": 0,

            "LOW": 0,

            "INFORMATIONAL": 0,
        }

        for result in results:

            distribution[
                result.threat_level
            ] += 1

        return {

            "total_events":

                len(results),

            "average_score":

                round(

                    sum(scores) / len(scores),

                    2,

                ),

            "highest_score":

                max(scores),

            "lowest_score":

                min(scores),

            "distribution":

                distribution,
        }


# ---------------------------------------------------------
# Singleton
# ---------------------------------------------------------

_default_engine = ThreatScoreEngine()


def calculate(
    event: Dict,
) -> ThreatScoreResult:

    return _default_engine.calculate(
        event
    )


def calculate_events(
    events,
):

    return _default_engine.calculate_events(
        events
    )


# ---------------------------------------------------------
# Local Testing
# ---------------------------------------------------------

if __name__ == "__main__":

    logging.basicConfig(

        level=logging.INFO,

        format="%(levelname)s - %(message)s"

    )

    sample_event = {

        "severity": "HIGH",

        "cvss_score": 9.8,

        "matched_ioc": True,

        "technique_weight": 95,

        "asset_criticality": "CRITICAL",

        "known_attack": True,

        "event_category": "Malware",

        "mitre_technique_id": "T1486",

    }

    result = calculate(
        sample_event
    )

    print()

    print(result)

    print()

    stats = _default_engine.statistics(
        [result]
    )

    print(stats)