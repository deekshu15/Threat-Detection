from __future__ import annotations

from typing import Dict


RISK_LEVELS = {
    "BENIGN": "LOW",
    "PortScan": "MEDIUM",
    "FTP-Patator": "HIGH",
    "SSH-Patator": "HIGH",
    "Bot": "HIGH",
    "Infiltration": "CRITICAL",
    "Heartbleed": "CRITICAL",
    "DoS Hulk": "CRITICAL",
    "DoS GoldenEye": "CRITICAL",
    "DoS slowloris": "CRITICAL",
    "DoS Slowhttptest": "CRITICAL",
    "DDoS": "CRITICAL",
    "Web Attack - Brute Force": "HIGH",
    "Web Attack - XSS": "HIGH",
    "Web Attack - SQL Injection": "CRITICAL",
}


RECOMMENDATIONS = {
    "LOW": [
        "Continue monitoring.",
        "No immediate action required.",
    ],
    "MEDIUM": [
        "Increase monitoring frequency.",
        "Review network traffic.",
    ],
    "HIGH": [
        "Investigate the source immediately.",
        "Block suspicious IP addresses.",
        "Collect forensic evidence.",
    ],
    "CRITICAL": [
        "Trigger incident response.",
        "Isolate affected assets.",
        "Block malicious traffic.",
        "Notify the SOC team.",
    ],
}


def postprocess(result: Dict) -> Dict:

    attack = result["prediction"]

    risk = RISK_LEVELS.get(
        attack,
        "MEDIUM",
    )

    result["risk_level"] = risk

    result["recommended_actions"] = RECOMMENDATIONS[risk]

    return result


if __name__ == "__main__":

    sample = {
        "prediction": "DDoS",
        "confidence": 0.93,
        "prediction_index": 2,
        "probabilities": [],
    }

    from pprint import pprint

    pprint(postprocess(sample))