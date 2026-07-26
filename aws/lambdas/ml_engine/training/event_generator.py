"""
Event Generator

Converts CICIDS2017 network flows into the
security event schema expected by the Feature
Engineering pipeline.
"""

from __future__ import annotations

from datetime import datetime

from datetime import datetime
import pandas as pd

PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

ATTACK_MAPPING = {

    "BENIGN": {
        "severity": "LOW",
        "cvss": 1.5,
        "threat": 10,
        "category": "Normal",
        "tactic": "None",
        "technique": "None",
        "asset": "LOW",
    },

    "PortScan": {
        "severity": "MEDIUM",
        "cvss": 5.5,
        "threat": 60,
        "category": "Reconnaissance",
        "tactic": "Discovery",
        "technique": "T1046",
        "asset": "MEDIUM",
    },

    "DDoS": {
        "severity": "CRITICAL",
        "cvss": 9.8,
        "threat": 98,
        "category": "Network Attack",
        "tactic": "Impact",
        "technique": "T1498",
        "asset": "CRITICAL",
    },

    "DoS Hulk": {
        "severity": "HIGH",
        "cvss": 9.3,
        "threat": 95,
        "category": "Network Attack",
        "tactic": "Impact",
        "technique": "T1499",
        "asset": "HIGH",
    },

    "DoS GoldenEye": {
        "severity": "HIGH",
        "cvss": 8.7,
        "threat": 90,
        "category": "Network Attack",
        "tactic": "Impact",
        "technique": "T1499",
        "asset": "HIGH",
    },

    "DoS slowloris": {
        "severity": "HIGH",
        "cvss": 8.8,
        "threat": 88,
        "category": "Application Attack",
        "tactic": "Impact",
        "technique": "T1499",
        "asset": "HIGH",
    },

    "DoS Slowhttptest": {
        "severity": "HIGH",
        "cvss": 8.6,
        "threat": 86,
        "category": "Application Attack",
        "tactic": "Impact",
        "technique": "T1499",
        "asset": "HIGH",
    },

    "Bot": {
        "severity": "HIGH",
        "cvss": 8.5,
        "threat": 80,
        "category": "Malware",
        "tactic": "Command and Control",
        "technique": "T1071",
        "asset": "HIGH",
    },

    "FTP-Patator": {
        "severity": "HIGH",
        "cvss": 7.8,
        "threat": 72,
        "category": "Credential Attack",
        "tactic": "Credential Access",
        "technique": "T1110",
        "asset": "MEDIUM",
    },

    "SSH-Patator": {
        "severity": "HIGH",
        "cvss": 8.0,
        "threat": 74,
        "category": "Credential Attack",
        "tactic": "Credential Access",
        "technique": "T1110",
        "asset": "MEDIUM",
    },

    "Heartbleed": {
        "severity": "CRITICAL",
        "cvss": 10.0,
        "threat": 100,
        "category": "Exploitation",
        "tactic": "Initial Access",
        "technique": "T1190",
        "asset": "CRITICAL",
    },

    "Infiltration": {
        "severity": "CRITICAL",
        "cvss": 9.8,
        "threat": 96,
        "category": "Intrusion",
        "tactic": "Lateral Movement",
        "technique": "T1021",
        "asset": "CRITICAL",
    },

    "Web Attack - Brute Force": {
        "severity": "HIGH",
        "cvss": 8.5,
        "threat": 84,
        "category": "Web Attack",
        "tactic": "Credential Access",
        "technique": "T1110",
        "asset": "HIGH",
    },

    "Web Attack - XSS": {
        "severity": "HIGH",
        "cvss": 8.0,
        "threat": 82,
        "category": "Web Attack",
        "tactic": "Execution",
        "technique": "T1059",
        "asset": "HIGH",
    },

    "Web Attack - SQL Injection": {
        "severity": "CRITICAL",
        "cvss": 9.8,
        "threat": 97,
        "category": "Web Attack",
        "tactic": "Execution",
        "technique": "T1190",
        "asset": "CRITICAL",
    }
}

class EventGenerator:

    def generate(self, row):

        label = (
            str(row["Label"])
            .replace("�", "-")
            .replace("Sql", "SQL")
            .strip()
        )

        attack = ATTACK_MAPPING.get(
            label,
            ATTACK_MAPPING["BENIGN"]
        )

        protocol_number = int(row.get("Protocol", 6))

        protocol = PROTOCOL_MAP.get(
            protocol_number,
            "OTHER"
        )

        src_ip = (
            f"192.168.{row.name % 250}."
            f"{(row.name // 250) % 250}"
        )

        dest_ip = (
            f"10.10.{(row.name // 1000) % 250}."
            f"{row.name % 250}"
        )

        return {

            "event_id": f"CICIDS-{row.name}",

            "timestamp": datetime.now(),

            "src_ip": src_ip,

            "dest_ip": dest_ip,

            "src_port": int(
                row.get("Source Port", 50000)
            ),

            "dest_port": int(
                row.get("Destination Port", 80)
            ),

            "protocol": protocol,

            "severity": attack["severity"],

            "event_category": attack["category"],

            "host": f"host-{row.name % 100}",

            "user": f"user-{row.name % 50}",

            "asset_criticality": attack["asset"],

            "threat_score": attack["threat"],

            "matched_ioc": attack["threat"] >= 80,

            "mitre_tactic": attack["tactic"],

            "mitre_technique_id": attack["technique"],

            "cvss_score": attack["cvss"],

            "metadata": {
                "original_label": label
            },
        }

_generator = EventGenerator()


def generate_event(row):

    return _generator.generate(row)

if __name__ == "__main__":

    import pandas as pd

    from .dataset_loader import load_dataset

    df = load_dataset()

    print(generate_event(df.iloc[0]))