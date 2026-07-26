"""
MITRE ATT&CK Mapper

Maps normalized security events to the MITRE ATT&CK framework.
"""

import json
from pathlib import Path


class MITREMapper:
    """Maps Windows, IDS and CVE events to MITRE ATT&CK."""

    def __init__(self):

        mapping_file = (
            Path(__file__).parent
            / "mappings"
            / "mitre_mapping.json"
        )

        with open(mapping_file, "r", encoding="utf-8") as f:
            self.mapping = json.load(f)

    def map_event(self, event: dict) -> dict:
        """
        Add MITRE ATT&CK information to an event.

        Args:
            event: Normalized event dictionary.

        Returns:
            Enriched event dictionary.
        """

        source = str(event.get("source", "")).lower()

        technique = None

        # ----------------------------------------------------------
        # Windows
        # ----------------------------------------------------------
        if source == "windows":

            event_id = str(event.get("event_type", ""))

            technique = (
                self.mapping
                .get("windows", {})
                .get(event_id)
            )

        # ----------------------------------------------------------
        # IDS
        # ----------------------------------------------------------
        elif source == "ids":

            attack = str(event.get("event_type", ""))

            technique = (
                self.mapping
                .get("ids", {})
                .get(attack)
            )

        # ----------------------------------------------------------
        # CVE
        # ----------------------------------------------------------
        elif source == "cve":

            cwe = event.get("cwe", "")

            technique = (
                self.mapping
                .get("cve", {})
                .get(cwe)
            )

        # ----------------------------------------------------------
        # Apply mapping
        # ----------------------------------------------------------
        if technique:

            event["mitre_technique_id"] = technique["technique_id"]

            event["mitre_technique"] = technique["technique"]

            event["mitre_tactic"] = technique["tactic"]

        else:

            event["mitre_technique_id"] = ""

            event["mitre_technique"] = "Unknown"

            event["mitre_tactic"] = "Unknown"

        return event