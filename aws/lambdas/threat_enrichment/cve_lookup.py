"""
CVE Lookup Engine

Provides high-performance CVE enrichment using the local
CVE reference dataset.

Responsibilities
----------------
- Load CVE dataset once
- Cache in memory
- Lookup CVE by ID
- Search CVEs in raw logs
- Return CVSS score
- Return severity
- Return metadata

Author:
AI Threat Detection Dashboard
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

import pandas as pd

logger = logging.getLogger(__name__)


# ---------------------------------------------------------
# CVE Regex
# ---------------------------------------------------------

CVE_PATTERN = re.compile(
    r"CVE-\d{4}-\d{4,7}",
    re.IGNORECASE,
)


# ---------------------------------------------------------
# Result Object
# ---------------------------------------------------------

@dataclass(slots=True)
class CVEResult:

    cve_exists: bool = False

    cve_id: Optional[str] = None

    cvss_score: Optional[float] = None

    severity: Optional[str] = None

    description: Optional[str] = None

    published: Optional[str] = None

    metadata: Optional[dict] = None


# ---------------------------------------------------------
# Lookup Engine
# ---------------------------------------------------------

class CVELookup:

    """
    Production CVE lookup engine.

    Loads the CVE parquet once and performs
    constant-time lookups.
    """

    def __init__(
        self,
        parquet_path: str,
    ):

        self.parquet_path = parquet_path

        self.df = pd.DataFrame()

        self.lookup_table: Dict[
            str,
            Dict,
        ] = {}

        self.load()


    # -----------------------------------------------------
    # Dataset Loading
    # -----------------------------------------------------

    def load(self):

        path = Path(
            self.parquet_path
        )

        if not path.exists():

            raise FileNotFoundError(
                self.parquet_path
            )

        logger.info(
            "Loading CVE dataset..."
        )

        self.df = pd.read_parquet(
            path
        )

        self.lookup_table = {}

        for _, row in self.df.iterrows():

            cve = str(
                row["cve_id"]
            ).upper()

            self.lookup_table[cve] = {

                "published":
                    row.get("published"),

                "cvss_score":
                    row.get("cvss_score"),

                "severity":
                    row.get("severity"),

                "description":
                    row.get("description"),
            }

        logger.info(

            "Loaded %d CVEs",

            len(self.lookup_table)

        )


    # -----------------------------------------------------
    # Direct Lookup
    # -----------------------------------------------------

    def lookup(
        self,
        cve_id: str,
    ) -> CVEResult:

        if not cve_id:

            return CVEResult()

        cve = cve_id.upper()

        if cve not in self.lookup_table:

            return CVEResult()

        record = self.lookup_table[cve]

        return CVEResult(

            cve_exists=True,

            cve_id=cve,

            cvss_score=record.get(
                "cvss_score"
            ),

            severity=record.get(
                "severity"
            ),

            description=record.get(
                "description"
            ),

            published=record.get(
                "published"
            ),

            metadata={
                "lookup": "local_dataset"
            },
        )


    # -----------------------------------------------------
    # Find CVE inside text
    # -----------------------------------------------------

    def extract_from_text(
        self,
        text: str,
    ) -> Optional[str]:

        if not text:
            return None

        match = CVE_PATTERN.search(text)

        if match:
            return match.group(0).upper()

        return None

    # -----------------------------------------------------
    # Event Lookup
    # -----------------------------------------------------

    def lookup_event(
        self,
        event: Dict,
    ) -> CVEResult:
        """
        Attempt to identify and enrich a CVE from an event.

        Search order:

        1. Explicit cve_id field
        2. raw_log
        3. description
        4. message
        """

        cve = None

        if event.get("cve_id"):

            cve = str(
                event["cve_id"]
            ).upper()

        elif event.get("raw_log"):

            cve = self.extract_from_text(
                event["raw_log"]
            )

        elif event.get("description"):

            cve = self.extract_from_text(
                event["description"]
            )

        elif event.get("message"):

            cve = self.extract_from_text(
                event["message"]
            )

        if cve:

            return self.lookup(cve)

        return CVEResult()

    # -----------------------------------------------------
    # Batch Lookup
    # -----------------------------------------------------

    def lookup_events(
        self,
        events,
    ):

        results = []

        logger.info(

            "Running CVE lookup for %d events.",

            len(events)

        )

        for event in events:

            results.append(

                self.lookup_event(event)

            )

        return results

    # -----------------------------------------------------
    # Dataset Statistics
    # -----------------------------------------------------

    def statistics(self):

        severity_counts = {}

        if not self.df.empty:

            for severity in self.df["severity"].fillna("UNKNOWN"):

                severity = str(
                    severity
                ).upper()

                severity_counts[severity] = (

                    severity_counts.get(
                        severity,
                        0,
                    )

                    + 1

                )

        return {

            "records": len(
                self.lookup_table
            ),

            "severity_distribution":
                severity_counts,

            "average_cvss":

                float(

                    self.df[
                        "cvss_score"
                    ].mean()

                )

                if not self.df.empty

                else None,

            "missing_cvss":

                int(

                    self.df[
                        "cvss_score"
                    ].isna().sum()

                )

                if not self.df.empty

                else 0,

        }


# ---------------------------------------------------------
# Singleton
# ---------------------------------------------------------

_default_lookup = None


def initialize(
    parquet_path: str,
):

    global _default_lookup

    _default_lookup = CVELookup(
        parquet_path
    )


def lookup_cve(
    cve_id: str,
) -> CVEResult:

    if _default_lookup is None:

        raise RuntimeError(
            "CVE lookup not initialized."
        )

    return _default_lookup.lookup(
        cve_id
    )


def lookup_event(
    event: Dict,
) -> CVEResult:

    if _default_lookup is None:

        raise RuntimeError(
            "CVE lookup not initialized."
        )

    return _default_lookup.lookup_event(
        event
    )


# ---------------------------------------------------------
# Local Testing
# ---------------------------------------------------------

if __name__ == "__main__":

    logging.basicConfig(

        level=logging.INFO,

        format="%(levelname)s - %(message)s"

    )

    lookup = CVELookup(

        "../../normalized_output/cve_reference.parquet"

    )

    print()

    print(

        lookup.lookup(

            "CVE-2025-0168"

        )

    )

    print()

    sample_event = {

        "raw_log":

        """
        Authentication failure caused by
        CVE-2025-0168 exploitation attempt.
        """

    }

    print(

        lookup.lookup_event(

            sample_event

        )

    )

    print()

    print(

        lookup.statistics()

    )