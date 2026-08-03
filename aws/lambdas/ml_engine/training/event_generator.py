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

class EventGenerator:

    def generate(self, row):

        # IMPORTANT: For training we must not leak the ground-truth label
        # into the generated event fields. This training event generator
        # produces only values that are available at inference time and
        # derived from raw flow attributes. We deliberately avoid using
        # the original dataset `Label` to populate enrichment fields.

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

        # Use conservative defaults that do NOT encode the label.
        # These values are intentionally neutral and only use flow-level
        # information (or safe defaults) so the model cannot learn the
        # ground-truth from engineered features.

        # Prefer dataset-provided timestamps when available to ensure
        # temporal features are computed correctly and do not leak
        # future information. Try multiple common timestamp column
        # names (case-sensitive) and fall back to now().
        ts = None
        for key in ("timestamp", "Timestamp", "time", "Time"):
            if key in row:
                ts = row.get(key)
                break

        if ts is not None:
            try:
                ts = pd.to_datetime(ts)
            except Exception:
                ts = datetime.now()
        else:
            ts = datetime.now()

        event = {

            "event_id": f"CICIDS-{row.name}",

            "timestamp": ts,

            "src_ip": src_ip,

            "dest_ip": dest_ip,

            "src_port": int(
                row.get("Source Port", 50000)
            ),

            "dest_port": int(
                row.get("Destination Port", 80)
            ),

            "protocol": protocol,

            # Do NOT derive severity from the ground-truth label. Use a
            # neutral value that will be validated by the feature pipeline.
            "severity": "UNKNOWN",

            # Event category must be present for validator, but set to
            # a non-informative default.
            "event_category": "Unknown",

            "host": f"host-{row.name % 100}",

            "user": f"user-{row.name % 50}",

            # Asset criticality and threat indicators must exist but must
            # not leak the label. Use UNKNOWN / zero defaults.
            "asset_criticality": "UNKNOWN",

            "threat_score": 0,

            "matched_ioc": False,

            "mitre_tactic": None,

            "mitre_technique_id": None,

            "cvss_score": None,

            "metadata": {},
        }

        # Merge raw row columns into the event for flow-feature extraction.
        # Exclude Label/Target to avoid reintroducing ground-truth.
        try:
            raw = dict(row)
        except Exception:
            raw = {}

        for k, v in raw.items():
            if str(k).lower() in {"label", "target", "original_label"}:
                continue
            # Do not override core fields we explicitly set above
            if k not in event:
                event[k] = v

        return event


_generator = EventGenerator()


def generate_event(row):

    return _generator.generate(row)

if __name__ == "__main__":

    import pandas as pd

    from .dataset_loader import load_dataset

    df = load_dataset()

    print(generate_event(df.iloc[0]))