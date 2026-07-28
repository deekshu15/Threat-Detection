"""
Local Development API

Serves real, normalized data from the tested backend pipeline
(aws/lambda/normalize_security_logs) over HTTP, so the frontend
can call it like a real API during local development.

This is NOT the production Lambda - it's a thin wrapper around the
same, already-tested processor code, just exposed over localhost
for frontend integration before real AWS deployment happens.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from fastapi import HTTPException

from aws.lambdas.feature_engineering.feature_pipeline import process_event
from aws.lambdas.ml_engine.predictor import predict

from local_api.services.analysis_service import analysis_service
from local_api.models.request import ThreatAnalysisRequest
# --------------------------------------------------
# Threat Analysis Request Model
# --------------------------------------------------

class ThreatAnalysisRequest(BaseModel):
    event_id: str
    timestamp: str

    src_ip: str
    dest_ip: str

    protocol: str

    severity: str
    event_category: str

    asset_criticality: str

    threat_score: float
    cvss_score: float

    matched_ioc: bool

    mitre_technique_id: str
    mitre_tactic: str

    user: str
    host: str

    src_port: int
    dest_port: int

# ------------------------------------------------------------------
# Make the real backend code importable
# ------------------------------------------------------------------
BACKEND_ROOT = (
    Path(__file__).resolve().parent.parent
    / "aws"
    / "lambdas"
    / "normalize_security_logs"
)
sys.path.append(str(BACKEND_ROOT))

from processors.cve_processor import CVEProcessor  # noqa: E402

app = FastAPI(title="Threat Detection Dashboard - Local Dev API")

# Allow the frontend dev server to call this API from the browser.
# Vite's default port is 5173; Create React App's default is 3000.
# Add any other port your frontend actually runs on.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
    ],
    allow_methods=["GET"],
    allow_headers=["*"],
)

CVE_DATASET_PATH = (
    Path(__file__).resolve().parent.parent
    / "datasets"
    / "raw"
    / "cve"
    / "nvdcve-2.0-recent.json"
)

# NVD's baseSeverity comes back uppercase (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN).
# The frontend's CVE type only supports Critical/High/Medium/Low - no "Unknown".
# UNKNOWN is mapped to "Low" here as a deliberate, visible default.
SEVERITY_MAP = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "UNKNOWN": "Low",
}


def to_relative_time(iso_timestamp: str) -> str:
    """Converts an ISO timestamp into a human phrase like 'Today', '2 days ago'."""
    if not iso_timestamp:
        return "Unknown"

    try:
        published = datetime.fromisoformat(iso_timestamp)
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
    except ValueError:
        return "Unknown"

    now = datetime.now(timezone.utc)
    delta_days = (now - published).days

    if delta_days <= 0:
        return "Today"
    if delta_days == 1:
        return "Yesterday"
    return f"{delta_days} days ago"


@app.get("/api/cves")
def get_latest_cves(limit: int = 10):
    """
    Returns the most recently published CVEs, shaped to match the
    frontend's CVE type exactly: { id, severity, description, published }
    """
    with open(CVE_DATASET_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    processor = CVEProcessor()
    records = processor.normalize(data)

    # Most recently published first
    records.sort(key=lambda r: r.timestamp or "", reverse=True)

    results = []
    for record in records[:limit]:
        results.append(
            {
                "id": record.event_id,
                "severity": SEVERITY_MAP.get(record.severity, "Low"),
                "description": record.description or "No description available",
                "published": to_relative_time(record.timestamp),
            }
        )

    return results


@app.get("/health")
def health_check():
    """Quick check that the API is running - visit http://localhost:8000/health in a browser."""
    return {"status": "ok"}

# ------------------------------------------------------------------
# SIEM Monitoring: real normalized Windows + IDS event data
# ------------------------------------------------------------------

from processors.windows_processor import WindowsProcessor  # noqa: E402
from processors.ids_processor import IDSProcessor  # noqa: E402
import pandas as pd  # noqa: E402

WINDOWS_DATASET_PATH = (
    Path(__file__).resolve().parent.parent / "datasets" / "raw" / "windows" / "windows_events.csv"
)
IDS_FOLDER = Path(__file__).resolve().parent.parent / "datasets" / "raw" / "ids"

# Well-known, publicly documented Windows Security Event ID meanings.
# Not fabricated - these are standard Microsoft-published event codes.
WINDOWS_EVENT_MEANINGS = {
    # Sysmon
    1: "Process Created",
    2: "File Creation Time Changed",
    3: "Network Connection",
    5: "Process Terminated",
    6: "Driver Loaded",
    7: "Image Loaded",
    8: "CreateRemoteThread",
    9: "Raw Disk Access Read",
    10: "Process Access",
    11: "File Created",
    12: "Registry Object Created/Deleted",
    13: "Registry Value Set",
    14: "Registry Key/Value Renamed",
    17: "Pipe Created",
    18: "Pipe Connected",
    22: "DNS Query",
    # Windows Security Log
    4624: "Successful Logon",
    4625: "Failed Logon",
    4663: "Object Access Attempt",
    5136: "Directory Service Object Modified",
    5145: "Network Share Access Check",
    5156: "Network Connection Allowed",
    # MSI Installer
    1040: "Software Install/Uninstall Started",
    1042: "Software Install/Uninstall Finished",
}

SIEM_SEVERITY_MAP = {
    "Critical": "Critical",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "Informational": "Low",
    "Unknown": "Low",
}


def _describe_event(row) -> str:
    """Builds a readable message. Windows uses the known-code lookup; IDS labels are already readable."""
    if row["source"] == "windows":
        try:
            code = int(row["event_type"])
            return WINDOWS_EVENT_MEANINGS.get(code, f"Event ID {code}")
        except (TypeError, ValueError):
            return "Unknown Windows Event"
    return str(row["event_type"])

_events_cache = None

def _load_combined_events() -> pd.DataFrame:
    global _events_cache
    if _events_cache is not None:
        return _events_cache.copy()

    frames = []
    if WINDOWS_DATASET_PATH.exists():
        windows_df = pd.read_csv(WINDOWS_DATASET_PATH, low_memory=False)
        frames.append(WindowsProcessor().normalize(windows_df))

    ids_files = sorted(IDS_FOLDER.glob("*.csv")) if IDS_FOLDER.exists() else []
    if ids_files:
        ids_df = pd.read_csv(ids_files[0], low_memory=False)
        frames.append(IDSProcessor().normalize(ids_df))

    if not frames:
        return pd.DataFrame()

    combined = pd.concat(frames, ignore_index=True)
    combined["severity"] = combined["severity"].map(SIEM_SEVERITY_MAP).fillna("Low")
    _events_cache = combined
    return _events_cache.copy()


@app.get("/api/siem/events")
def get_siem_events(limit: int = 20):
    """Returns real, normalized security events shaped to match the frontend's SIEMEvent type."""
    combined = _load_combined_events()
    if combined.empty:
        return []

    combined = combined.sort_values("timestamp", ascending=False).head(limit)

    results = []
    for idx, row in combined.iterrows():
        timestamp = row["timestamp"]
        time_label = timestamp.strftime("%H:%M") if pd.notna(timestamp) else "Unknown"

        results.append(
            {
                "id": int(idx),
                "timestamp": time_label,
                "source": str(row["source"]).capitalize(),
                "severity": row["severity"],
                "message": _describe_event(row),
            }
        )

    return results


@app.get("/api/siem/severity")
def get_siem_severity():
    """Returns real severity counts across combined Windows + IDS events."""
    combined = _load_combined_events()
    if combined.empty:
        return []

    counts = combined["severity"].value_counts()

    # Always return all 4 categories, even if a count is 0, so the chart doesn't silently drop bars.
    ordered = ["Critical", "High", "Medium", "Low"]
    return [{"severity": s, "count": int(counts.get(s, 0))} for s in ordered]


@app.get("/api/siem/source-breakdown")
def get_source_breakdown():
    """Real event count and share per data source."""
    combined = _load_combined_events()
    if combined.empty:
        return []
    total = len(combined)
    counts = combined["source"].value_counts()
    label_map = {"windows": "Windows", "ids": "IDS"}
    return [
        {"source": label_map.get(src, src.capitalize()), "count": int(count), "percent": round(count / total * 100, 1)}
        for src, count in counts.items()
    ]


@app.get("/api/siem/priorities")
def get_priorities(limit: int = 3):
    """Most recent genuinely high-severity events, used as real 'immediate priorities'."""
    combined = _load_combined_events()
    if combined.empty:
        return []
    priority = combined[combined["severity"].isin(["Critical", "High"])].sort_values(
        "timestamp", ascending=False
    ).head(limit)

    results = []
    for idx, row in priority.iterrows():
        timestamp = row["timestamp"]
        time_label = timestamp.strftime("%H:%M") if pd.notna(timestamp) else "Unknown"
        results.append(
            {
                "id": int(idx),
                "title": _describe_event(row),
                "detail": f"{str(row['source']).capitalize()} • {row['severity']} • {time_label}",
                "severity": row["severity"],
            }
        )
    return results

@app.get("/api/siem/total-count")
def get_total_event_count():
    """Returns the total number of real events across combined Windows + IDS data."""
    combined = _load_combined_events()
    return {"total": len(combined)}

# --------------------------------------------------
# Threat Analysis API
# --------------------------------------------------

@app.post("/api/analyze")
def analyze(request: ThreatAnalysisRequest):

    result = analysis_service.analyze(
        request.model_dump()
    )

    return {
    "success": True,

    "prediction": result["prediction"],

    "enriched_event": result["enriched_event"],

    "validated_event": result["validated_event"],

    "feature_count": len(result["features"]),

    "vector_length": len(result["vector"]),

    "processing": {
        "model": "RandomForest-v1"
    }
}
    