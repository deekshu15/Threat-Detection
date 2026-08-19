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
import time
import logging
from fastapi import FastAPI, logger
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from fastapi import HTTPException
from fastapi import File, UploadFile

from aws.lambdas.feature_engineering.feature_pipeline import process_event
from aws.lambdas.ml_engine.predictor import predict

from local_api.services.analysis_service import analysis_service
from local_api.services.dashboard_service import (
    DashboardService,
    DashboardDataError,
)
from local_api.services.events_service import events_service

import logging
from datetime import datetime, timezone
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
dashboard_service = DashboardService()

# Allow the frontend dev server to call this API from the browser.
# Vite's default port is 5173; Create React App's default is 3000.
# Add any other port your frontend actually runs on.
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
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
    logger = logging.getLogger("local_api.analyze")
    payload = request.model_dump()
    start = datetime.now(timezone.utc)

    try:
        result = analysis_service.analyze(payload)

        pred = result.get("prediction")

        model_info = {
            "model": getattr(result.get("prediction", {}), "get", lambda k, d=None: None)("model_name", None)
        }

        response = {
            "success": True,
            "prediction": pred,
            "enriched_event": result.get("enriched_event"),
            "validated_event": result.get("validated_event"),
            # Report the actual feature count used by the model (vector length)
            "feature_count": len(result.get("vector", [])),
            "vector_length": len(result.get("vector", [])),
            "processing": {
                "model_name": model_info.get("model") or getattr(result.get("prediction", {}), "get", lambda k, d=None: None)("model_name", None)
            },
            "timing": {
                "prediction_time": datetime.now(timezone.utc).isoformat(),
                "elapsed_ms": (datetime.now(timezone.utc) - start).total_seconds() * 1000,
            },
        }

        return response

    except Exception as exc:
        logger.exception("Analyze failed")
        raise HTTPException(status_code=500, detail=str(exc))
    
# --------------------------------------------------
# Dashboard API
# --------------------------------------------------

@app.get("/api/dashboard")
def get_dashboard():
    """
    Returns dashboard statistics generated from
    the latest processed security dataset.
    """

    try:
        return dashboard_service.get_dashboard()

    except DashboardDataError as exc:
        raise HTTPException(
            status_code=404,
            detail={
                "message": str(exc),
                "code": "NO_DASHBOARD_DATA",
            },
        )

    except Exception as exc:
        logging.getLogger(
            "local_api.dashboard"
        ).exception(
            "Dashboard generation failed"
        )

        raise HTTPException(
            status_code=500,
            detail={
                "message": "Unable to generate dashboard data",
                "error": str(exc),
            },
        )


# --------------------------------------------------
# Dataset Upload API
# --------------------------------------------------

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Accepts a CSV or JSON file, normalizes it and saves a processed copy.

    Returns a JSON response with success, message, rows_processed and filename.
    """
    logger = logging.getLogger("local_api.upload")

    start = time.perf_counter()

    logger.info("=" * 60)
    logger.info("UPLOAD STARTED")
    logger.info("Filename: %s", file.filename)

    try:
        # -------------------------
        # Read uploaded file
        # -------------------------
        content = await file.read()

        logger.info(
            "File read completed (%.2f ms)",
            (time.perf_counter() - start) * 1000,
        )

        filename = file.filename or "uploaded_dataset"

        import io
        import json as jsonlib
        import pandas as pd

        # -------------------------
        # Parse CSV / JSON
        # -------------------------
        data_input = None

        try:
            data_input = pd.read_csv(io.BytesIO(content))
        except Exception:
            try:
                parsed_json = jsonlib.loads(content.decode("utf-8-sig"))
                data_input = (
                    parsed_json
                    if isinstance(parsed_json, dict)
                    else pd.DataFrame(parsed_json)
                )
            except Exception:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "message": "Uploaded file must be valid CSV or JSON",
                        "detected_columns": [],
                        "missing_required_columns": [],
                        "supported_schemas": {},
                    },
                )

        logger.info(
            "Data loaded successfully | Rows=%d | Columns=%d | %.2f ms",
            len(data_input),
            len(data_input.columns),
            (time.perf_counter() - start) * 1000,
        )

        # -------------------------
        # Schema Detection
        # -------------------------
        from processors.factory import ProcessorFactory
        from processors.schema_detector import (
            DatasetSchemaDetector,
            DatasetSchemaError,
        )
        from processors.cve_processor import CVEProcessor

        logger.info("Starting schema detection...")

        try:
            detection = DatasetSchemaDetector.detect(data_input)
            detected_type = detection.get("dataset_type")

            logger.info(
                "Schema detected: %s (%.2f ms)",
                detected_type,
                (time.perf_counter() - start) * 1000,
            )

        except DatasetSchemaError as se:
            detail = {
                "message": se.message,
                "detected_columns": se.detected_columns,
                "missing_required_columns": se.missing_required,
                "supported_schemas": se.supported_schemas,
            }

            logger.warning(
                "Upload rejected due to schema mismatch: %s",
                detail,
            )

            raise HTTPException(
                status_code=400,
                detail=detail,
            )

        # -------------------------
        # Normalization
        # -------------------------
        logger.info("Starting normalization...")

        try:
            if detected_type == "cve" and isinstance(data_input, dict):
                normalized = CVEProcessor().normalize(data_input)

                normalized = pd.DataFrame(
                    [
                        vars(row)
                        if hasattr(row, "__dict__")
                        else row
                        for row in normalized
                    ]
                )

            else:
                processor = ProcessorFactory.create(detected_type)
                normalized = processor.normalize(data_input)

            logger.info(
                "Normalization completed | Rows=%d | Columns=%d | %.2f ms",
                len(normalized),
                len(normalized.columns),
                (time.perf_counter() - start) * 1000,
            )

        except Exception as e:
            logger.exception("Normalization failed")

            raise HTTPException(
                status_code=500,
                detail={
                    "message": f"Normalization failed: {e}",
                    "error_details": str(e),
                },
            )

        # -------------------------
        # Save Processed Dataset
        # -------------------------
        logger.info("Writing processed dataset...")

        processed_dir = (
            Path(__file__).resolve().parent.parent
            / "datasets"
            / "processed"
        )

        processed_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        out_path = (
            processed_dir
            / f"processed_{filename.rsplit('.',1)[0]}.csv"
        )

        normalized.to_csv(
            out_path,
            index=False,
        )

        logger.info(
            "CSV written successfully (%.2f ms)",
            (time.perf_counter() - start) * 1000,
        )

        # -------------------------
        # Build Response
        # -------------------------
        rows = len(normalized)

        resp = {
            "success": True,
            "message": "Dataset uploaded successfully",
            "dataset_type": detected_type,
            "rows_processed": rows,
            "filename": str(out_path.name),
        }

        logger.info(
            "Upload succeeded: %s | Rows=%d | File=%s",
            filename,
            rows,
            out_path,
        )

        logger.info(
            "Returning response (Total %.2f ms)",
            (time.perf_counter() - start) * 1000,
        )

        logger.info("=" * 60)

        return resp

    except HTTPException:
        raise

    except Exception:
        logger.exception("Upload failed")

        raise HTTPException(
            status_code=500,
            detail="Internal Server Error",
        )


# --------------------------------------------------
# Security Events API
# --------------------------------------------------

from pydantic import BaseModel  # noqa: E402


class SecurityEventRequest(BaseModel):
    event_id: str = ""
    timestamp: str = ""
    source: str = ""
    tool: str | None = None
    target: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    country: str | None = None
    attack_type: str | None = None
    severity: str | None = None
    risk_score: int | None = None
    status: str | None = None
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    description: str | None = None
    recommendation: str | None = None


@app.post("/api/events")
def save_security_event(payload: SecurityEventRequest):
    try:
        event = events_service.save_event(
            SecurityEvent(**payload.model_dump())
        )
        return {"success": True, "event": event.model_dump()}
    except Exception as exc:
        logger.exception("Failed to save security event")
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/events")
def get_security_events(limit: int = 100):
    try:
        events = events_service.get_events(limit=limit)
        return {"success": True, "events": events}
    except Exception as exc:
        logger.exception("Failed to load security events")
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/analytics")
def get_analytics():
    try:
        analytics = events_service.get_analytics()
        return {"success": True, **analytics}
    except Exception as exc:
        logger.exception("Failed to compute analytics")
        raise HTTPException(status_code=500, detail=str(exc))
