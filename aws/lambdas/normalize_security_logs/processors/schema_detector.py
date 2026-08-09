import pandas as pd
from pathlib import Path
import json


class DatasetSchemaError(Exception):
    def __init__(self, detected_columns, missing_required, supported_schemas, message="Schema mismatch"):
        super().__init__(message)
        self.detected_columns = detected_columns
        self.missing_required = missing_required
        self.supported_schemas = supported_schemas
        self.message = message


class DatasetSchemaDetector:
    """Detect dataset type from dataframe columns or JSON-like structure.

    Detection is schema-driven (column names) rather than filename-based.
    """

    @staticmethod
    def _load_windows_required():
        # Read the mapping file to determine which original columns WindowsProcessor expects
        mapping_file = (
            Path(__file__).resolve().parents[1]
            / "mappings"
            / "windows_mapping.json"
        )

        if mapping_file.exists():
            try:
                with open(mapping_file, "r", encoding="utf-8") as fh:
                    mapping = json.load(fh)
                return set(mapping.values())
            except Exception:
                return set()
        return set()

    # Define required columns for supported dataset schemas
    SUPPORTED_SCHEMAS = {
        "ids": {"Label"},
        "firewall": {"Timestamp", "Source IP", "Destination IP", "Action"},
        "windows": None,  # loaded dynamically from mappings/windows_mapping.json
        "cve": None,  # JSON-based; detection based on dict keys
    }

    @classmethod
    def supported_schema_details(cls):
        details = {}
        for name, cols in cls.SUPPORTED_SCHEMAS.items():
            if name == "windows":
                cols = cls._load_windows_required()
            if cols is None:
                cols = []
            details[name] = sorted(list(cols))
        return details

    @classmethod
    def detect(cls, data):
        """Detect dataset type.

        Args:
            data: pandas.DataFrame or dict (for JSON payloads)

        Returns:
            dict: { "dataset_type": str, "confidence": float, "detected_columns": [...]} or
            raises DatasetSchemaError when incompatible.
        """

        # JSON structure - detect CVE feed
        if isinstance(data, dict):
            if "vulnerabilities" in data:
                return {"dataset_type": "cve", "confidence": 1.0, "detected_columns": ["vulnerabilities"]}
            # unknown dict structure
            raise DatasetSchemaError(
                detected_columns=list(data.keys()),
                missing_required=[],
                supported_schemas=cls.supported_schema_details(),
                message="Unsupported JSON dataset structure",
            )

        # Expect a DataFrame
        if not isinstance(data, pd.DataFrame):
            raise DatasetSchemaError(
                detected_columns=[],
                missing_required=[],
                supported_schemas=cls.supported_schema_details(),
                message="Unsupported data type for schema detection",
            )

        # Normalize column names
        cols = [str(c).strip() for c in list(data.columns)]
        colset = set(cols)

        # Load dynamic windows required set
        windows_required = cls._load_windows_required()
        if windows_required:
            cls.SUPPORTED_SCHEMAS["windows"] = windows_required

        # Evaluate each supported schema: require full set to match
        best_match = None
        for name, required in cls.SUPPORTED_SCHEMAS.items():
            if name == "cve":
                # CVE is JSON only; skip for DataFrame inputs
                continue
            required_set = set(required) if required else set()
            if not required_set:
                continue
            present = required_set & colset
            if present == required_set:
                # exact match of required columns (may have extras) -> full confidence
                return {"dataset_type": name, "confidence": 1.0, "detected_columns": sorted(list(colset))}
            # track best partial match
            score = len(present) / len(required_set)
            if best_match is None or score > best_match[0]:
                best_match = (score, name, required_set - present)

        # No schema matched fully: reject with structured details
        detected = sorted(list(colset))
        missing_required = []
        best = None
        if best_match:
            best = {"schema": best_match[1], "missing": sorted(list(best_match[2])), "score": best_match[0]}
            missing_required = sorted(list(best_match[2]))

        raise DatasetSchemaError(
            detected_columns=detected,
            missing_required=missing_required,
            supported_schemas=cls.supported_schema_details(),
            message=f"No supported schema matched the uploaded dataset (best: {best})",
        )
