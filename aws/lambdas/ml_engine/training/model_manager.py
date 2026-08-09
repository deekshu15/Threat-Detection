"""Model persistence helpers for the training pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

import joblib


@dataclass(frozen=True, slots=True)
class ModelArtifact:
    """Metadata describing a persisted model artifact."""

    name: str
    path: str
    version: str
    created_at: str
    feature_count: int


class ModelCompatibilityError(RuntimeError):
    """Raised when an artifact does not match the expected contract."""


class ModelManager:
    """Persist and validate models, encoders, feature lists, and metadata."""

    def __init__(
        self,
        model_dir: Path,
        production_model_dir: Path,
    ) -> None:
        self.model_dir = Path(model_dir)
        self.production_model_dir = Path(production_model_dir)
        self.version_dir = self.model_dir / "versions"
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.production_model_dir.mkdir(parents=True, exist_ok=True)
        self.version_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _timestamp_version() -> str:
        return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    @staticmethod
    def _dump_json(path: Path, payload: Dict[str, Any]) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
        return path

    def save_model(
        self,
        model: Any,
        filename: str = "best_model.pkl",
        metadata: Optional[Dict[str, Any]] = None,
        promote_to_production: bool = False,
    ) -> ModelArtifact:
        """Persist a model to the training directory and optionally promote it."""

        version = self._timestamp_version()
        artifact_path = self.model_dir / filename
        joblib.dump(model, artifact_path)

        version_path = self.version_dir / version / filename
        version_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(artifact_path, version_path)

        if promote_to_production:
            shutil.copy2(artifact_path, self.production_model_dir / filename)

        if metadata is not None:
            self.save_metadata(metadata)

        feature_count = int(metadata.get("feature_count", 0)) if metadata else 0
        self._dump_json(
            self.version_dir / version / "artifact.json",
            asdict(
                ModelArtifact(
                    name=filename,
                    path=str(artifact_path),
                    version=version,
                    created_at=datetime.now(timezone.utc).isoformat(),
                    feature_count=feature_count,
                )
            ),
        )

        return ModelArtifact(
            name=filename,
            path=str(artifact_path),
            version=version,
            created_at=datetime.now(timezone.utc).isoformat(),
            feature_count=feature_count,
        )

    def save_metadata(self, metadata: Dict[str, Any], filename: str = "metadata.json") -> Path:
        return self._dump_json(self.model_dir / filename, metadata)

    def save_active_features(self, active_features: Iterable[str], filename: str = "active_features.json") -> Path:
        payload = {"feature_names": list(active_features)}
        return self._dump_json(self.model_dir / filename, payload)

    def save_label_encoder(self, encoder: Any, filename: str = "label_encoder.pkl", promote_to_production: bool = True) -> Path:
        path = self.model_dir / filename
        joblib.dump(encoder, path)
        if promote_to_production:
            shutil.copy2(path, self.production_model_dir / filename)
        return path

    def version_model(self, filename: str = "best_model.pkl") -> Path:
        source = self.model_dir / filename
        if not source.exists():
            raise FileNotFoundError(f"Model file not found: {source}")
        version = self._timestamp_version()
        destination = self.version_dir / version / filename
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        return destination

    def validate_compatibility(
        self,
        model: Any,
        expected_features: Optional[Iterable[str]] = None,
    ) -> None:
        if not hasattr(model, "predict"):
            raise ModelCompatibilityError("Loaded artifact does not expose predict().")
        if not hasattr(model, "predict_proba"):
            raise ModelCompatibilityError("Loaded artifact must expose predict_proba().")

        if expected_features is not None:
            expected = list(expected_features)
            if not expected:
                raise ModelCompatibilityError("Expected feature list is empty.")

            active_feature_file = self.model_dir / "active_features.json"
            if active_feature_file.exists():
                with active_feature_file.open("r", encoding="utf-8") as handle:
                    payload = json.load(handle)
                persisted = list(payload.get("feature_names", []))
                if persisted and persisted != expected:
                    raise ModelCompatibilityError(
                        "Expected features do not match persisted active features."
                    )

    def load_model(
        self,
        filename: str = "best_model.pkl",
        expected_features: Optional[Iterable[str]] = None,
    ) -> Any:
        path = self.model_dir / filename
        if not path.exists():
            path = self.production_model_dir / filename
        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {path}")

        model = joblib.load(path)
        self.validate_compatibility(model, expected_features=expected_features)
        return model

