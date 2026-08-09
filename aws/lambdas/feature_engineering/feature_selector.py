"""
Feature Selector

Combines all engineered features into a
single ML-ready feature vector.

Responsibilities
----------------
- Merge feature groups
- Validate required ML features
- Maintain feature ordering
- Generate feature vector
- Export feature names

Author:
AI Threat Detection Dashboard
"""

from __future__ import annotations

from typing import Dict, List
import json
from pathlib import Path

from .constants import FEATURE_COLUMNS
# ---------------------------------------------------------
# Feature Selector
# ---------------------------------------------------------

class FeatureSelector:

    """
    Produces the final ordered feature vector
    for training and inference.
    """

    def __init__(self):

        # Prefer an active_features.json next to deployed models if present.
        # This allows inference to use the exact feature ordering the model
        # was trained with (avoids feature-count mismatch).
        try:
            models_active = (
                Path(__file__).resolve().parent.parent
                / "ml_engine"
                / "models"
                / "active_features.json"
            )
            if models_active.exists():
                payload = json.loads(models_active.read_text())
                names = payload.get("feature_names")
                if names and isinstance(names, list):
                    self.feature_order = names.copy()
                else:
                    self.feature_order = FEATURE_COLUMNS.copy()
            else:
                # Try the training saved_models copy as a fallback (common in dev).
                training_active = (
                    Path(__file__).resolve().parent.parent
                    / "ml_engine"
                    / "training"
                    / "saved_models"
                    / "active_features.json"
                )
                if training_active.exists():
                    payload = json.loads(training_active.read_text())
                    names = payload.get("feature_names")
                    if names and isinstance(names, list):
                        self.feature_order = names.copy()
                    else:
                        self.feature_order = FEATURE_COLUMNS.copy()
                else:
                    self.feature_order = FEATURE_COLUMNS.copy()
        except Exception:
            # On any failure fall back to the canonical FEATURE_COLUMNS
            self.feature_order = FEATURE_COLUMNS.copy()

    # -----------------------------------------------------
    # Merge Dictionaries
    # -----------------------------------------------------

    def merge_features(

        self,

        *feature_groups: Dict,

    ) -> Dict:

        merged = {}

        for group in feature_groups:

            if not group:

                continue

            merged.update(group)

        return merged
    # -----------------------------------------------------
    # Validate Feature Set
    # -----------------------------------------------------

    def validate(

        self,

        features: Dict,

    ) -> None:

        missing = [

            feature

            for feature in self.feature_order

            if feature not in features

        ]

        if missing:

            raise ValueError(

                "Missing engineered features: "

                + ", ".join(missing)

            )
    # -----------------------------------------------------
    # Ordered Feature Dictionary
    # -----------------------------------------------------

    def ordered_dict(

        self,

        features: Dict,

    ) -> Dict:

        self.validate(

            features

        )

        return {

            feature: features[feature]

            for feature in self.feature_order

        }
    # -----------------------------------------------------
    # Feature Vector
    # -----------------------------------------------------

    def feature_vector(
        self,
        features: Dict,
    ) -> List[float]:

        ordered = self.ordered_dict(

            features

        )

        return [

            ordered[column]

            for column in self.feature_order

        ]

    # -----------------------------------------------------
    # Batch Feature Vectors
    # -----------------------------------------------------

    def batch_feature_vectors(
        self,
        feature_sets: List[Dict],
    ) -> List[List[float]]:

        vectors = []

        for features in feature_sets:

            vectors.append(

                self.feature_vector(

                    features

                )

            )

        return vectors

    # -----------------------------------------------------
    # Feature Names
    # -----------------------------------------------------

    def feature_names(
        self,
    ) -> List[str]:

        return self.feature_order.copy()

    # -----------------------------------------------------
    # Number of Features
    # -----------------------------------------------------

    def feature_count(
        self,
    ) -> int:

        return len(

            self.feature_order

        )
    # -----------------------------------------------------
    # Pandas DataFrame
    # -----------------------------------------------------

    def dataframe(
        self,
        feature_sets: List[Dict],
    ):

        try:

            import pandas as pd

        except ImportError as exc:

            raise ImportError(

                "pandas is required."

            ) from exc

        ordered_rows = [

            self.ordered_dict(

                features

            )

            for features in feature_sets

        ]

        return pd.DataFrame(

            ordered_rows,

            columns=self.feature_order,

        )

    # -----------------------------------------------------
    # Export Schema
    # -----------------------------------------------------

    def schema(
        self,
    ) -> Dict:

        return {

            "feature_count": self.feature_count(),

            "feature_names": self.feature_names(),

        }
# ---------------------------------------------------------
# Singleton
# ---------------------------------------------------------

_selector = FeatureSelector()


def merge_features(
    *feature_groups: Dict,
) -> Dict:

    return _selector.merge_features(

        *feature_groups

    )


def feature_vector(
    features: Dict,
) -> List[float]:

    return _selector.feature_vector(

        features

    )


def batch_feature_vectors(
    feature_sets: List[Dict],
):

    return _selector.batch_feature_vectors(

        feature_sets

    )


def feature_dataframe(
    feature_sets: List[Dict],
):

    return _selector.dataframe(

        feature_sets

    )


def feature_schema():

    return _selector.schema()


# ---------------------------------------------------------
# Local Testing
# ---------------------------------------------------------

if __name__ == "__main__":

    from pprint import pprint

    sample = {

        column: 1

        for column in FEATURE_COLUMNS

    }

    pprint(

        feature_vector(

            sample

        )

    )

    pprint(

        feature_schema()

    )
    
