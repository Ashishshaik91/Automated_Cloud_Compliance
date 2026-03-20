"""
AI/ML Anomaly Detection Module.
Uses Isolation Forest for unsupervised anomaly detection in compliance metrics.
Reduces false positives via statistical baselines.
"""

from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import structlog
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

logger = structlog.get_logger(__name__)

MODEL_DIR = Path(__file__).parent / "models"
MODEL_DIR.mkdir(exist_ok=True)

MODEL_PATH = MODEL_DIR / "isolation_forest.joblib"
SCALER_PATH = MODEL_DIR / "scaler.joblib"


class AnomalyDetector:
    """
    Isolation Forest-based anomaly detector for compliance metrics.
    Detects unusual patterns in compliance scores, check failure rates,
    and resource configuration drift.
    """

    def __init__(self, contamination: float = 0.05) -> None:
        self.contamination = contamination
        self._model: IsolationForest | None = None
        self._scaler: StandardScaler | None = None
        self._is_trained = False

    def _load_or_init(self) -> None:
        """Load persisted model or initialize a new one."""
        if MODEL_PATH.exists() and SCALER_PATH.exists():
            try:
                self._model = joblib.load(MODEL_PATH)
                self._scaler = joblib.load(SCALER_PATH)
                self._is_trained = True
                logger.info("Anomaly detection model loaded from disk")
                return
            except Exception as e:
                logger.warning("Failed to load model, reinitializing", error=str(e))

        self._model = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        )
        self._scaler = StandardScaler()
        self._is_trained = False

    def fit(self, training_data: list[dict[str, Any]]) -> None:
        """Train the anomaly detection model on historical compliance data."""
        if not training_data:
            logger.warning("No training data provided")
            return

        self._load_or_init()
        df = self._extract_features(training_data)
        if df.empty:
            return

        X = self._scaler.fit_transform(df.values)  # type: ignore[union-attr]
        self._model.fit(X)  # type: ignore[union-attr]
        self._is_trained = True

        # Persist the trained model
        joblib.dump(self._model, MODEL_PATH)
        joblib.dump(self._scaler, SCALER_PATH)
        logger.info("Anomaly detection model trained and saved", samples=len(df))

    def predict(self, data_points: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Predict anomalies in the given data points.
        Returns enriched dicts with 'is_anomaly' and 'anomaly_score' fields.
        """
        if not self._is_trained:
            self._load_or_init()
            if not self._is_trained:
                # Return all as normal if model not trained yet
                return [{**d, "is_anomaly": False, "anomaly_score": 0.0} for d in data_points]

        df = self._extract_features(data_points)
        if df.empty:
            return data_points

        X = self._scaler.transform(df.values)  # type: ignore[union-attr]
        predictions = self._model.predict(X)  # type: ignore[union-attr]
        scores = self._model.score_samples(X)  # type: ignore[union-attr]

        results = []
        for i, point in enumerate(data_points):
            results.append({
                **point,
                "is_anomaly": bool(predictions[i] == -1),
                "anomaly_score": float(scores[i]),
            })
        return results

    def _extract_features(self, data: list[dict[str, Any]]) -> pd.DataFrame:
        """Extract numerical features from compliance metrics dicts."""
        feature_keys = [
            "compliance_score",
            "total_checks",
            "failed_checks",
            "passed_checks",
            "critical_count",
            "high_count",
        ]
        rows = []
        for d in data:
            row = {}
            for k in feature_keys:
                row[k] = float(d.get(k, 0))
            rows.append(row)

        if not rows:
            return pd.DataFrame()

        df = pd.DataFrame(rows, columns=feature_keys)
        # Fill NaN with 0
        df = df.fillna(0)
        return df

    def get_baseline_stats(self, data: list[dict[str, Any]]) -> dict[str, Any]:
        """Return basic statistical baseline for false positive reduction."""
        if not data:
            return {}
        df = self._extract_features(data)
        return {
            "mean": df.mean().to_dict(),
            "std": df.std().to_dict(),
            "min": df.min().to_dict(),
            "max": df.max().to_dict(),
        }
