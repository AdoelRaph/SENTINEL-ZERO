"""
Sentinel-Zero ML Engine - Anomaly Detection Model

Implements an Isolation Forest-based anomaly detection system for:
- DoS/Loop pattern detection (high-frequency repetitive traffic)
- Backdoor detection (unusual outbound connections)
- Zero-day attack identification (behavioral anomalies)

Supports automatic retraining and model versioning.
"""

from __future__ import annotations

import hashlib
import io
import pickle
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from config import get_settings
from database.connection import db
from storage.r2_client import r2_storage
from utils.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


@dataclass
class TrainingMetrics:
    """Metrics from a training run."""

    model_version: str
    training_samples: int
    validation_samples: int
    training_started_at: datetime
    training_completed_at: datetime
    validation_accuracy: float | None = None
    false_positive_rate: float | None = None
    false_negative_rate: float | None = None
    auc_score: float | None = None
    hyperparameters: dict[str, Any] = field(default_factory=dict)
    feature_columns: list[str] = field(default_factory=list)


@dataclass
class FeatureVector:
    """Extracted features from network traffic data."""

    source_ip: str
    destination_ip: str
    timestamp: datetime

    # Traffic volume features
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    avg_packet_size: float = 0.0

    # Protocol distribution
    tcp_ratio: float = 0.0
    udp_ratio: float = 0.0
    icmp_ratio: float = 0.0

    # Port features
    unique_dst_ports: int = 0
    unique_src_ports: int = 0
    high_port_ratio: float = 0.0

    # Connection patterns
    connection_count: int = 0
    failed_connection_ratio: float = 0.0
    syn_flood_score: float = 0.0

    # Flow characteristics
    flow_duration: float = 0.0
    flow_idle_time: float = 0.0
    bidirectional_ratio: float = 0.0

    # Payload features
    payload_entropy: float = 0.0
    avg_payload_size: float = 0.0

    # Loop detection specific
    header_repetition_score: float = 0.0
    packet_interval_std: float = 0.0

    # Backdoor detection specific
    is_outbound: bool = False
    dst_is_allowlisted: bool = False
    uses_standard_port: bool = True

    # Memory forensics features
    mem_pslist_nproc: int = 0
    mem_dlllist_ndlls: int = 0
    mem_handles_nhandles: int = 0
    mem_malfind_ninjections: int = 0
    mem_ldrmodules_not_in_load: int = 0

    def to_array(self) -> np.ndarray:
        """Convert to numpy array for model input."""
        return np.array([
            self.packets_per_second,
            self.bytes_per_second,
            self.avg_packet_size,
            self.tcp_ratio,
            self.udp_ratio,
            self.icmp_ratio,
            self.unique_dst_ports,
            self.unique_src_ports,
            self.high_port_ratio,
            self.connection_count,
            self.failed_connection_ratio,
            self.syn_flood_score,
            self.flow_duration,
            self.flow_idle_time,
            self.bidirectional_ratio,
            self.payload_entropy,
            self.avg_payload_size,
            self.header_repetition_score,
            self.packet_interval_std,
            float(self.is_outbound),
            float(not self.dst_is_allowlisted),
            float(not self.uses_standard_port),
        ])


class AnomalyDetectionModel:
    """
    Isolation Forest-based anomaly detection model.

    Designed for detecting:
    1. DoS/Loop patterns - High packet rates with repetitive headers
    2. Backdoors - Unusual outbound connections to non-allowlisted IPs
    3. General anomalies - Behavioral deviations from baseline
    """

    FEATURE_COLUMNS = [
        # Network Features (1-22)
        "packets_per_second",
        "bytes_per_second",
        "avg_packet_size",
        "tcp_ratio",
        "udp_ratio",
        "icmp_ratio",
        "unique_dst_ports",
        "unique_src_ports",
        "high_port_ratio",
        "connection_count",
        "failed_connection_ratio",
        "syn_flood_score",
        "flow_duration",
        "flow_idle_time",
        "bidirectional_ratio",
        "payload_entropy",
        "avg_payload_size",
        "header_repetition_score",
        "packet_interval_std",
        "is_outbound",
        "is_non_allowlisted",
        "uses_non_standard_port",

        # Memory Features (23-27) - NOW INCLUDED!
        "mem_pslist_nproc",
        "mem_dlllist_ndlls",
        "mem_handles_nhandles",
        "mem_malfind_ninjections",
        "mem_ldrmodules_not_in_load",
    ]

    def __init__(
            self,
            organization_id: UUID | None = None,
            model_version: str | None = None,
    ):
        self.organization_id = organization_id
        self.model_version = model_version or settings.ml.model_version

        self._model: IsolationForest | None = None
        self._scaler: StandardScaler | None = None
        self._is_fitted = False
        self._training_metrics: TrainingMetrics | None = None

    async def load(self) -> bool:
        """
        Load model from R2 storage.

        Returns:
            True if model was loaded successfully.
        """
        try:
            model_data = await r2_storage.load_ml_model(
                organization_id=self.organization_id,
                model_name="anomaly_detection",
                model_version=self.model_version,
            )

            model_bundle = pickle.loads(model_data)

            self._model = model_bundle["model"]
            self._scaler = model_bundle["scaler"]
            self._is_fitted = True
            self._training_metrics = model_bundle.get("metrics")

            logger.info(
                "Loaded anomaly detection model",
                version=self.model_version,
                organization=str(self.organization_id) if self.organization_id else "global",
            )

            return True

        except Exception as e:
            logger.warning(
                "Failed to load model, will need training",
                error=str(e),
            )
            return False

    async def train(
            self,
            training_data: pd.DataFrame | None = None,
            validation_split: float = 0.2,
    ) -> TrainingMetrics:
        """
        Train the anomaly detection model.

        Args:
            training_data: DataFrame with feature columns. If None, fetches from R2.
            validation_split: Fraction of data to use for validation.

        Returns:
            Training metrics and performance statistics.
        """
        training_start = datetime.utcnow()

        logger.info(
            "Starting model training",
            organization=str(self.organization_id) if self.organization_id else "global",
        )

        # Load training data if not provided
        if training_data is None:
            training_data = await self._load_training_data()

        if len(training_data) < settings.ml.min_training_samples:
            raise ValueError(
                f"Insufficient training data: {len(training_data)} samples "
                f"(minimum: {settings.ml.min_training_samples})"
            )

        # Prepare features
        X = training_data[self.FEATURE_COLUMNS].values

        # Split into training and validation
        split_idx = int(len(X) * (1 - validation_split))
        X_train = X[:split_idx]
        X_val = X[split_idx:]

        # Fit scaler on training data
        self._scaler = StandardScaler()
        X_train_scaled = self._scaler.fit_transform(X_train)
        X_val_scaled = self._scaler.transform(X_val)

        # Initialize and train Isolation Forest
        self._model = IsolationForest(
            n_estimators=settings.ml.n_estimators,
            contamination=settings.ml.contamination,
            max_samples=min(settings.ml.max_samples, len(X_train)),
            random_state=42,
            n_jobs=-1,
            warm_start=False,
        )

        self._model.fit(X_train_scaled)
        self._is_fitted = True

        # Evaluate on validation set
        val_predictions = self._model.predict(X_val_scaled)
        val_scores = self._model.decision_function(X_val_scaled)

        # Calculate metrics (assuming clean data, so anomalies are false positives)
        anomaly_count = np.sum(val_predictions == -1)
        fpr = anomaly_count / len(val_predictions)

        training_completed = datetime.utcnow()

        # Create metrics
        self._training_metrics = TrainingMetrics(
            model_version=self.model_version,
            training_samples=len(X_train),
            validation_samples=len(X_val),
            training_started_at=training_start,
            training_completed_at=training_completed,
            false_positive_rate=float(fpr),
            hyperparameters={
                "n_estimators": settings.ml.n_estimators,
                "contamination": settings.ml.contamination,
                "max_samples": settings.ml.max_samples,
            },
            feature_columns=self.FEATURE_COLUMNS,
        )

        # Save model to R2
        await self._save_model()

        # Register model in database
        await self._register_model()

        logger.info(
            "Model training completed",
            version=self.model_version,
            training_samples=len(X_train),
            training_duration_seconds=(training_completed - training_start).total_seconds(),
            false_positive_rate=fpr,
        )

        return self._training_metrics

    async def _load_training_data(self) -> pd.DataFrame:
        """
        Load training data from R2 storage.

        Fetches network traffic feature files from the past training period.
        """
        # List available training data files
        prefix = f"training-data/{self.organization_id or 'global'}/"
        objects = await r2_storage.list_objects(prefix, max_keys=100)

        if not objects:
            raise ValueError("No training data available in R2 storage")

        # Load and concatenate data files
        dataframes = []

        for obj in objects:
            try:
                data = await r2_storage.download_file(obj["key"])
                df = pd.read_parquet(io.BytesIO(data))
                dataframes.append(df)
            except Exception as e:
                logger.warning(
                    "Failed to load training file",
                    key=obj["key"],
                    error=str(e),
                )

        if not dataframes:
            raise ValueError("Could not load any training data files")

        combined = pd.concat(dataframes, ignore_index=True)

        logger.info(
            "Loaded training data",
            files=len(dataframes),
            samples=len(combined),
        )

        return combined

    async def _save_model(self) -> dict[str, Any]:
        """Save model to R2 storage."""
        model_bundle = {
            "model": self._model,
            "scaler": self._scaler,
            "metrics": self._training_metrics,
            "created_at": datetime.utcnow().isoformat(),
            "feature_columns": self.FEATURE_COLUMNS,
        }

        model_bytes = pickle.dumps(model_bundle)

        result = await r2_storage.store_ml_model(
            organization_id=self.organization_id,
            model_name="anomaly_detection",
            model_version=self.model_version,
            model_data=model_bytes,
            metadata={
                "training-samples": str(self._training_metrics.training_samples),
                "fpr": str(self._training_metrics.false_positive_rate),
            },
        )

        return result

    async def _register_model(self) -> None:
        """Register trained model in database."""
        async with db.raw_connection() as conn:
            # Deactivate previous models
            await conn.execute("""
                               UPDATE ml_models
                               SET is_active      = FALSE,
                                   deactivated_at = NOW()
                               WHERE organization_id = $1
                                 AND model_name = 'anomaly_detection'
                                 AND is_active = TRUE
                               """, self.organization_id)

            # Insert new model record
            model_bytes = pickle.dumps({
                "model": self._model,
                "scaler": self._scaler,
            })
            checksum = hashlib.sha256(model_bytes).hexdigest()

            await conn.execute("""
                               INSERT INTO ml_models (organization_id, model_name, model_version, model_type,
                                                      r2_model_key, file_size_bytes, checksum_sha256,
                                                      training_samples, false_positive_rate,
                                                      training_started_at, training_completed_at,
                                                      training_duration_seconds, hyperparameters, feature_columns,
                                                      is_active, activated_at)
                               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, TRUE, NOW())
                               """,
                               self.organization_id,
                               "anomaly_detection",
                               self.model_version,
                               "isolation_forest",
                               f"ml-models/{self.organization_id or 'global'}/anomaly_detection/v{self.model_version}/model.pkl",
                               len(model_bytes),
                               checksum,
                               self._training_metrics.training_samples,
                               self._training_metrics.false_positive_rate,
                               self._training_metrics.training_started_at,
                               self._training_metrics.training_completed_at,
                               int((self._training_metrics.training_completed_at -
                                    self._training_metrics.training_started_at).total_seconds()),
                               self._training_metrics.hyperparameters,
                               self._training_metrics.feature_columns,
                               )

    def predict(self, features: FeatureVector | np.ndarray) -> tuple[bool, float]:
        """
        Predict if a sample is anomalous.

        Args:
            features: Feature vector or numpy array.

        Returns:
            Tuple of (is_anomaly, anomaly_score).
        """
        if not self._is_fitted:
            raise RuntimeError("Model not fitted. Call load() or train() first.")

        if isinstance(features, FeatureVector):
            X = features.to_array().reshape(1, -1)
        else:
            X = features.reshape(1, -1) if features.ndim == 1 else features

        # Scale features
        X_scaled = self._scaler.transform(X)

        # Get prediction and score
        prediction = self._model.predict(X_scaled)[0]
        score = self._model.decision_function(X_scaled)[0]

        # Convert to boolean (1 = normal, -1 = anomaly)
        is_anomaly = prediction == -1

        # Normalize score to 0-1 range (lower score = more anomalous)
        # Decision function returns values roughly in [-0.5, 0.5]
        normalized_score = max(0, min(1, (score + 0.5)))
        anomaly_score = 1 - normalized_score

        return is_anomaly, float(anomaly_score)

    def predict_batch(
            self,
            features: np.ndarray,
    ) -> tuple[np.ndarray, np.ndarray]:
        """
        Predict anomalies for a batch of samples.

        Args:
            features: 2D numpy array of feature vectors.

        Returns:
            Tuple of (is_anomaly array, anomaly_scores array).
        """
        if not self._is_fitted:
            raise RuntimeError("Model not fitted. Call load() or train() first.")

        X_scaled = self._scaler.transform(features)

        predictions = self._model.predict(X_scaled)
        scores = self._model.decision_function(X_scaled)

        is_anomaly = predictions == -1
        normalized_scores = np.clip((scores + 0.5), 0, 1)
        anomaly_scores = 1 - normalized_scores

        return is_anomaly, anomaly_scores

    def detect_loop_pattern(self, features: FeatureVector) -> tuple[bool, float]:
        """
        Specific detection for DoS/routing loop patterns.

        Identifies high-frequency repetitive traffic that indicates:
        - SYN flood attacks
        - Routing loops
        - Amplification attacks
        """
        loop_score = 0.0

        # High packet rate is primary indicator
        if features.packets_per_second > settings.ml.loop_packet_threshold:
            loop_score += 0.4

        # Header repetition indicates loop
        if features.header_repetition_score > 0.7:
            loop_score += 0.3

        # Low packet interval variance indicates automated traffic
        if features.packet_interval_std < 0.001:
            loop_score += 0.2

        # SYN flood detection
        if features.syn_flood_score > 0.5:
            loop_score += 0.3

        # High connection count with failures
        if features.connection_count > 100 and features.failed_connection_ratio > 0.8:
            loop_score += 0.2

        loop_score = min(1.0, loop_score)
        is_loop = loop_score > 0.5

        return is_loop, loop_score

    def detect_backdoor_pattern(
            self,
            features: FeatureVector,
    ) -> tuple[bool, float]:
        """
        Specific detection for backdoor/C2 communication patterns.

        Identifies potential backdoors based on:
        - Outbound connections to non-allowlisted IPs
        - Non-standard port usage
        - Regular beacon patterns
        """
        backdoor_score = 0.0

        # Outbound to non-allowlisted destination
        if features.is_outbound and not features.dst_is_allowlisted:
            backdoor_score += 0.4

        # Using non-standard port
        if not features.uses_standard_port:
            backdoor_score += 0.2

        # Regular intervals suggest beacon
        if 0.01 < features.packet_interval_std < 0.1:
            backdoor_score += 0.2

        # Low payload entropy might indicate encoded commands
        if features.payload_entropy < 3.0:
            backdoor_score += 0.1

        # High port usage
        if features.high_port_ratio > 0.8:
            backdoor_score += 0.1

        backdoor_score = min(1.0, backdoor_score)
        is_backdoor = backdoor_score > 0.4

        return is_backdoor, backdoor_score

    @property
    def is_fitted(self) -> bool:
        """Check if model is ready for predictions."""
        return self._is_fitted

    @property
    def training_metrics(self) -> TrainingMetrics | None:
        """Get training metrics if available."""
        return self._training_metrics


class ModelTrainingPipeline:
    """
    Automated model training pipeline.

    Handles scheduled retraining based on:
    - Time intervals (weekly by default)
    - Data drift detection
    - Performance degradation
    """

    def __init__(self, organization_id: UUID | None = None):
        self.organization_id = organization_id

    async def should_retrain(self) -> tuple[bool, str]:
        """
        Determine if model retraining is needed.

        Returns:
            Tuple of (should_retrain, reason).
        """
        async with db.raw_connection() as conn:
            # Check last training time
            last_training = await conn.fetchval("""
                                                SELECT training_completed_at
                                                FROM ml_models
                                                WHERE organization_id = $1
                                                  AND model_name = 'anomaly_detection'
                                                  AND is_active = TRUE
                                                """, self.organization_id)

            if last_training is None:
                return True, "no_existing_model"

            days_since_training = (datetime.utcnow() - last_training).days

            if days_since_training >= settings.ml.retrain_interval_days:
                return True, f"scheduled_interval ({days_since_training} days)"

            # Check false positive rate trend
            recent_detections = await conn.fetchval("""
                                                    SELECT COUNT(*)
                                                    FROM anomaly_detections
                                                    WHERE organization_id = $1
                                                      AND created_at > NOW() - INTERVAL '7 days'
                                                      AND is_false_positive = TRUE
                                                    """, self.organization_id)

            total_detections = await conn.fetchval("""
                                                   SELECT COUNT(*)
                                                   FROM anomaly_detections
                                                   WHERE organization_id = $1
                                                     AND created_at > NOW() - INTERVAL '7 days'
                                                   """, self.organization_id)

            if total_detections > 100:
                fp_rate = recent_detections / total_detections
                if fp_rate > 0.3:  # 30% false positive rate
                    return True, f"high_false_positive_rate ({fp_rate:.2%})"

        return False, "not_needed"

    async def run_if_needed(self) -> TrainingMetrics | None:
        """Run training pipeline if needed."""
        should_train, reason = await self.should_retrain()

        if not should_train:
            logger.info("Model retraining not needed", reason=reason)
            return None

        logger.info("Starting model retraining", reason=reason)

        # Generate new version
        new_version = datetime.utcnow().strftime("%Y%m%d.%H%M%S")

        model = AnomalyDetectionModel(
            organization_id=self.organization_id,
            model_version=new_version,
        )

        metrics = await model.train()

        return metrics


# Factory function for model access
async def get_model(
        organization_id: UUID | None = None,
) -> AnomalyDetectionModel:
    """
    Get or create an anomaly detection model.

    Loads from R2 if available, otherwise returns uninitialized model.
    """
    model = AnomalyDetectionModel(organization_id=organization_id)
    await model.load()
    return model