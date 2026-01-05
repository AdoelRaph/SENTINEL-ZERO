"""
Sentinel-Zero ML Engine - Real-Time Prediction Service

Provides real-time anomaly detection inference including:
- Stream processing of network features
- Detection classification (DoS, backdoor, general)
- Alert generation and storage
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

import numpy as np

from config import get_settings
from database.connection import db
from ml_engine.model import AnomalyDetectionModel, FeatureVector, get_model
from storage.r2_client import r2_storage
from utils.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


@dataclass
class DetectionResult:
    """Result from anomaly detection inference."""

    is_anomaly: bool
    anomaly_type: str  # 'dos_loop', 'backdoor_connection', 'general', 'normal'
    severity: str  # 'critical', 'high', 'medium', 'low', 'informational'
    confidence: float
    details: dict[str, Any]
    feature_vector: dict[str, float]
    timestamp: datetime


class AnomalyPredictor:
    """
    Real-time anomaly prediction service.

    Provides streaming inference with automatic model loading
    and alert generation.
    """

    # Severity thresholds
    SEVERITY_THRESHOLDS = {
        "critical": 0.9,
        "high": 0.75,
        "medium": 0.5,
        "low": 0.3,
    }

    def __init__(self, organization_id: UUID):
        self.organization_id = organization_id
        self._model: AnomalyDetectionModel | None = None
        self._model_load_time: datetime | None = None
        self._prediction_count = 0
        self._anomaly_count = 0

    async def initialize(self) -> None:
        """Initialize predictor and load model."""
        self._model = await get_model(self.organization_id)
        self._model_load_time = datetime.utcnow()

        if not self._model.is_fitted:
            logger.warning(
                "No trained model available for organization",
                organization=str(self.organization_id),
            )

    async def predict(self, features: FeatureVector) -> DetectionResult:
        """
        Perform anomaly detection on a feature vector.

        Args:
            features: Extracted network traffic features.

        Returns:
            DetectionResult with classification and confidence.
        """
        if not self._model or not self._model.is_fitted:
            raise RuntimeError("Model not initialized. Call initialize() first.")

        self._prediction_count += 1
        timestamp = datetime.utcnow()

        # Run general anomaly detection
        is_anomaly, anomaly_score = self._model.predict(features)

        # Run specific pattern detections
        is_loop, loop_score = self._model.detect_loop_pattern(features)
        is_backdoor, backdoor_score = self._model.detect_backdoor_pattern(features)

        # Determine anomaly type and overall confidence
        if is_loop and loop_score > backdoor_score:
            anomaly_type = "dos_loop"
            confidence = loop_score
            details = {
                "packets_per_second": features.packets_per_second,
                "header_repetition_score": features.header_repetition_score,
                "syn_flood_score": features.syn_flood_score,
            }
        elif is_backdoor and backdoor_score > loop_score:
            anomaly_type = "backdoor_connection"
            confidence = backdoor_score
            details = {
                "destination_ip": features.destination_ip,
                "is_allowlisted": features.dst_is_allowlisted,
                "uses_standard_port": features.uses_standard_port,
            }
        elif is_anomaly:
            anomaly_type = "general"
            confidence = anomaly_score
            details = {
                "anomaly_score": anomaly_score,
            }
        else:
            anomaly_type = "normal"
            confidence = 1 - anomaly_score
            details = {}

        # Determine severity
        severity = self._calculate_severity(confidence, anomaly_type)

        # Create result
        result = DetectionResult(
            is_anomaly=anomaly_type != "normal",
            anomaly_type=anomaly_type,
            severity=severity,
            confidence=confidence,
            details=details,
            feature_vector=self._features_to_dict(features),
            timestamp=timestamp,
        )

        # Track anomalies
        if result.is_anomaly:
            self._anomaly_count += 1

            # Store detection in database
            await self._store_detection(result, features)

        return result

    async def predict_batch(
            self,
            feature_list: list[FeatureVector],
    ) -> list[DetectionResult]:
        """
        Perform batch anomaly detection.

        More efficient for processing multiple samples.
        """
        if not self._model or not self._model.is_fitted:
            raise RuntimeError("Model not initialized. Call initialize() first.")

        # Convert to numpy array
        X = np.array([f.to_array() for f in feature_list])

        # Batch prediction
        is_anomaly_arr, scores = self._model.predict_batch(X)

        results = []
        for i, features in enumerate(feature_list):
            is_anomaly = is_anomaly_arr[i]
            anomaly_score = scores[i]

            # Individual pattern detection
            is_loop, loop_score = self._model.detect_loop_pattern(features)
            is_backdoor, backdoor_score = self._model.detect_backdoor_pattern(features)

            # Classify
            if is_loop and loop_score > backdoor_score:
                anomaly_type = "dos_loop"
                confidence = loop_score
            elif is_backdoor:
                anomaly_type = "backdoor_connection"
                confidence = backdoor_score
            elif is_anomaly:
                anomaly_type = "general"
                confidence = anomaly_score
            else:
                anomaly_type = "normal"
                confidence = 1 - anomaly_score

            severity = self._calculate_severity(confidence, anomaly_type)

            result = DetectionResult(
                is_anomaly=anomaly_type != "normal",
                anomaly_type=anomaly_type,
                severity=severity,
                confidence=confidence,
                details={},
                feature_vector=self._features_to_dict(features),
                timestamp=datetime.utcnow(),
            )

            results.append(result)

            if result.is_anomaly:
                self._anomaly_count += 1

        self._prediction_count += len(feature_list)

        # Store all detections
        anomalous_results = [
            (r, f) for r, f in zip(results, feature_list) if r.is_anomaly
        ]
        if anomalous_results:
            await self._store_detections_batch(anomalous_results)

        return results

    def _calculate_severity(self, confidence: float, anomaly_type: str) -> str:
        """Calculate severity level from confidence and type."""
        # Boost severity for specific attack types
        if anomaly_type == "dos_loop":
            confidence = min(1.0, confidence * 1.2)
        elif anomaly_type == "backdoor_connection":
            confidence = min(1.0, confidence * 1.3)

        for severity, threshold in self.SEVERITY_THRESHOLDS.items():
            if confidence >= threshold:
                return severity

        return "informational"

    def _features_to_dict(self, features: FeatureVector) -> dict[str, float]:
        """Convert feature vector to dictionary."""
        return {
            "packets_per_second": features.packets_per_second,
            "bytes_per_second": features.bytes_per_second,
            "avg_packet_size": features.avg_packet_size,
            "tcp_ratio": features.tcp_ratio,
            "udp_ratio": features.udp_ratio,
            "unique_dst_ports": features.unique_dst_ports,
            "connection_count": features.connection_count,
            "header_repetition_score": features.header_repetition_score,
            "packet_interval_std": features.packet_interval_std,
        }

    async def _store_detection(
            self,
            result: DetectionResult,
            features: FeatureVector,
    ) -> UUID:
        """Store detection in database."""
        async with db.raw_connection() as conn:
            # Look up asset
            asset_id = await conn.fetchval("""
                                           SELECT id
                                           FROM assets
                                           WHERE organization_id = $1
                                             AND ip_address = $2::inet
                                           """, self.organization_id, features.source_ip)

            detection_id = await conn.fetchval("""
                                               INSERT INTO anomaly_detections (organization_id, asset_id, anomaly_type,
                                                                               severity,
                                                                               detection_model_version,
                                                                               confidence_score,
                                                                               source_ip, destination_ip, packet_count,
                                                                               packets_per_second, feature_vector)
                                               VALUES ($1, $2, $3, $4, $5, $6, $7::inet, $8::inet, $9, $10,
                                                       $11) RETURNING id
                                               """,
                                               self.organization_id,
                                               asset_id,
                                               result.anomaly_type,
                                               result.severity,
                                               self._model.model_version if self._model else "unknown",
                                               result.confidence,
                                               features.source_ip,
                                               features.destination_ip,
                                               int(features.packets_per_second * features.flow_duration),
                                               features.packets_per_second,
                                               result.feature_vector,
                                               )

            return detection_id

    async def _store_detections_batch(
            self,
            results_and_features: list[tuple[DetectionResult, FeatureVector]],
    ) -> None:
        """Store multiple detections efficiently."""
        async with db.raw_connection() as conn:
            for result, features in results_and_features:
                asset_id = await conn.fetchval("""
                                               SELECT id
                                               FROM assets
                                               WHERE organization_id = $1
                                                 AND ip_address = $2::inet
                                               """, self.organization_id, features.source_ip)

                await conn.execute("""
                                   INSERT INTO anomaly_detections (organization_id, asset_id, anomaly_type, severity,
                                                                   detection_model_version, confidence_score,
                                                                   source_ip, destination_ip, packets_per_second,
                                                                   feature_vector)
                                   VALUES ($1, $2, $3, $4, $5, $6, $7::inet, $8::inet, $9, $10)
                                   """,
                                   self.organization_id,
                                   asset_id,
                                   result.anomaly_type,
                                   result.severity,
                                   self._model.model_version if self._model else "unknown",
                                   result.confidence,
                                   features.source_ip,
                                   features.destination_ip,
                                   features.packets_per_second,
                                   result.feature_vector,
                                   )

    async def check_allowlist(
            self,
            destination_ip: str,
            port: int | None = None,
    ) -> bool:
        """Check if destination is in organization's allowlist."""
        async with db.raw_connection() as conn:
            is_allowed = await conn.fetchval("""
                SELECT is_ip_allowed($1, $2::inet, $3, 'outbound')
            """, self.organization_id, destination_ip, port)

            return bool(is_allowed)

    def get_stats(self) -> dict[str, Any]:
        """Get predictor statistics."""
        return {
            "organization_id": str(self.organization_id),
            "prediction_count": self._prediction_count,
            "anomaly_count": self._anomaly_count,
            "anomaly_rate": (
                self._anomaly_count / self._prediction_count
                if self._prediction_count > 0 else 0
            ),
            "model_loaded_at": (
                self._model_load_time.isoformat()
                if self._model_load_time else None
            ),
            "model_version": (
                self._model.model_version
                if self._model else None
            ),
        }


# Factory function
async def create_predictor(organization_id: UUID) -> AnomalyPredictor:
    """Create and initialize an anomaly predictor."""
    predictor = AnomalyPredictor(organization_id)
    await predictor.initialize()
    return predictor