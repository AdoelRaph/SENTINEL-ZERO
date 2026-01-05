"""
Sentinel-Zero API Routes

Complete REST API for the cybersecurity platform:
- Asset management
- Vulnerability tracking
- Anomaly detection
- Network scanning
- Remediation workflows
- Threat intelligence

Copyright (c) 2024 Sentinel Security Inc.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from config import get_settings
from database.connection import db, get_db_with_org
from ml_engine.model import FeatureVector
from ml_engine.predict import AnomalyPredictor
from modules.scanner import network_scanner
from modules.intel_ingest import threat_intel
from agents.patcher import get_remediation_agent, RemediationType, RemediationRisk
from utils.logging import get_logger
from utils.validators import validate_ip, validate_cidr, ValidationError

# Avoid circular import - orchestrator will be injected
_orchestrator = None

def set_orchestrator(orch):
    """Set the orchestrator instance after main.py initializes."""
    global _orchestrator
    _orchestrator = orch

logger = get_logger(__name__)
settings = get_settings()

# Create routers
assets_router = APIRouter(prefix="/api/v1/assets", tags=["Assets"])
vulnerabilities_router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["Vulnerabilities"])
anomalies_router = APIRouter(prefix="/api/v1/anomalies", tags=["Anomalies"])
scans_router = APIRouter(prefix="/api/v1/scans", tags=["Scans"])
remediation_router = APIRouter(prefix="/api/v1/remediation", tags=["Remediation"])
intel_router = APIRouter(prefix="/api/v1/intel", tags=["Threat Intelligence"])
ml_router = APIRouter(prefix="/api/v1/ml", tags=["Machine Learning"])


# ============================================================================
# Request/Response Models
# ============================================================================

class AssetResponse(BaseModel):
    """Asset information response."""
    id: UUID
    organization_id: UUID
    hostname: Optional[str]
    ip_address: str
    mac_address: Optional[str]
    asset_type: str
    is_server: bool
    is_critical: bool
    os_family: Optional[str]
    os_version: Optional[str]
    status: str
    open_ports: list[int]
    services: list[dict[str, Any]]
    first_seen_at: datetime
    last_seen_at: datetime
    vulnerability_count: Optional[int] = 0
    anomaly_count: Optional[int] = 0


class VulnerabilityResponse(BaseModel):
    """Vulnerability information response."""
    id: UUID
    asset_id: UUID
    cve_id: str
    severity: str
    status: str
    detected_at: datetime
    affected_component: Optional[str]
    is_exploitable: Optional[bool]
    cvss_v3_score: Optional[float]
    remediation_available: bool


class AnomalyResponse(BaseModel):
    """Anomaly detection response."""
    id: UUID
    asset_id: Optional[UUID]
    anomaly_type: str
    severity: str
    confidence_score: float
    detected_at: datetime
    source_ip: Optional[str]
    destination_ip: Optional[str]
    packets_per_second: Optional[float]
    is_acknowledged: bool
    details: dict[str, Any]


class ScanRequest(BaseModel):
    """Network scan request."""
    target: str = Field(..., description="IP range in CIDR notation (e.g., 192.168.1.0/24)")
    scan_type: str = Field(default="standard", description="quick, standard, or comprehensive")


class RemediationRequest(BaseModel):
    """Remediation task creation request."""
    asset_id: UUID
    title: str
    description: Optional[str] = None
    template_name: Optional[str] = None
    custom_script: Optional[str] = None
    parameters: Optional[dict[str, Any]] = None


class PredictionRequest(BaseModel):
    """Anomaly prediction request."""
    source_ip: str
    destination_ip: str
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    avg_packet_size: float = 0.0
    tcp_ratio: float = 0.0
    udp_ratio: float = 0.0
    unique_dst_ports: int = 0
    connection_count: int = 0


# ============================================================================
# Assets API
# ============================================================================

@assets_router.get("/", response_model=list[AssetResponse])
async def list_assets(
    organization_id: UUID,
    status: Optional[str] = None,
    is_critical: Optional[bool] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
):
    """
    List all assets for an organization.

    Supports filtering by status and criticality.
    """
    async with db.raw_connection() as conn:
        query = """
            SELECT a.*,
                   COUNT(DISTINCT av.id) FILTER (WHERE av.status = 'open') as vulnerability_count,
                   COUNT(DISTINCT ad.id) FILTER (WHERE ad.is_acknowledged = FALSE) as anomaly_count
            FROM assets a
            LEFT JOIN asset_vulnerabilities av ON a.id = av.asset_id
            LEFT JOIN anomaly_detections ad ON a.id = ad.asset_id
            WHERE a.organization_id = $1
        """

        params = [organization_id]
        param_idx = 2

        if status:
            query += f" AND a.status = ${param_idx}"
            params.append(status)
            param_idx += 1

        if is_critical is not None:
            query += f" AND a.is_critical = ${param_idx}"
            params.append(is_critical)
            param_idx += 1

        query += f"""
            GROUP BY a.id
            ORDER BY a.last_seen_at DESC
            LIMIT ${param_idx} OFFSET ${param_idx + 1}
        """
        params.extend([limit, offset])

        rows = await conn.fetch(query, *params)

        return [AssetResponse(**dict(row)) for row in rows]


@assets_router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: UUID,
    organization_id: UUID,
):
    """Get detailed information about a specific asset."""
    async with db.raw_connection() as conn:
        row = await conn.fetchrow("""
            SELECT a.*,
                   COUNT(DISTINCT av.id) FILTER (WHERE av.status = 'open') as vulnerability_count,
                   COUNT(DISTINCT ad.id) FILTER (WHERE ad.is_acknowledged = FALSE) as anomaly_count
            FROM assets a
            LEFT JOIN asset_vulnerabilities av ON a.id = av.asset_id
            LEFT JOIN anomaly_detections ad ON a.id = ad.asset_id
            WHERE a.id = $1 AND a.organization_id = $2
            GROUP BY a.id
        """, asset_id, organization_id)

        if not row:
            raise HTTPException(status_code=404, detail="Asset not found")

        return AssetResponse(**dict(row))


@assets_router.patch("/{asset_id}/quarantine")
async def quarantine_asset(
    asset_id: UUID,
    organization_id: UUID,
    reason: str,
):
    """
    Quarantine an asset (mark as isolated).

    This prevents the asset from normal network operations.
    """
    async with db.raw_connection() as conn:
        await conn.execute("""
            UPDATE assets
            SET status = 'quarantined',
                quarantine_reason = $3,
                quarantine_at = NOW(),
                updated_at = NOW()
            WHERE id = $1 AND organization_id = $2
        """, asset_id, organization_id, reason)

    logger.info("Asset quarantined", asset_id=str(asset_id), reason=reason)

    return {"status": "quarantined", "asset_id": str(asset_id)}


# ============================================================================
# Vulnerabilities API
# ============================================================================

@vulnerabilities_router.get("/", response_model=list[VulnerabilityResponse])
async def list_vulnerabilities(
    organization_id: UUID,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    asset_id: Optional[UUID] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
):
    """List vulnerabilities with filtering."""
    async with db.raw_connection() as conn:
        query = """
            SELECT av.*, kt.cve_id, kt.severity, kt.cvss_v3_score,
                   EXISTS(
                       SELECT 1 FROM remediation_tasks rt
                       WHERE rt.vulnerability_id = av.id
                       AND rt.status IN ('pending_approval', 'approved', 'in_progress')
                   ) as remediation_available
            FROM asset_vulnerabilities av
            JOIN known_threats kt ON av.threat_id = kt.id
            WHERE av.organization_id = $1
        """

        params = [organization_id]
        param_idx = 2

        if status:
            query += f" AND av.status = ${param_idx}"
            params.append(status)
            param_idx += 1

        if severity:
            query += f" AND kt.severity = ${param_idx}"
            params.append(severity)
            param_idx += 1

        if asset_id:
            query += f" AND av.asset_id = ${param_idx}"
            params.append(asset_id)
            param_idx += 1

        query += f"""
            ORDER BY kt.cvss_v3_score DESC NULLS LAST, av.detected_at DESC
            LIMIT ${param_idx} OFFSET ${param_idx + 1}
        """
        params.extend([limit, offset])

        rows = await conn.fetch(query, *params)

        return [VulnerabilityResponse(**dict(row)) for row in rows]


@vulnerabilities_router.get("/stats")
async def get_vulnerability_stats(organization_id: UUID):
    """Get vulnerability statistics by severity."""
    async with db.raw_connection() as conn:
        stats = await conn.fetch("""
            SELECT kt.severity,
                   COUNT(*) as count,
                   COUNT(*) FILTER (WHERE av.is_exploitable = TRUE) as exploitable_count,
                   AVG(kt.cvss_v3_score) as avg_cvss
            FROM asset_vulnerabilities av
            JOIN known_threats kt ON av.threat_id = kt.id
            WHERE av.organization_id = $1
              AND av.status = 'open'
            GROUP BY kt.severity
            ORDER BY 
                CASE kt.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END
        """, organization_id)

        return {
            "by_severity": [dict(row) for row in stats],
            "total_open": sum(row["count"] for row in stats),
        }


@vulnerabilities_router.patch("/{vulnerability_id}/accept-risk")
async def accept_vulnerability_risk(
    vulnerability_id: UUID,
    organization_id: UUID,
    justification: str,
    accepted_by: UUID,
    expires_days: int = 90,
):
    """Accept risk for a vulnerability (won't remediate)."""
    async with db.raw_connection() as conn:
        await conn.execute("""
            UPDATE asset_vulnerabilities
            SET status = 'accepted_risk',
                accepted_at = NOW(),
                accepted_by = $3,
                acceptance_justification = $4,
                acceptance_expires_at = NOW() + ($5 || ' days')::INTERVAL,
                updated_at = NOW()
            WHERE id = $1 AND organization_id = $2
        """, vulnerability_id, organization_id, accepted_by, justification, expires_days)

    logger.info("Vulnerability risk accepted", vuln_id=str(vulnerability_id))

    return {"status": "accepted_risk", "expires_days": expires_days}


# ============================================================================
# Anomalies API
# ============================================================================

@anomalies_router.get("/", response_model=list[AnomalyResponse])
async def list_anomalies(
    organization_id: UUID,
    anomaly_type: Optional[str] = None,
    severity: Optional[str] = None,
    is_acknowledged: Optional[bool] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
):
    """List detected anomalies."""
    async with db.raw_connection() as conn:
        query = """
            SELECT id, asset_id, anomaly_type, severity, confidence_score,
                   detected_at, source_ip, destination_ip, packets_per_second,
                   is_acknowledged, 
                   jsonb_build_object(
                       'feature_vector', feature_vector,
                       'investigation_notes', investigation_notes
                   ) as details
            FROM anomaly_detections
            WHERE organization_id = $1
        """

        params = [organization_id]
        param_idx = 2

        if anomaly_type:
            query += f" AND anomaly_type = ${param_idx}"
            params.append(anomaly_type)
            param_idx += 1

        if severity:
            query += f" AND severity = ${param_idx}"
            params.append(severity)
            param_idx += 1

        if is_acknowledged is not None:
            query += f" AND is_acknowledged = ${param_idx}"
            params.append(is_acknowledged)
            param_idx += 1

        query += f"""
            ORDER BY detected_at DESC
            LIMIT ${param_idx} OFFSET ${param_idx + 1}
        """
        params.extend([limit, offset])

        rows = await conn.fetch(query, *params)

        return [AnomalyResponse(**dict(row)) for row in rows]


@anomalies_router.patch("/{anomaly_id}/acknowledge")
async def acknowledge_anomaly(
    anomaly_id: UUID,
    organization_id: UUID,
    acknowledged_by: UUID,
    notes: Optional[str] = None,
    is_false_positive: bool = False,
):
    """Acknowledge an anomaly detection."""
    async with db.raw_connection() as conn:
        await conn.execute("""
            UPDATE anomaly_detections
            SET is_acknowledged = TRUE,
                acknowledged_by = $3,
                acknowledged_at = NOW(),
                investigation_notes = $4,
                is_false_positive = $5,
                updated_at = NOW()
            WHERE id = $1 AND organization_id = $2
        """, anomaly_id, organization_id, acknowledged_by, notes, is_false_positive)

    return {"status": "acknowledged", "is_false_positive": is_false_positive}


@anomalies_router.get("/stats")
async def get_anomaly_stats(
    organization_id: UUID,
    days: int = Query(default=7, ge=1, le=90),
):
    """Get anomaly statistics over time."""
    async with db.raw_connection() as conn:
        stats = await conn.fetch("""
            SELECT anomaly_type,
                   severity,
                   COUNT(*) as count,
                   COUNT(*) FILTER (WHERE is_false_positive = TRUE) as false_positives,
                   AVG(confidence_score) as avg_confidence
            FROM anomaly_detections
            WHERE organization_id = $1
              AND detected_at > NOW() - ($2 || ' days')::INTERVAL
            GROUP BY anomaly_type, severity
            ORDER BY count DESC
        """, organization_id, days)

        # Time series data
        timeline = await conn.fetch("""
            SELECT DATE_TRUNC('hour', detected_at) as hour,
                   COUNT(*) as count,
                   AVG(confidence_score) as avg_confidence
            FROM anomaly_detections
            WHERE organization_id = $1
              AND detected_at > NOW() - ($2 || ' days')::INTERVAL
            GROUP BY hour
            ORDER BY hour DESC
        """, organization_id, days)

        return {
            "by_type_severity": [dict(row) for row in stats],
            "timeline": [dict(row) for row in timeline],
        }


# ============================================================================
# Scans API
# ============================================================================

@scans_router.post("/trigger")
async def trigger_scan(
    organization_id: UUID,
    request: ScanRequest,
):
    """Trigger an on-demand network scan."""
    try:
        # Validate CIDR
        target = validate_cidr(request.target)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Trigger scan
    result = await _orchestrator.run_manual_scan(
        organization_id=organization_id,
        target=target,
        scan_type=request.scan_type,
    )

    return result


@scans_router.get("/history")
async def get_scan_history(
    organization_id: UUID,
    limit: int = Query(default=50, le=200),
):
    """Get scan history."""
    async with db.raw_connection() as conn:
        rows = await conn.fetch("""
            SELECT id, scan_type, target_specification, status,
                   started_at, completed_at,
                   assets_discovered, assets_updated, vulnerabilities_found,
                   errors_encountered
            FROM scan_jobs
            WHERE organization_id = $1
            ORDER BY started_at DESC
            LIMIT $2
        """, organization_id, limit)

        return [dict(row) for row in rows]


@scans_router.get("/{scan_id}")
async def get_scan_details(
    scan_id: UUID,
    organization_id: UUID,
):
    """Get detailed scan results."""
    async with db.raw_connection() as conn:
        row = await conn.fetchrow("""
            SELECT *
            FROM scan_jobs
            WHERE id = $1 AND organization_id = $2
        """, scan_id, organization_id)

        if not row:
            raise HTTPException(status_code=404, detail="Scan not found")

        return dict(row)


# ============================================================================
# Remediation API
# ============================================================================

@remediation_router.post("/tasks")
async def create_remediation_task(
    organization_id: UUID,
    request: RemediationRequest,
    requested_by: UUID,
):
    """Create a new remediation task."""
    agent = get_remediation_agent(organization_id)

    # Get asset details
    async with db.raw_connection() as conn:
        asset = await conn.fetchrow("""
            SELECT ip_address, hostname
            FROM assets
            WHERE id = $1 AND organization_id = $2
        """, request.asset_id, organization_id)

        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")

    # Create task
    task = await agent.create_remediation_task(
        asset_id=request.asset_id,
        target_ip=str(asset["ip_address"]),
        remediation_type=RemediationType.CUSTOM_SCRIPT if request.custom_script else RemediationType.UPDATE_PACKAGE,
        title=request.title,
        description=request.description,
        template_name=request.template_name,
        custom_script=request.custom_script,
        parameters=request.parameters,
        requested_by=requested_by,
    )

    return {
        "task_id": str(task.task_id),
        "status": task.status,
        "risk_level": task.risk_level.value,
    }


@remediation_router.get("/tasks")
async def list_remediation_tasks(
    organization_id: UUID,
    status: Optional[str] = None,
    limit: int = Query(default=100, le=500),
):
    """List remediation tasks."""
    async with db.raw_connection() as conn:
        query = """
            SELECT rt.*,
                   a.hostname, a.ip_address
            FROM remediation_tasks rt
            JOIN assets a ON rt.asset_id = a.id
            WHERE rt.organization_id = $1
        """

        params = [organization_id]
        if status:
            query += " AND rt.status = $2"
            params.append(status)

        query += " ORDER BY rt.created_at DESC LIMIT " + str(limit)

        rows = await conn.fetch(query, *params)

        return [dict(row) for row in rows]


@remediation_router.post("/tasks/{task_id}/approve")
async def approve_remediation_task(
    task_id: UUID,
    organization_id: UUID,
    approved_by: UUID,
):
    """Approve a pending remediation task."""
    agent = get_remediation_agent(organization_id)

    try:
        fully_approved = await agent.approve_task(task_id, approved_by)

        return {
            "status": "approved" if fully_approved else "awaiting_second_approval",
            "task_id": str(task_id),
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@remediation_router.post("/tasks/{task_id}/execute")
async def execute_remediation_task(
    task_id: UUID,
    organization_id: UUID,
):
    """Execute an approved remediation task."""
    agent = get_remediation_agent(organization_id)

    try:
        result = await agent.execute_task(task_id)

        return {
            "success": result.success,
            "exit_code": result.exit_code,
            "duration_seconds": result.duration_seconds,
            "stdout": result.stdout[:500] if result.stdout else "",
            "stderr": result.stderr[:500] if result.stderr else "",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@remediation_router.get("/templates")
async def list_remediation_templates():
    """List available remediation templates."""
    from agents.patcher import RemediationAgent

    templates = []
    for name, config in RemediationAgent.TEMPLATES.items():
        templates.append({
            "name": name,
            "risk_level": config["risk"].value,
            "requires_downtime": config["requires_downtime"],
            "has_rollback": "rollback" in config,
        })

    return {"templates": templates}


# ============================================================================
# Threat Intelligence API
# ============================================================================

@intel_router.post("/sync")
async def sync_threat_intel():
    """Trigger threat intelligence synchronization."""
    results = await threat_intel.run_full_sync()
    return results


@intel_router.get("/stats")
async def get_intel_stats():
    """Get threat intelligence statistics."""
    stats = await threat_intel.get_threat_stats()
    return stats


@intel_router.get("/cves/search")
async def search_cves(
    query: str = Query(..., min_length=3),
    limit: int = Query(default=50, le=200),
):
    """Search CVE database."""
    async with db.raw_connection() as conn:
        rows = await conn.fetch("""
            SELECT cve_id, title, description, severity, cvss_v3_score,
                   is_exploited_in_wild, published_at
            FROM known_threats
            WHERE cve_id ILIKE $1
               OR title ILIKE $1
               OR description ILIKE $1
            ORDER BY cvss_v3_score DESC NULLS LAST
            LIMIT $2
        """, f"%{query}%", limit)

        return [dict(row) for row in rows]


@intel_router.get("/cves/{cve_id}")
async def get_cve_details(cve_id: str):
    """Get detailed CVE information."""
    async with db.raw_connection() as conn:
        row = await conn.fetchrow("""
            SELECT *
            FROM known_threats
            WHERE cve_id = $1
        """, cve_id.upper())

        if not row:
            raise HTTPException(status_code=404, detail="CVE not found")

        return dict(row)


# ============================================================================
# Machine Learning API
# ============================================================================

@ml_router.post("/predict")
async def predict_anomaly(
    organization_id: UUID,
    request: PredictionRequest,
):
    """
    Run anomaly prediction on network traffic features.

    Returns prediction result with anomaly type and confidence.
    """
    try:
        # Get predictor
        predictor = await _orchestrator.get_predictor(organization_id)

        # Create feature vector
        features = FeatureVector(
            source_ip=request.source_ip,
            destination_ip=request.destination_ip,
            timestamp=datetime.utcnow(),
            packets_per_second=request.packets_per_second,
            bytes_per_second=request.bytes_per_second,
            avg_packet_size=request.avg_packet_size,
            tcp_ratio=request.tcp_ratio,
            udp_ratio=request.udp_ratio,
            unique_dst_ports=request.unique_dst_ports,
            connection_count=request.connection_count,
        )

        # Run prediction
        result = await predictor.predict(features)

        return {
            "is_anomaly": result.is_anomaly,
            "anomaly_type": result.anomaly_type,
            "severity": result.severity,
            "confidence": result.confidence,
            "timestamp": result.timestamp.isoformat(),
        }

    except Exception as e:
        logger.error("Prediction failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@ml_router.get("/model/info")
async def get_model_info(organization_id: UUID):
    """Get information about the active ML model."""
    async with db.raw_connection() as conn:
        row = await conn.fetchrow("""
            SELECT model_name, model_version, training_samples,
                   false_positive_rate, training_completed_at,
                   activated_at
            FROM ml_models
            WHERE organization_id = $1
              AND is_active = TRUE
            ORDER BY activated_at DESC
            LIMIT 1
        """, organization_id)

        if not row:
            return {"status": "no_model", "message": "No trained model available"}

        return dict(row)


@ml_router.get("/predictor/stats")
async def get_predictor_stats(organization_id: UUID):
    """Get predictor statistics."""
    try:
        predictor = await orchestrator.get_predictor(organization_id)
        return predictor.get_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Export all routers
all_routers = [
    assets_router,
    vulnerabilities_router,
    anomalies_router,
    scans_router,
    remediation_router,
    intel_router,
    ml_router,
]


# ============================================================================
# Integration with main.py
# ============================================================================
# Add these lines to main.py after creating the FastAPI app:
#
# from api.routes import all_routers, set_orchestrator
#
# # Include all routers
# for router in all_routers:
#     app.include_router(router)
#
# # Inject orchestrator after initialization (inside lifespan startup)
# @asynccontextmanager
# async def lifespan(app: FastAPI):
#     await orchestrator.initialize()
#     set_orchestrator(orchestrator)  # ← Add this line
#     yield
#     await orchestrator.shutdown()
# ============================================================================