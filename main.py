"""
Sentinel-Zero Main Orchestrator

Central control loop for the autonomous cybersecurity platform.
Coordinates all subsystems:
- Threat Intelligence Ingestion
- Network Scanning and Discovery
- ML-based Anomaly Detection
- Automated Remediation

Runs as an async service with scheduled tasks and real-time monitoring.
"""

from __future__ import annotations

import asyncio
import signal
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any
from uuid import UUID

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware

from config import get_settings
from database.connection import db
from modules.intel_ingest import threat_intel
from modules.scanner import network_scanner
from ml_engine.model import ModelTrainingPipeline
from ml_engine.predict import create_predictor, AnomalyPredictor
from agents.patcher import get_remediation_agent
from storage.r2_client import r2_storage
from utils.logging import get_logger, configure_logging

logger = get_logger(__name__)
settings = get_settings()


class SentinelZeroOrchestrator:
    """
    Main orchestrator for Sentinel-Zero platform.

    Manages the lifecycle of all subsystems and coordinates
    the Scan -> Analyze -> Fix -> Report workflow.
    """

    def __init__(self):
        self._scheduler = AsyncIOScheduler()
        self._is_running = False
        self._active_predictors: dict[UUID, AnomalyPredictor] = {}
        self._scan_in_progress = False
        self._shutdown_event = asyncio.Event()

    async def initialize(self) -> None:
        """Initialize all subsystems."""
        logger.info(
            "Initializing Sentinel-Zero",
            version=settings.app_version,
            environment=settings.environment,
        )

        # Configure logging
        configure_logging()

        # Initialize database connection
        await db.initialize()

        # Initialize threat intelligence
        await threat_intel.initialize()

        # Verify R2 connection
        r2_health = await r2_storage.health_check()
        if r2_health["status"] != "healthy":
            logger.error("R2 storage unhealthy", **r2_health)
            raise RuntimeError("R2 storage connection failed")

        # Setup scheduled tasks
        self._setup_scheduled_tasks()

        logger.info("Sentinel-Zero initialization complete")

    async def shutdown(self) -> None:
        """Gracefully shutdown all subsystems."""
        logger.info("Shutting down Sentinel-Zero")

        self._is_running = False
        self._shutdown_event.set()

        # Stop scheduler
        if self._scheduler.running:
            self._scheduler.shutdown(wait=True)

        # Cleanup threat intel
        await threat_intel.shutdown()

        # Close database connections
        await db.shutdown()

        logger.info("Sentinel-Zero shutdown complete")

    def _setup_scheduled_tasks(self) -> None:
        """Configure scheduled background tasks."""

        # Threat intelligence sync - every 6 hours
        self._scheduler.add_job(
            self._sync_threat_intel,
            trigger=IntervalTrigger(hours=settings.threat_intel.nvd_poll_interval_hours),
            id="threat_intel_sync",
            name="Threat Intelligence Sync",
            max_instances=1,
            replace_existing=True,
        )

        # Network scan - daily at 2 AM
        self._scheduler.add_job(
            self._run_scheduled_scan,
            trigger=CronTrigger(hour=2, minute=0),
            id="daily_network_scan",
            name="Daily Network Scan",
            max_instances=1,
            replace_existing=True,
        )

        # ML model retraining - weekly on Sunday at 3 AM
        self._scheduler.add_job(
            self._retrain_ml_models,
            trigger=CronTrigger(day_of_week="sun", hour=3, minute=0),
            id="weekly_ml_retrain",
            name="Weekly ML Model Retraining",
            max_instances=1,
            replace_existing=True,
        )

        # Health check - every 5 minutes
        self._scheduler.add_job(
            self._health_check,
            trigger=IntervalTrigger(minutes=5),
            id="health_check",
            name="System Health Check",
            max_instances=1,
            replace_existing=True,
        )

        # Audit log archival - daily at 4 AM
        self._scheduler.add_job(
            self._archive_audit_logs,
            trigger=CronTrigger(hour=4, minute=0),
            id="audit_log_archival",
            name="Audit Log Archival",
            max_instances=1,
            replace_existing=True,
        )

    async def start(self) -> None:
        """Start the orchestrator main loop."""
        self._is_running = True
        self._scheduler.start()

        logger.info("Sentinel-Zero orchestrator started")

        # Initial threat intel sync
        asyncio.create_task(self._sync_threat_intel())

        # Wait for shutdown signal
        await self._shutdown_event.wait()

    async def _sync_threat_intel(self) -> None:
        """Sync threat intelligence from all sources."""
        try:
            logger.info("Starting threat intelligence sync")
            results = await threat_intel.run_full_sync()

            logger.info(
                "Threat intelligence sync completed",
                **results,
            )

        except Exception as e:
            logger.error("Threat intelligence sync failed", error=str(e))

    async def _run_scheduled_scan(self) -> None:
        """Run scheduled network discovery scan."""
        if self._scan_in_progress:
            logger.warning("Scan already in progress, skipping scheduled scan")
            return

        self._scan_in_progress = True

        try:
            # Get all active organizations
            async with db.raw_connection() as conn:
                orgs = await conn.fetch("""
                                        SELECT id, name
                                        FROM organizations
                                        WHERE license_expires_at > NOW()
                                        """)

            for org in orgs:
                try:
                    # Get network ranges to scan
                    async with db.raw_connection() as conn:
                        ranges = await conn.fetch("""
                                                  SELECT DISTINCT network_segment
                                                  FROM assets
                                                  WHERE organization_id = $1
                                                    AND network_segment IS NOT NULL
                                                  """, org["id"])

                    if not ranges:
                        # Default to common private ranges
                        ranges = [{"network_segment": "192.168.0.0/16"}]

                    for range_row in ranges:
                        target = range_row["network_segment"]

                        logger.info(
                            "Running scheduled scan",
                            organization=org["name"],
                            target=target,
                        )

                        result = await network_scanner.discover_network(
                            organization_id=org["id"],
                            target=target,
                            scan_type="standard",
                        )

                        logger.info(
                            "Scheduled scan completed",
                            organization=org["name"],
                            target=target,
                            assets_discovered=result.assets_discovered,
                            vulnerabilities_found=result.vulnerabilities_found,
                        )

                except Exception as e:
                    logger.error(
                        "Scan failed for organization",
                        organization=org["name"],
                        error=str(e),
                    )

        finally:
            self._scan_in_progress = False

    async def _retrain_ml_models(self) -> None:
        """Retrain ML models for all organizations."""
        logger.info("Starting weekly ML model retraining")

        async with db.raw_connection() as conn:
            orgs = await conn.fetch("""
                                    SELECT id, name
                                    FROM organizations
                                    WHERE license_expires_at > NOW()
                                      AND (features ->>'ml_enabled')::boolean = TRUE
                                    """)

        for org in orgs:
            try:
                pipeline = ModelTrainingPipeline(organization_id=org["id"])
                metrics = await pipeline.run_if_needed()

                if metrics:
                    logger.info(
                        "Model retrained",
                        organization=org["name"],
                        version=metrics.model_version,
                        samples=metrics.training_samples,
                    )

            except Exception as e:
                logger.error(
                    "Model retraining failed",
                    organization=org["name"],
                    error=str(e),
                )

    async def _health_check(self) -> None:
        """Perform system health check."""
        health = {
            "timestamp": datetime.utcnow().isoformat(),
            "status": "healthy",
            "components": {},
        }

        # Database health
        db_health = await db.health_check()
        health["components"]["database"] = db_health

        # R2 health
        r2_health = await r2_storage.health_check()
        health["components"]["storage"] = r2_health

        # Threat intel stats
        intel_stats = await threat_intel.get_threat_stats()
        health["components"]["threat_intel"] = intel_stats

        # Scanner status
        health["components"]["scanner"] = {
            "active_scans": len(network_scanner.get_active_scans()),
        }

        # Overall status
        if any(c.get("status") != "healthy" for c in health["components"].values() if isinstance(c, dict)):
            health["status"] = "degraded"

        logger.info("Health check completed", **health)

    async def _archive_audit_logs(self) -> None:
        """Archive old audit logs to R2 for compliance."""
        logger.info("Starting audit log archival")

        async with db.raw_connection() as conn:
            orgs = await conn.fetch("""
                                    SELECT id, name
                                    FROM organizations
                                    """)

        for org in orgs:
            try:
                # Get logs older than 30 days
                logs = await conn.fetch("""
                                        SELECT *
                                        FROM audit_logs
                                        WHERE organization_id = $1
                                          AND created_at < NOW() - INTERVAL '30 days'
                                          AND r2_detail_key IS NULL
                                        ORDER BY created_at
                                            LIMIT 10000
                                        """, org["id"])

                if not logs:
                    continue

                # Archive to R2
                log_date = logs[0]["created_at"].date()
                key = await r2_storage.store_audit_log(
                    organization_id=org["id"],
                    log_entries=[dict(log) for log in logs],
                    log_date=datetime.combine(log_date, datetime.min.time()),
                )

                # Mark as archived
                log_ids = [log["id"] for log in logs]
                await conn.execute("""
                                   UPDATE audit_logs
                                   SET r2_detail_key = $2
                                   WHERE id = ANY ($1::uuid[])
                                   """, log_ids, key)

                logger.info(
                    "Audit logs archived",
                    organization=org["name"],
                    count=len(logs),
                    key=key,
                )

            except Exception as e:
                logger.error(
                    "Audit archival failed",
                    organization=org["name"],
                    error=str(e),
                )

    async def run_manual_scan(
            self,
            organization_id: UUID,
            target: str,
            scan_type: str = "standard",
    ) -> dict[str, Any]:
        """
        Run an on-demand network scan.

        Called via API for immediate scanning.
        """
        result = await network_scanner.discover_network(
            organization_id=organization_id,
            target=target,
            scan_type=scan_type,
        )

        return {
            "scan_id": str(result.scan_id),
            "status": "completed" if result.completed_at else "failed",
            "assets_discovered": result.assets_discovered,
            "assets_updated": result.assets_updated,
            "vulnerabilities_found": result.vulnerabilities_found,
            "errors": result.errors,
            "duration_seconds": (
                (result.completed_at - result.started_at).total_seconds()
                if result.completed_at else None
            ),
        }

    async def get_predictor(self, organization_id: UUID) -> AnomalyPredictor:
        """Get or create a predictor for an organization."""
        if organization_id not in self._active_predictors:
            predictor = await create_predictor(organization_id)
            self._active_predictors[organization_id] = predictor

        return self._active_predictors[organization_id]


# Global orchestrator instance
orchestrator = SentinelZeroOrchestrator()


# FastAPI Application
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    await orchestrator.initialize()
    yield
    await orchestrator.shutdown()


app = FastAPI(
    title="Sentinel-Zero",
    description="Enterprise Autonomous Cybersecurity Defense Platform",
    version=settings.app_version,
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health_check():
    """System health endpoint."""
    db_health = await db.health_check()
    r2_health = await r2_storage.health_check()

    return {
        "status": "healthy" if db_health["status"] == "healthy" else "degraded",
        "components": {
            "database": db_health,
            "storage": r2_health,
        },
        "version": settings.app_version,
        "environment": settings.environment,
    }


@app.post("/api/v1/scan")
async def trigger_scan(
        organization_id: UUID,
        target: str,
        scan_type: str = "standard",
):
    """Trigger an on-demand network scan."""
    try:
        result = await orchestrator.run_manual_scan(
            organization_id=organization_id,
            target=target,
            scan_type=scan_type,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/intel/sync")
async def trigger_intel_sync():
    """Trigger threat intelligence sync."""
    try:
        results = await threat_intel.run_full_sync()
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/stats")
async def get_stats(organization_id: UUID):
    """Get organization statistics."""
    async with db.raw_connection() as conn:
        stats = await conn.fetchrow("""
                                    SELECT (SELECT COUNT(*) FROM assets WHERE organization_id = $1)     as total_assets,
                                           (SELECT COUNT(*)
                                            FROM assets
                                            WHERE organization_id = $1
                                              AND status = 'active')                                    as active_assets,
                                           (SELECT COUNT(*)
                                            FROM asset_vulnerabilities
                                            WHERE organization_id = $1
                                              AND status = 'open')                                      as open_vulnerabilities,
                                           (SELECT COUNT(*)
                                            FROM anomaly_detections
                                            WHERE organization_id = $1
                                              AND is_acknowledged = FALSE)                              as unacked_anomalies,
                                           (SELECT COUNT(*)
                                            FROM remediation_tasks
                                            WHERE organization_id = $1
                                              AND status = 'pending_approval')                          as pending_remediations
                                    """, organization_id)

        return dict(stats) if stats else {}


def main():
    """Entry point for Sentinel-Zero."""
    import uvicorn

    # Setup signal handlers
    def handle_shutdown(signum, frame):
        logger.info("Received shutdown signal")
        asyncio.create_task(orchestrator.shutdown())
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    # Run the application
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        workers=1,  # Single worker for scheduler
        log_level="info",
        reload=settings.environment == "development",
    )

#if you would like to use api if not just run main.py i do that

# from api.routes import all_routers, set_orchestrator

# # Include all routers
# for router in all_routers:
#     app.include_router(router)

# # Inject orchestrator after initialization (inside lifespan startup)
# @asynccontextmanager
# async def lifespan(app: FastAPI):
#     await orchestrator.initialize()
#     set_orchestrator(orchestrator)  # ← Add this line
#     yield
#     await orchestrator.shutdown()

if __name__ == "__main__":

    main()
