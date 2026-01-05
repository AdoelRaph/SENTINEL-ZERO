"""
Sentinel-Zero Database Connection Module

Provides async database connection management with connection pooling,
automatic reconnection, and query instrumentation for Neon PostgreSQL.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, AsyncGenerator
from uuid import UUID

import asyncpg
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from config import get_settings
from utils.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


class DatabaseManager:
    """
    Manages async database connections to Neon PostgreSQL.

    Features:
    - Connection pooling with automatic recovery
    - Query performance instrumentation
    - Tenant context injection for RLS
    - Health check and monitoring
    """

    _instance: DatabaseManager | None = None
    _engine: AsyncEngine | None = None
    _session_factory: async_sessionmaker[AsyncSession] | None = None
    _raw_pool: asyncpg.Pool | None = None

    def __new__(cls) -> DatabaseManager:
        """Singleton pattern for database manager."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    async def initialize(self) -> None:
        """
        Initialize database connections and pools.

        Should be called once during application startup.
        """
        if self._engine is not None:
            logger.warning("Database already initialized, skipping")
            return

        logger.info("Initializing Neon PostgreSQL connection")

        # Create SQLAlchemy async engine
        self._engine = create_async_engine(
            settings.neon.get_async_url(),
            pool_size=settings.neon.pool_size,
            max_overflow=settings.neon.max_overflow,
            pool_timeout=settings.neon.pool_timeout,
            pool_recycle=settings.neon.pool_recycle,
            pool_pre_ping=True,  # Verify connections before use
            echo=settings.neon.echo_sql,
            connect_args={
                "ssl": "require",
                "server_settings": {
                    "application_name": "sentinel-zero",
                },
            },
        )

        # Attach event listeners for instrumentation
        self._attach_engine_events()

        # Create session factory
        self._session_factory = async_sessionmaker(
            bind=self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )

        # Create raw asyncpg pool for high-performance operations
        self._raw_pool = await asyncpg.create_pool(
            settings.neon.database_url.get_secret_value(),
            min_size=5,
            max_size=settings.neon.pool_size,
            max_inactive_connection_lifetime=300.0,
            command_timeout=60.0,
        )

        # Verify connection
        await self._verify_connection()

        logger.info("Database connection initialized successfully")

    def _attach_engine_events(self) -> None:
        """Attach SQLAlchemy event listeners for monitoring."""

        @event.listens_for(self._engine.sync_engine, "before_cursor_execute")
        def receive_before_cursor_execute(
                conn, cursor, statement, parameters, context, executemany
        ):
            conn.info.setdefault("query_start_time", []).append(datetime.utcnow())

        @event.listens_for(self._engine.sync_engine, "after_cursor_execute")
        def receive_after_cursor_execute(
                conn, cursor, statement, parameters, context, executemany
        ):
            query_start = conn.info["query_start_time"].pop()
            duration = (datetime.utcnow() - query_start).total_seconds()

            if duration > 1.0:  # Log slow queries
                logger.warning(
                    "Slow query detected",
                    duration_seconds=duration,
                    statement=statement[:200],
                )

    async def _verify_connection(self) -> None:
        """Verify database connection is working."""
        async with self._raw_pool.acquire() as conn:
            version = await conn.fetchval("SELECT version()")
            logger.info("Connected to database", version=version[:50])

    async def shutdown(self) -> None:
        """
        Gracefully shutdown database connections.

        Should be called during application shutdown.
        """
        logger.info("Shutting down database connections")

        if self._raw_pool:
            await self._raw_pool.close()
            self._raw_pool = None

        if self._engine:
            await self._engine.dispose()
            self._engine = None

        self._session_factory = None
        logger.info("Database connections closed")

    @asynccontextmanager
    async def session(
            self,
            organization_id: UUID | None = None,
    ) -> AsyncGenerator[AsyncSession, None]:
        """
        Get a database session with optional tenant context.

        Args:
            organization_id: Optional org ID to set for RLS policies.

        Yields:
            Configured AsyncSession instance.
        """
        if self._session_factory is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")

        session = self._session_factory()

        try:
            # Set tenant context for Row Level Security
            if organization_id:
                await session.execute(
                    text(f"SET app.current_org_id = '{organization_id}'")
                )

            yield session

            await session.commit()

        except Exception as e:
            await session.rollback()
            logger.error("Database session error", error=str(e))
            raise

        finally:
            await session.close()

    @asynccontextmanager
    async def raw_connection(self) -> AsyncGenerator[asyncpg.Connection, None]:
        """
        Get a raw asyncpg connection for high-performance operations.

        Useful for bulk inserts, COPY operations, and complex queries.
        """
        if self._raw_pool is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")

        async with self._raw_pool.acquire() as conn:
            yield conn

    async def execute_many(
            self,
            query: str,
            args: list[tuple],
            batch_size: int = 1000,
    ) -> int:
        """
        Execute a query with many parameter sets efficiently.

        Uses asyncpg's executemany for optimal bulk operations.

        Args:
            query: SQL query with $1, $2, ... placeholders.
            args: List of parameter tuples.
            batch_size: Number of records per batch.

        Returns:
            Total number of rows affected.
        """
        total_affected = 0

        async with self.raw_connection() as conn:
            for i in range(0, len(args), batch_size):
                batch = args[i:i + batch_size]
                result = await conn.executemany(query, batch)
                # executemany returns status string, parse row count
                if result:
                    total_affected += len(batch)

        return total_affected

    async def health_check(self) -> dict[str, Any]:
        """
        Perform database health check.

        Returns:
            Dictionary with health status and metrics.
        """
        health = {
            "status": "unhealthy",
            "latency_ms": None,
            "pool_size": None,
            "pool_available": None,
            "timestamp": datetime.utcnow().isoformat(),
        }

        try:
            start = datetime.utcnow()

            async with self.raw_connection() as conn:
                await conn.fetchval("SELECT 1")

            latency = (datetime.utcnow() - start).total_seconds() * 1000

            health.update({
                "status": "healthy",
                "latency_ms": round(latency, 2),
                "pool_size": self._raw_pool.get_size() if self._raw_pool else 0,
                "pool_available": self._raw_pool.get_idle_size() if self._raw_pool else 0,
            })

        except Exception as e:
            health["error"] = str(e)
            logger.error("Database health check failed", error=str(e))

        return health


# Singleton instance
db = DatabaseManager()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency for database sessions.

    Usage:
        @app.get("/assets")
        async def get_assets(session: AsyncSession = Depends(get_db)):
            ...
    """
    async with db.session() as session:
        yield session


async def get_db_with_org(
        organization_id: UUID,
) -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency for tenant-scoped database sessions.

    Sets RLS context for multi-tenant isolation.
    """
    async with db.session(organization_id=organization_id) as session:
        yield session