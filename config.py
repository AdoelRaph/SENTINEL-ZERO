"""
Sentinel-Zero Configuration Module - COMPLETE WORKING VERSION

Centralized configuration management with secure credential handling,
connection pooling, and environment-aware settings.

License: Proprietary - Sentinel Security Inc.
"""

from __future__ import annotations

import os
import ssl
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class NeonDatabaseSettings(BaseSettings):
    """Neon PostgreSQL serverless database configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: SecretStr = Field(
        ...,
        description="Neon PostgreSQL connection string with SSL"
    )
    pool_size: int = Field(
        default=20,
        ge=5,
        le=100,
        description="Connection pool size"
    )
    max_overflow: int = Field(
        default=10,
        ge=0,
        le=50,
        description="Maximum overflow connections"
    )
    pool_timeout: int = Field(
        default=30,
        description="Pool connection timeout in seconds"
    )
    pool_recycle: int = Field(
        default=1800,
        description="Connection recycle time in seconds"
    )
    echo_sql: bool = Field(
        default=False,
        description="Echo SQL statements for debugging"
    )

    @field_validator("database_url", mode="before")
    @classmethod
    def load_database_url(cls, v):
        """Load DATABASE_URL from environment if not provided."""
        if v is None or v == "":
            v = os.getenv("DATABASE_URL")
        if not v:
            raise ValueError("DATABASE_URL environment variable is required")
        return v

    @field_validator("database_url")
    @classmethod
    def validate_ssl_mode(cls, v: SecretStr) -> SecretStr:
        """Ensure SSL mode is enforced for Neon connections."""
        url = v.get_secret_value()
        if "sslmode=require" not in url and "sslmode=verify-full" not in url:
            raise ValueError(
                "Neon database URL must include sslmode=require or sslmode=verify-full"
            )
        return v

    def get_async_url(self) -> str:
        """Convert standard PostgreSQL URL to async-compatible format."""
        url = self.database_url.get_secret_value()
        return url.replace("postgresql://", "postgresql+asyncpg://")


class CloudflareR2Settings(BaseSettings):
    """Cloudflare R2 object storage configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="R2_",
        extra="ignore",
    )

    account_id: str = Field(..., description="Cloudflare account ID")
    access_key_id: SecretStr = Field(..., description="R2 access key ID")
    secret_access_key: SecretStr = Field(..., description="R2 secret access key")
    bucket_name: str = Field(..., description="Primary storage bucket")
    endpoint_url: str = Field(..., description="R2 endpoint URL")
    region: str = Field(default="auto", description="R2 region")

    pcap_prefix: str = Field(default="pcap-logs/", description="PCAP storage path")
    model_prefix: str = Field(default="ml-models/", description="ML model storage path")
    audit_prefix: str = Field(default="audit-trails/", description="Audit log path")

    multipart_threshold: int = Field(
        default=8 * 1024 * 1024,
        description="Multipart upload threshold in bytes"
    )
    max_concurrency: int = Field(
        default=10,
        description="Maximum concurrent transfers"
    )


class MLEngineSettings(BaseSettings):
    """Machine Learning engine configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="ML_",
        extra="ignore",
    )

    retrain_interval_days: int = Field(
        default=7,
        ge=1,
        le=30,
        description="Days between automatic retraining"
    )
    anomaly_threshold: float = Field(
        default=0.15,
        ge=0.01,
        le=0.5,
        description="Anomaly detection threshold (lower = more sensitive)"
    )
    model_version: str = Field(
        default="1.0.0",
        description="Current model version identifier"
    )

    n_estimators: int = Field(default=200, description="Number of trees")
    contamination: float = Field(
        default=0.1,
        ge=0.01,
        le=0.5,
        description="Expected proportion of anomalies"
    )
    max_samples: int = Field(
        default=10000,
        description="Maximum samples per tree"
    )

    time_window_seconds: int = Field(
        default=300,
        description="Rolling window for feature aggregation"
    )
    min_training_samples: int = Field(
        default=10000,
        description="Minimum samples required for training"
    )

    loop_packet_threshold: int = Field(
        default=1000,
        description="Packets per second threshold for loop detection"
    )
    loop_time_window: int = Field(
        default=10,
        description="Seconds to observe for loop patterns"
    )

    suspicious_port_threshold: int = Field(
        default=1024,
        description="Port number above which listening is suspicious on non-servers"
    )


class ScannerSettings(BaseSettings):
    """Network scanner configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="SCANNER_",
        extra="ignore",
    )

    timeout_seconds: int = Field(
        default=30,
        ge=5,
        le=300,
        description="Per-host scan timeout"
    )
    max_concurrent: int = Field(
        default=100,
        ge=10,
        le=500,
        description="Maximum concurrent scan operations"
    )
    nmap_path: Path = Field(
        default=Path("/usr/bin/nmap"),
        description="Path to nmap binary"
    )

    quick_scan_ports: str = Field(
        default="21-23,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080",
        description="Ports for quick scans"
    )
    full_scan_ports: str = Field(
        default="1-65535",
        description="Ports for comprehensive scans"
    )

    wireless_interface: str | None = Field(
        default=None,
        description="Wireless interface for WiFi scanning"
    )
    wireless_scan_enabled: bool = Field(
        default=False,
        description="Enable wireless network discovery"
    )


class RemediationSettings(BaseSettings):
    """Remediation agent configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="REMEDIATION_",
        extra="ignore",
    )

    auto_approve_low_risk: bool = Field(
        default=False,
        description="Auto-approve low-risk patches without human review"
    )
    ssh_timeout: int = Field(
        default=60,
        ge=10,
        le=300,
        description="SSH connection timeout in seconds"
    )
    max_retries: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum patch application retries"
    )

    approval_timeout_hours: int = Field(
        default=24,
        description="Hours before pending approvals expire"
    )
    require_dual_approval: bool = Field(
        default=True,
        description="Require two approvers for high-risk patches"
    )

    credential_vault_path: str = Field(
        default="credentials/",
        description="Path prefix in R2 for encrypted credentials"
    )


class SecuritySettings(BaseSettings):
    """Security and cryptography configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    api_secret_key: SecretStr = Field(
        default="dev-secret-key-minimum-32-characters-required-here!!!!"
    )
    jwt_algorithm: str = Field(
        default="HS256",
        description="JWT signing algorithm"
    )
    jwt_expiration_hours: int = Field(
        default=24,
        ge=1,
        le=168,
        description="JWT token expiration in hours"
    )
    encryption_key: SecretStr = Field(
        default="bjwMNDoUvrEaXU9a2wylwWUWo9FArdU6ggSLExCZNVc="
    )

    @field_validator("api_secret_key")
    @classmethod
    def validate_secret_strength(cls, v: SecretStr) -> SecretStr:
        """Ensure API secret key meets minimum security requirements."""
        secret = v.get_secret_value()
        if len(secret) < 32:
            raise ValueError("API secret key must be at least 32 characters")
        return v


class ThreatIntelSettings(BaseSettings):
    """Threat intelligence feed configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    nist_nvd_api_key: SecretStr | None = Field(
        default=None,
        description="NIST NVD API key for higher rate limits"
    )
    cisa_api_enabled: bool = Field(
        default=True,
        description="Enable CISA KEV feed ingestion"
    )

    nvd_poll_interval_hours: int = Field(
        default=6,
        description="Hours between NVD API polls"
    )
    cisa_poll_interval_hours: int = Field(
        default=1,
        description="Hours between CISA KEV polls"
    )

    nvd_requests_per_minute: int = Field(
        default=30,
        description="NVD API rate limit (with API key)"
    )


class LoggingSettings(BaseSettings):
    """Logging and monitoring configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="LOG_",
        extra="ignore",
    )

    level: str = Field(
        default="INFO",
        description="Logging level"
    )
    format: str = Field(
        default="json",
        description="Log output format"
    )

    syslog_enabled: bool = Field(
        default=False,
        description="Enable syslog forwarding"
    )
    syslog_host: str = Field(
        default="localhost",
        description="Syslog server host"
    )
    syslog_port: int = Field(
        default=514,
        ge=1,
        le=65535,
        description="Syslog server port"
    )


class SentinelZeroSettings(BaseSettings):
    """
    Master configuration aggregating all subsystem settings.

    This class provides a single point of access for all configuration
    values throughout the application.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Subsystem configurations
    neon: NeonDatabaseSettings = Field(default_factory=NeonDatabaseSettings)
    r2: CloudflareR2Settings = Field(default_factory=CloudflareR2Settings)
    ml: MLEngineSettings = Field(default_factory=MLEngineSettings)
    scanner: ScannerSettings = Field(default_factory=ScannerSettings)
    remediation: RemediationSettings = Field(default_factory=RemediationSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    threat_intel: ThreatIntelSettings = Field(default_factory=ThreatIntelSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)

    # Application metadata
    app_name: str = Field(default="Sentinel-Zero")
    app_version: str = Field(default="1.0.0")
    environment: str = Field(
        default="development",
    )

    def get_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for secure connections."""
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context


@lru_cache
def get_settings() -> SentinelZeroSettings:
    """
    Get cached application settings.

    Uses LRU cache to ensure settings are loaded once and reused
    throughout the application lifecycle.

    Returns:
        SentinelZeroSettings: Fully validated configuration object.
    """
    return SentinelZeroSettings()


# Singleton instance - loads settings at module import
settings = get_settings()