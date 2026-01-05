"""
Sentinel-Zero Logging Configuration

Enterprise-grade structured logging with:
- JSON formatting for log aggregation (ELK, Splunk, Datadog)
- Context propagation for distributed tracing
- Performance metrics tracking
- Compliance-ready audit trail formatting
- Syslog forwarding for SIEM integration

Copyright (c) 2024 Sentinel Security Inc.
Licensed under Proprietary License
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
from typing import Any

import structlog
from pythonjsonlogger import jsonlogger
from structlog.types import Processor

from config import get_settings

settings = get_settings()


class ComplianceFilter(logging.Filter):
    """
    Filter to mark sensitive operations for compliance tracking.

    Automatically flags authentication, authorization, data access,
    and configuration changes as compliance-relevant events.
    """

    SENSITIVE_ACTIONS = {
        'login', 'logout', 'authentication', 'authorization',
        'credential', 'password', 'api_key', 'token',
        'access', 'permission', 'role', 'privilege',
        'configuration', 'setting', 'policy',
        'data_export', 'data_delete', 'pii_access',
    }

    def filter(self, record: logging.LogRecord) -> bool:
        """Mark record as compliance-relevant if it contains sensitive actions."""
        message = record.getMessage().lower()

        # Check if any sensitive action is in the message
        record.compliance_relevant = any(
            action in message for action in self.SENSITIVE_ACTIONS
        )

        # Always pass through (return True)
        return True


class SyslogHandler(logging.handlers.SysLogHandler):
    """
    Custom Syslog handler with connection retry and formatting.

    Ensures logs reach SIEM systems even with network interruptions.
    """

    def __init__(self, address: tuple[str, int], facility: int = logging.handlers.SysLogHandler.LOG_USER):
        super().__init__(address=address, facility=facility)
        self.retry_count = 3
        self.retry_delay = 1.0

    def emit(self, record: logging.LogRecord) -> None:
        """Emit with retry logic."""
        import time

        for attempt in range(self.retry_count):
            try:
                super().emit(record)
                return
            except Exception as e:
                if attempt == self.retry_count - 1:
                    # Last attempt failed, log to stderr
                    sys.stderr.write(f"Failed to send log to syslog: {e}\n")
                    return
                time.sleep(self.retry_delay)


class PerformanceLogger:
    """
    Context manager for tracking operation performance.

    Usage:
        with PerformanceLogger("database_query"):
            result = await db.execute(query)
    """

    def __init__(self, operation: str, logger: structlog.stdlib.BoundLogger | None = None):
        self.operation = operation
        self.logger = logger or structlog.get_logger()
        self.start_time: float | None = None

    def __enter__(self):
        import time
        self.start_time = time.perf_counter()
        self.logger.debug(f"{self.operation}_started")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        import time
        duration = time.perf_counter() - self.start_time

        if exc_type is None:
            self.logger.info(
                f"{self.operation}_completed",
                duration_seconds=round(duration, 4),
            )
        else:
            self.logger.error(
                f"{self.operation}_failed",
                duration_seconds=round(duration, 4),
                error_type=exc_type.__name__,
                error=str(exc_val),
            )

        return False  # Don't suppress exceptions


def add_application_context(
    logger: logging.Logger,
    method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Add application-specific context to all log records."""
    event_dict['application'] = 'sentinel-zero'
    event_dict['version'] = settings.app_version
    event_dict['environment'] = settings.environment
    return event_dict


def filter_sensitive_data(
    logger: logging.Logger,
    method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """
    Scrub sensitive data from logs.

    Prevents credential leakage and PII exposure in log files.
    """
    sensitive_keys = {
        'password', 'passwd', 'pwd',
        'secret', 'api_key', 'apikey', 'token',
        'private_key', 'priv_key',
        'authorization', 'auth',
        'ssn', 'social_security',
        'credit_card', 'card_number',
    }

    def scrub_dict(d: dict) -> dict:
        scrubbed = {}
        for key, value in d.items():
            key_lower = str(key).lower()

            # Check if key contains sensitive terms
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                scrubbed[key] = '***REDACTED***'
            elif isinstance(value, dict):
                scrubbed[key] = scrub_dict(value)
            elif isinstance(value, list):
                scrubbed[key] = [
                    scrub_dict(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                scrubbed[key] = value

        return scrubbed

    return scrub_dict(event_dict)


def configure_logging() -> None:
    """
    Configure enterprise structured logging.

    Sets up:
    - JSON formatted logs for production
    - Console logs for development
    - Syslog forwarding for SIEM
    - Performance tracking
    - Compliance filtering
    """

    # Determine log processors based on format
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_logger_name,
        add_application_context,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        filter_sensitive_data,
        structlog.processors.UnicodeDecoder(),
    ]

    if settings.logging.format == "json":
        # Production: JSON output
        renderer = structlog.processors.JSONRenderer()
    else:
        # Development: Colored console output
        renderer = structlog.dev.ConsoleRenderer(
            colors=True,
            exception_formatter=structlog.dev.plain_traceback,
        )

    # Configure structlog
    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Configure stdlib logging
    formatter = structlog.stdlib.ProcessorFormatter(
        processor=renderer,
        foreign_pre_chain=shared_processors,
    )

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(ComplianceFilter())

    # Setup handlers list
    handlers: list[logging.Handler] = [console_handler]

    # Syslog handler for SIEM integration
    if settings.logging.syslog_enabled:
        try:
            syslog_handler = SyslogHandler(
                address=(settings.logging.syslog_host, settings.logging.syslog_port),
                facility=logging.handlers.SysLogHandler.LOG_LOCAL0,
            )

            # Use JSON formatter for syslog
            syslog_formatter = jsonlogger.JsonFormatter(
                '%(timestamp)s %(level)s %(name)s %(message)s',
                rename_fields={
                    'timestamp': '@timestamp',
                    'level': 'severity',
                },
            )
            syslog_handler.setFormatter(syslog_formatter)
            syslog_handler.addFilter(ComplianceFilter())

            handlers.append(syslog_handler)

        except Exception as e:
            sys.stderr.write(f"Failed to setup syslog handler: {e}\n")

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.handlers.clear()

    for handler in handlers:
        root_logger.addHandler(handler)

    root_logger.setLevel(getattr(logging, settings.logging.level.upper()))

    # Quiet noisy third-party libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("aioboto3").setLevel(logging.WARNING)
    logging.getLogger("s3transfer").setLevel(logging.WARNING)

    # Log configuration completion
    logger = structlog.get_logger(__name__)
    logger.info(
        "Logging configured",
        log_level=settings.logging.level,
        log_format=settings.logging.format,
        syslog_enabled=settings.logging.syslog_enabled,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """
    Get a structured logger instance for a module.

    Args:
        name: Module name (typically __name__)

    Returns:
        Configured structlog logger

    Example:
        logger = get_logger(__name__)
        logger.info("Operation completed", user_id=user_id, duration=0.5)
    """
    return structlog.get_logger(name)


def log_function_call(func):
    """
    Decorator to automatically log function entry/exit.

    Usage:
        @log_function_call
        async def process_data(data: dict) -> dict:
            ...
    """
    import functools
    import inspect

    logger = get_logger(func.__module__)

    @functools.wraps(func)
    async def async_wrapper(*args, **kwargs):
        with PerformanceLogger(func.__name__, logger):
            return await func(*args, **kwargs)

    @functools.wraps(func)
    def sync_wrapper(*args, **kwargs):
        with PerformanceLogger(func.__name__, logger):
            return func(*args, **kwargs)

    if inspect.iscoroutinefunction(func):
        return async_wrapper
    else:
        return sync_wrapper


# Convenience export
__all__ = [
    'configure_logging',
    'get_logger',
    'PerformanceLogger',
    'log_function_call',
]