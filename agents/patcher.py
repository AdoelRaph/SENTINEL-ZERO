"""
Sentinel-Zero Remediation Agent

Secure automated patching and remediation via:
- SSH (Linux/Unix systems)
- WinRM (Windows systems)

Includes approval workflows, rollback capabilities, and audit logging.
"""

from __future__ import annotations

import asyncio
import io
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any
from uuid import UUID

import paramiko
from cryptography.fernet import Fernet

from config import get_settings
from database.connection import db
from storage.r2_client import r2_storage
from utils.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


class RemediationType(str, Enum):
    """Types of remediation actions."""

    PATCH_SYSTEM = "patch_system"
    UPDATE_PACKAGE = "update_package"
    RESTART_SERVICE = "restart_service"
    MODIFY_FIREWALL = "modify_firewall"
    QUARANTINE_HOST = "quarantine_host"
    CUSTOM_SCRIPT = "custom_script"


class RemediationRisk(str, Enum):
    """Risk levels for remediation actions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RemediationTask:
    """Represents a remediation task to be executed."""

    task_id: UUID
    organization_id: UUID
    asset_id: UUID
    target_ip: str

    remediation_type: RemediationType
    title: str
    description: str | None = None

    # Execution details
    script: str | None = None
    template_name: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)

    # Risk assessment
    risk_level: RemediationRisk = RemediationRisk.MEDIUM
    requires_downtime: bool = False
    estimated_downtime_minutes: int = 0

    # Rollback
    rollback_script: str | None = None
    rollback_available: bool = True

    # Status
    status: str = "pending_approval"
    requested_by: UUID | None = None
    requested_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ExecutionResult:
    """Result of a remediation execution."""

    task_id: UUID
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float


class CredentialVault:
    """
    Secure credential management for SSH/WinRM access.

    Credentials are encrypted and stored in R2.
    """

    def __init__(self, organization_id: UUID):
        self.organization_id = organization_id
        self._fernet = Fernet(settings.security.encryption_key.get_secret_value().encode())

    async def get_ssh_credentials(
            self,
            asset_id: UUID,
    ) -> tuple[str, str | None, bytes | None]:
        """
        Retrieve SSH credentials for an asset.

        Returns:
            Tuple of (username, password, private_key_bytes).
        """
        key = f"credentials/{self.organization_id}/{asset_id}/ssh.enc"

        try:
            encrypted_data = await r2_storage.download_file(key, verify_checksum=True)
            decrypted = self._fernet.decrypt(encrypted_data)

            import json
            creds = json.loads(decrypted.decode())

            return (
                creds["username"],
                creds.get("password"),
                creds.get("private_key", "").encode() if creds.get("private_key") else None,
            )

        except Exception as e:
            logger.error(
                "Failed to retrieve SSH credentials",
                asset_id=str(asset_id),
                error=str(e),
            )
            raise ValueError(f"No credentials available for asset {asset_id}")

    async def store_ssh_credentials(
            self,
            asset_id: UUID,
            username: str,
            password: str | None = None,
            private_key: str | None = None,
    ) -> None:
        """Store encrypted SSH credentials."""
        import json

        creds = {
            "username": username,
            "password": password,
            "private_key": private_key,
            "stored_at": datetime.utcnow().isoformat(),
        }

        encrypted = self._fernet.encrypt(json.dumps(creds).encode())

        await r2_storage.upload_file(
            key=f"credentials/{self.organization_id}/{asset_id}/ssh.enc",
            data=encrypted,
            content_type="application/octet-stream",
            metadata={
                "organization-id": str(self.organization_id),
                "asset-id": str(asset_id),
                "credential-type": "ssh",
            },
        )


class SSHExecutor:
    """
    SSH-based command executor for Linux/Unix systems.

    Features:
    - Key-based and password authentication
    - Command timeout handling
    - Output capture and streaming
    - Secure connection management
    """

    def __init__(
            self,
            hostname: str,
            username: str,
            password: str | None = None,
            private_key: bytes | None = None,
            port: int = 22,
    ):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.private_key = private_key
        self.port = port
        self._client: paramiko.SSHClient | None = None

    async def connect(self) -> None:
        """Establish SSH connection."""
        loop = asyncio.get_event_loop()

        def _connect():
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                "hostname": self.hostname,
                "port": self.port,
                "username": self.username,
                "timeout": settings.remediation.ssh_timeout,
                "allow_agent": False,
                "look_for_keys": False,
            }

            if self.private_key:
                key_file = io.BytesIO(self.private_key)
                pkey = paramiko.RSAKey.from_private_key(key_file)
                connect_kwargs["pkey"] = pkey
            elif self.password:
                connect_kwargs["password"] = self.password
            else:
                raise ValueError("Either password or private_key required")

            self._client.connect(**connect_kwargs)

        await loop.run_in_executor(None, _connect)

        logger.debug(
            "SSH connection established",
            hostname=self.hostname,
            username=self.username,
        )

    async def execute(
            self,
            command: str,
            timeout: int | None = None,
    ) -> tuple[int, str, str]:
        """
        Execute a command over SSH.

        Returns:
            Tuple of (exit_code, stdout, stderr).
        """
        if not self._client:
            raise RuntimeError("Not connected. Call connect() first.")

        loop = asyncio.get_event_loop()
        timeout = timeout or settings.remediation.ssh_timeout

        def _execute():
            stdin, stdout, stderr = self._client.exec_command(
                command,
                timeout=timeout,
            )

            exit_code = stdout.channel.recv_exit_status()
            stdout_text = stdout.read().decode("utf-8", errors="replace")
            stderr_text = stderr.read().decode("utf-8", errors="replace")

            return exit_code, stdout_text, stderr_text

        return await loop.run_in_executor(None, _execute)

    async def upload_file(
            self,
            local_content: bytes,
            remote_path: str,
            mode: int = 0o644,
    ) -> None:
        """Upload file content to remote system."""
        if not self._client:
            raise RuntimeError("Not connected. Call connect() first.")

        loop = asyncio.get_event_loop()

        def _upload():
            sftp = self._client.open_sftp()
            try:
                with sftp.file(remote_path, "wb") as f:
                    f.write(local_content)
                sftp.chmod(remote_path, mode)
            finally:
                sftp.close()

        await loop.run_in_executor(None, _upload)

    async def disconnect(self) -> None:
        """Close SSH connection."""
        if self._client:
            self._client.close()
            self._client = None


class RemediationAgent:
    """
    Central remediation orchestrator.

    Manages the complete remediation lifecycle:
    1. Task creation and risk assessment
    2. Approval workflow
    3. Execution with retry logic
    4. Rollback on failure
    5. Audit logging
    """

    # Built-in remediation templates
    TEMPLATES = {
        "linux_apt_update": {
            "script": "sudo apt-get update && sudo apt-get upgrade -y",
            "risk": RemediationRisk.MEDIUM,
            "requires_downtime": False,
        },
        "linux_apt_security": {
            "script": "sudo apt-get update && sudo apt-get upgrade -y --only-upgrade $(apt-get --just-print upgrade 2>&1 | grep -i security | awk '{print $2}' | sort -u)",
            "risk": RemediationRisk.LOW,
            "requires_downtime": False,
        },
        "linux_restart_service": {
            "script": "sudo systemctl restart {service_name}",
            "risk": RemediationRisk.MEDIUM,
            "requires_downtime": True,
        },
        "linux_firewall_block_ip": {
            "script": "sudo iptables -A INPUT -s {blocked_ip} -j DROP && sudo iptables-save",
            "risk": RemediationRisk.MEDIUM,
            "requires_downtime": False,
            "rollback": "sudo iptables -D INPUT -s {blocked_ip} -j DROP && sudo iptables-save",
        },
        "linux_kill_process": {
            "script": "sudo pkill -9 -f '{process_pattern}'",
            "risk": RemediationRisk.HIGH,
            "requires_downtime": False,
        },
        "linux_update_package": {
            "script": "sudo apt-get update && sudo apt-get install -y --only-upgrade {package_name}",
            "risk": RemediationRisk.LOW,
            "requires_downtime": False,
        },
    }

    def __init__(self, organization_id: UUID):
        self.organization_id = organization_id
        self._credential_vault = CredentialVault(organization_id)

    async def create_remediation_task(
            self,
            asset_id: UUID,
            target_ip: str,
            remediation_type: RemediationType,
            title: str,
            description: str | None = None,
            template_name: str | None = None,
            custom_script: str | None = None,
            parameters: dict[str, Any] | None = None,
            requested_by: UUID | None = None,
    ) -> RemediationTask:
        """
        Create a new remediation task.

        The task will be pending approval unless auto-approval is enabled
        for low-risk tasks.
        """
        import uuid
        task_id = uuid.uuid4()

        # Determine script and risk level
        if template_name and template_name in self.TEMPLATES:
            template = self.TEMPLATES[template_name]
            script = template["script"]
            risk_level = template["risk"]
            requires_downtime = template.get("requires_downtime", False)
            rollback_script = template.get("rollback")

            # Apply parameters to script
            if parameters:
                script = script.format(**parameters)
                if rollback_script:
                    rollback_script = rollback_script.format(**parameters)
        elif custom_script:
            script = custom_script
            risk_level = RemediationRisk.HIGH  # Custom scripts are high risk
            requires_downtime = True
            rollback_script = None
        else:
            raise ValueError("Either template_name or custom_script required")

        # Create task
        task = RemediationTask(
            task_id=task_id,
            organization_id=self.organization_id,
            asset_id=asset_id,
            target_ip=target_ip,
            remediation_type=remediation_type,
            title=title,
            description=description,
            script=script,
            template_name=template_name,
            parameters=parameters or {},
            risk_level=risk_level,
            requires_downtime=requires_downtime,
            rollback_script=rollback_script,
            rollback_available=rollback_script is not None,
            requested_by=requested_by,
        )

        # Check for auto-approval
        if (
                settings.remediation.auto_approve_low_risk
                and risk_level == RemediationRisk.LOW
        ):
            task.status = "approved"
            logger.info(
                "Task auto-approved (low risk)",
                task_id=str(task_id),
            )

        # Store task in database
        await self._store_task(task)

        logger.info(
            "Remediation task created",
            task_id=str(task_id),
            title=title,
            risk_level=risk_level.value,
            status=task.status,
        )

        return task

    async def approve_task(
            self,
            task_id: UUID,
            approved_by: UUID,
    ) -> bool:
        """Approve a pending remediation task."""
        async with db.raw_connection() as conn:
            # Check current status
            current = await conn.fetchrow("""
                                          SELECT status, risk_level
                                          FROM remediation_tasks
                                          WHERE id = $1
                                            AND organization_id = $2
                                          """, task_id, self.organization_id)

            if not current:
                raise ValueError(f"Task {task_id} not found")

            if current["status"] != "pending_approval":
                raise ValueError(f"Task {task_id} is not pending approval")

            # Check if dual approval required
            risk_level = current["risk_level"]
            if (
                    settings.remediation.require_dual_approval
                    and risk_level in ("high", "critical")
            ):
                # Check for existing approval
                existing_approval = await conn.fetchval("""
                                                        SELECT approved_by
                                                        FROM remediation_tasks
                                                        WHERE id = $1
                                                          AND approved_by IS NOT NULL
                                                        """, task_id)

                if existing_approval and existing_approval != approved_by:
                    # Second approval - fully approved
                    await conn.execute("""
                                       UPDATE remediation_tasks
                                       SET status                = 'approved',
                                           secondary_approved_by = $2,
                                           secondary_approved_at = NOW(),
                                           updated_at            = NOW()
                                       WHERE id = $1
                                       """, task_id, approved_by)
                else:
                    # First approval - needs second
                    await conn.execute("""
                                       UPDATE remediation_tasks
                                       SET approved_by = $2,
                                           approved_at = NOW(),
                                           updated_at  = NOW()
                                       WHERE id = $1
                                       """, task_id, approved_by)

                    logger.info(
                        "Task awaiting second approval",
                        task_id=str(task_id),
                    )
                    return False
            else:
                # Single approval sufficient
                await conn.execute("""
                                   UPDATE remediation_tasks
                                   SET status      = 'approved',
                                       approved_by = $2,
                                       approved_at = NOW(),
                                       updated_at  = NOW()
                                   WHERE id = $1
                                   """, task_id, approved_by)

        logger.info(
            "Task approved",
            task_id=str(task_id),
            approved_by=str(approved_by),
        )

        return True

    async def execute_task(
            self,
            task_id: UUID,
    ) -> ExecutionResult:
        """
        Execute an approved remediation task.

        Handles connection, execution, retry logic, and result storage.
        """
        # Load task
        async with db.raw_connection() as conn:
            task_row = await conn.fetchrow("""
                                           SELECT *
                                           FROM remediation_tasks
                                           WHERE id = $1
                                             AND organization_id = $2
                                           """, task_id, self.organization_id)

            if not task_row:
                raise ValueError(f"Task {task_id} not found")

        task = dict(task_row)

        if task["status"] != "approved":
            raise ValueError(f"Task {task_id} is not approved (status: {task['status']})")

        # Get asset details
        asset = await self._get_asset(task["asset_id"])
        target_ip = asset["ip_address"]

        # Get credentials
        username, password, private_key = await self._credential_vault.get_ssh_credentials(
            task["asset_id"]
        )

        # Update status to in_progress
        await self._update_task_status(task_id, "in_progress")

        started_at = datetime.utcnow()
        result: ExecutionResult | None = None

        try:
            # Create executor and connect
            executor = SSHExecutor(
                hostname=str(target_ip),
                username=username,
                password=password,
                private_key=private_key,
            )

            await executor.connect()

            try:
                # Execute with retry
                for attempt in range(settings.remediation.max_retries):
                    try:
                        exit_code, stdout, stderr = await executor.execute(
                            task["remediation_script"]
                        )
                        break
                    except Exception as e:
                        if attempt == settings.remediation.max_retries - 1:
                            raise
                        logger.warning(
                            "Execution attempt failed, retrying",
                            task_id=str(task_id),
                            attempt=attempt + 1,
                            error=str(e),
                        )
                        await asyncio.sleep(5)

                completed_at = datetime.utcnow()

                result = ExecutionResult(
                    task_id=task_id,
                    success=exit_code == 0,
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr=stderr,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_seconds=(completed_at - started_at).total_seconds(),
                )

            finally:
                await executor.disconnect()

            # Update task with result
            status = "completed" if result.success else "failed"
            await self._update_task_result(task_id, result, status)

            logger.info(
                "Remediation task executed",
                task_id=str(task_id),
                success=result.success,
                exit_code=exit_code,
                duration_seconds=result.duration_seconds,
            )

        except Exception as e:
            completed_at = datetime.utcnow()
            result = ExecutionResult(
                task_id=task_id,
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=(completed_at - started_at).total_seconds(),
            )

            await self._update_task_result(task_id, result, "failed")

            logger.error(
                "Remediation task failed",
                task_id=str(task_id),
                error=str(e),
            )

        # Create audit log
        await self._create_audit_log(task_id, result)

        return result

    async def rollback_task(
            self,
            task_id: UUID,
            rolled_back_by: UUID,
            reason: str,
    ) -> ExecutionResult:
        """
        Rollback a completed remediation task.

        Uses the rollback script stored with the task.
        """
        async with db.raw_connection() as conn:
            task = await conn.fetchrow("""
                                       SELECT *
                                       FROM remediation_tasks
                                       WHERE id = $1
                                         AND organization_id = $2
                                       """, task_id, self.organization_id)

            if not task:
                raise ValueError(f"Task {task_id} not found")

            if not task["rollback_script"]:
                raise ValueError(f"Task {task_id} has no rollback script")

        # Get credentials
        username, password, private_key = await self._credential_vault.get_ssh_credentials(
            task["asset_id"]
        )

        asset = await self._get_asset(task["asset_id"])

        started_at = datetime.utcnow()

        executor = SSHExecutor(
            hostname=str(asset["ip_address"]),
            username=username,
            password=password,
            private_key=private_key,
        )

        await executor.connect()

        try:
            exit_code, stdout, stderr = await executor.execute(task["rollback_script"])
        finally:
            await executor.disconnect()

        completed_at = datetime.utcnow()

        result = ExecutionResult(
            task_id=task_id,
            success=exit_code == 0,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=(completed_at - started_at).total_seconds(),
        )

        # Update task status
        async with db.raw_connection() as conn:
            await conn.execute("""
                               UPDATE remediation_tasks
                               SET status          = 'rolled_back',
                                   rolled_back_at  = NOW(),
                                   rolled_back_by  = $2,
                                   rollback_reason = $3,
                                   updated_at      = NOW()
                               WHERE id = $1
                               """, task_id, rolled_back_by, reason)

        logger.info(
            "Remediation task rolled back",
            task_id=str(task_id),
            success=result.success,
            reason=reason,
        )

        return result

    async def _store_task(self, task: RemediationTask) -> None:
        """Store task in database."""
        async with db.raw_connection() as conn:
            await conn.execute("""
                               INSERT INTO remediation_tasks (id, organization_id, asset_id, task_type, title,
                                                              description,
                                                              priority, remediation_script, remediation_template,
                                                              parameters,
                                                              risk_level, requires_downtime, estimated_downtime_minutes,
                                                              rollback_available, rollback_script, status, requested_by,
                                                              requested_at)
                               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
                               """,
                               task.task_id,
                               task.organization_id,
                               task.asset_id,
                               task.remediation_type.value,
                               task.title,
                               task.description,
                               "medium",
                               task.script,
                               task.template_name,
                               task.parameters,
                               task.risk_level.value,
                               task.requires_downtime,
                               task.estimated_downtime_minutes,
                               task.rollback_available,
                               task.rollback_script,
                               task.status,
                               task.requested_by,
                               task.requested_at,
                               )

    async def _update_task_status(self, task_id: UUID, status: str) -> None:
        """Update task status."""
        async with db.raw_connection() as conn:
            await conn.execute("""
                               UPDATE remediation_tasks
                               SET status     = $2,
                                   started_at = CASE WHEN $2 = 'in_progress' THEN NOW() ELSE started_at END,
                                   updated_at = NOW()
                               WHERE id = $1
                               """, task_id, status)

    async def _update_task_result(
            self,
            task_id: UUID,
            result: ExecutionResult,
            status: str,
    ) -> None:
        """Update task with execution result."""
        async with db.raw_connection() as conn:
            await conn.execute("""
                               UPDATE remediation_tasks
                               SET status           = $2,
                                   completed_at     = $3,
                                   execution_output = $4,
                                   error_message    = $5,
                                   exit_code        = $6,
                                   updated_at       = NOW()
                               WHERE id = $1
                               """,
                               task_id,
                               status,
                               result.completed_at,
                               result.stdout,
                               result.stderr if not result.success else None,
                               result.exit_code,
                               )

    async def _get_asset(self, asset_id: UUID) -> dict[str, Any]:
        """Get asset details."""
        async with db.raw_connection() as conn:
            row = await conn.fetchrow("""
                                      SELECT *
                                      FROM assets
                                      WHERE id = $1
                                      """, asset_id)
            return dict(row) if row else {}

    async def _create_audit_log(
            self,
            task_id: UUID,
            result: ExecutionResult,
    ) -> None:
        """Create audit log entry for remediation."""
        async with db.raw_connection() as conn:
            await conn.execute("""
                               INSERT INTO audit_logs (organization_id, action, resource_type, resource_id,
                                                       new_state, success, actor_type)
                               VALUES ($1, $2, $3, $4, $5, $6, $7)
                               """,
                               self.organization_id,
                               "remediation_executed",
                               "remediation_task",
                               task_id,
                               {
                                   "exit_code": result.exit_code,
                                   "duration_seconds": result.duration_seconds,
                                   "stdout_preview": result.stdout[:500] if result.stdout else None,
                               },
                               result.success,
                               "system",
                               )


# Module-level factory
def get_remediation_agent(organization_id: UUID) -> RemediationAgent:
    """Get a remediation agent for an organization."""
    return RemediationAgent(organization_id)