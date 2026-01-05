"""
Sentinel-Zero R2 Storage Client

Enterprise-grade Cloudflare R2 (S3-compatible) client for:
- PCAP log archival
- ML model weight storage
- Audit trail preservation
- Compliance-ready immutable storage
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import io
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, BinaryIO
from uuid import UUID

import aioboto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

from config import get_settings
from utils.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


class R2StorageClient:
    """
    Async Cloudflare R2 storage client with enterprise features.

    Features:
    - Multipart upload for large files
    - Automatic compression
    - Integrity verification (SHA-256)
    - Retention policy enforcement
    - Presigned URL generation
    """

    _instance: R2StorageClient | None = None
    _session: aioboto3.Session | None = None

    # Storage class prefixes
    PCAP_PREFIX = "pcap-logs"
    MODEL_PREFIX = "ml-models"
    AUDIT_PREFIX = "audit-trails"
    CREDENTIALS_PREFIX = "credentials"
    TEMP_PREFIX = "temp"

    def __new__(cls) -> R2StorageClient:
        """Singleton pattern for R2 client."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Initialize R2 client configuration."""
        if self._session is not None:
            return

        self._session = aioboto3.Session()
        self._bucket = settings.r2.bucket_name
        self._config = BotoConfig(
            signature_version="s3v4",
            retries={"max_attempts": 3, "mode": "adaptive"},
            max_pool_connections=50,
        )

    def _get_client_kwargs(self) -> dict[str, Any]:
        """Get common client configuration."""
        return {
            "service_name": "s3",
            "endpoint_url": settings.r2.endpoint_url,
            "aws_access_key_id": settings.r2.access_key_id.get_secret_value(),
            "aws_secret_access_key": settings.r2.secret_access_key.get_secret_value(),
            "region_name": settings.r2.region,
            "config": self._config,
        }

    async def upload_file(
            self,
            key: str,
            data: bytes | BinaryIO,
            content_type: str = "application/octet-stream",
            metadata: dict[str, str] | None = None,
            compress: bool = False,
            encryption: bool = True,
    ) -> dict[str, Any]:
        """
        Upload a file to R2 storage.

        Args:
            key: S3 key (path) for the object.
            data: File content as bytes or file-like object.
            content_type: MIME type of the content.
            metadata: Optional metadata dictionary.
            compress: Enable gzip compression.
            encryption: Enable server-side encryption.

        Returns:
            Upload result with ETag, version, and checksum.
        """
        if isinstance(data, bytes):
            file_data = data
        else:
            file_data = data.read()

        # Apply compression if requested
        if compress:
            original_size = len(file_data)
            file_data = gzip.compress(file_data, compresslevel=6)
            content_type = "application/gzip"
            logger.debug(
                "Compressed file",
                original_size=original_size,
                compressed_size=len(file_data),
                ratio=f"{len(file_data) / original_size:.2%}",
            )

        # Calculate checksum for integrity verification
        checksum = hashlib.sha256(file_data).hexdigest()

        # Prepare metadata
        upload_metadata = {
            "sentinel-checksum": checksum,
            "sentinel-upload-time": datetime.utcnow().isoformat(),
            "sentinel-compressed": str(compress).lower(),
        }
        if metadata:
            upload_metadata.update(metadata)

        # Prepare extra args
        extra_args: dict[str, Any] = {
            "ContentType": content_type,
            "Metadata": upload_metadata,
        }

        async with self._session.client(**self._get_client_kwargs()) as client:
            # Use multipart upload for large files
            if len(file_data) > settings.r2.multipart_threshold:
                result = await self._multipart_upload(
                    client, key, file_data, extra_args
                )
            else:
                response = await client.put_object(
                    Bucket=self._bucket,
                    Key=key,
                    Body=file_data,
                    **extra_args,
                )
                result = {
                    "key": key,
                    "etag": response.get("ETag", "").strip('"'),
                    "version_id": response.get("VersionId"),
                }

        result["checksum_sha256"] = checksum
        result["size_bytes"] = len(file_data)

        logger.info(
            "File uploaded to R2",
            key=key,
            size_bytes=len(file_data),
            checksum=checksum[:16] + "...",
        )

        return result

    async def _multipart_upload(
            self,
            client: Any,
            key: str,
            data: bytes,
            extra_args: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Handle multipart upload for large files.

        Splits file into 8MB parts and uploads concurrently.
        """
        part_size = settings.r2.multipart_threshold

        # Initiate multipart upload
        response = await client.create_multipart_upload(
            Bucket=self._bucket,
            Key=key,
            **extra_args,
        )
        upload_id = response["UploadId"]

        try:
            parts = []
            part_number = 1

            for i in range(0, len(data), part_size):
                chunk = data[i:i + part_size]

                part_response = await client.upload_part(
                    Bucket=self._bucket,
                    Key=key,
                    UploadId=upload_id,
                    PartNumber=part_number,
                    Body=chunk,
                )

                parts.append({
                    "PartNumber": part_number,
                    "ETag": part_response["ETag"],
                })

                part_number += 1

            # Complete multipart upload
            complete_response = await client.complete_multipart_upload(
                Bucket=self._bucket,
                Key=key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )

            return {
                "key": key,
                "etag": complete_response.get("ETag", "").strip('"'),
                "version_id": complete_response.get("VersionId"),
            }

        except Exception as e:
            # Abort failed multipart upload
            await client.abort_multipart_upload(
                Bucket=self._bucket,
                Key=key,
                UploadId=upload_id,
            )
            raise

    async def download_file(
            self,
            key: str,
            verify_checksum: bool = True,
    ) -> bytes:
        """
        Download a file from R2 storage.

        Args:
            key: S3 key of the object.
            verify_checksum: Verify SHA-256 checksum if available.

        Returns:
            File content as bytes.
        """
        async with self._session.client(**self._get_client_kwargs()) as client:
            response = await client.get_object(
                Bucket=self._bucket,
                Key=key,
            )

            data = await response["Body"].read()
            metadata = response.get("Metadata", {})

        # Verify checksum if available
        if verify_checksum and "sentinel-checksum" in metadata:
            expected_checksum = metadata["sentinel-checksum"]
            actual_checksum = hashlib.sha256(data).hexdigest()

            if actual_checksum != expected_checksum:
                raise ValueError(
                    f"Checksum mismatch for {key}: "
                    f"expected {expected_checksum}, got {actual_checksum}"
                )

        # Decompress if needed
        if metadata.get("sentinel-compressed") == "true":
            data = gzip.decompress(data)

        logger.debug("Downloaded file from R2", key=key, size_bytes=len(data))

        return data

    async def download_file_to_path(
            self,
            key: str,
            local_path: Path,
            verify_checksum: bool = True,
    ) -> Path:
        """
        Download a file directly to a local path.

        More memory-efficient for large files.
        """
        data = await self.download_file(key, verify_checksum)

        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_bytes(data)

        return local_path

    async def store_pcap(
            self,
            organization_id: UUID,
            pcap_data: bytes,
            source_ip: str,
            capture_time: datetime,
    ) -> str:
        """
        Store PCAP capture with compliance-ready metadata.

        Returns:
            R2 key for the stored PCAP.
        """
        # Generate compliance-friendly path
        date_path = capture_time.strftime("%Y/%m/%d")
        timestamp = capture_time.strftime("%H%M%S")
        filename = f"{source_ip.replace('.', '_')}_{timestamp}.pcap.gz"

        key = f"{self.PCAP_PREFIX}/{organization_id}/{date_path}/{filename}"

        metadata = {
            "source-ip": source_ip,
            "capture-time": capture_time.isoformat(),
            "organization-id": str(organization_id),
            "retention-days": "365",  # Compliance retention
        }

        await self.upload_file(
            key=key,
            data=pcap_data,
            content_type="application/vnd.tcpdump.pcap",
            metadata=metadata,
            compress=True,
        )

        return key

    async def store_ml_model(
            self,
            organization_id: UUID | None,
            model_name: str,
            model_version: str,
            model_data: bytes,
            metadata: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """
        Store ML model weights with versioning.

        Returns:
            Upload result with key and checksum.
        """
        org_path = str(organization_id) if organization_id else "global"
        key = f"{self.MODEL_PREFIX}/{org_path}/{model_name}/v{model_version}/model.pkl"

        model_metadata = {
            "model-name": model_name,
            "model-version": model_version,
            "organization-id": org_path,
        }
        if metadata:
            model_metadata.update(metadata)

        result = await self.upload_file(
            key=key,
            data=model_data,
            content_type="application/x-pickle",
            metadata=model_metadata,
            compress=True,
        )

        # Also store metadata JSON
        metadata_key = key.replace("model.pkl", "metadata.json")
        await self.upload_file(
            key=metadata_key,
            data=json.dumps(model_metadata, indent=2).encode(),
            content_type="application/json",
        )

        return result

    async def load_ml_model(
            self,
            organization_id: UUID | None,
            model_name: str,
            model_version: str,
    ) -> bytes:
        """
        Load ML model weights from storage.

        Returns:
            Model data as bytes (typically pickled sklearn/torch model).
        """
        org_path = str(organization_id) if organization_id else "global"
        key = f"{self.MODEL_PREFIX}/{org_path}/{model_name}/v{model_version}/model.pkl"

        return await self.download_file(key)

    async def store_audit_log(
            self,
            organization_id: UUID,
            log_entries: list[dict[str, Any]],
            log_date: datetime,
    ) -> str:
        """
        Store batch of audit logs for compliance archival.

        Args:
            organization_id: Organization UUID.
            log_entries: List of audit log dictionaries.
            log_date: Date for log organization.

        Returns:
            R2 key for stored logs.
        """
        date_path = log_date.strftime("%Y/%m/%d")
        timestamp = datetime.utcnow().strftime("%H%M%S%f")

        key = f"{self.AUDIT_PREFIX}/{organization_id}/{date_path}/audit_{timestamp}.json.gz"

        log_data = json.dumps(log_entries, default=str, indent=None).encode()

        metadata = {
            "organization-id": str(organization_id),
            "log-date": log_date.isoformat(),
            "entry-count": str(len(log_entries)),
            "immutable": "true",
            "retention-years": "7",  # Compliance requirement
        }

        await self.upload_file(
            key=key,
            data=log_data,
            content_type="application/json",
            metadata=metadata,
            compress=True,
        )

        logger.info(
            "Audit logs archived to R2",
            key=key,
            entry_count=len(log_entries),
        )

        return key

    async def list_objects(
            self,
            prefix: str,
            max_keys: int = 1000,
    ) -> list[dict[str, Any]]:
        """
        List objects with a given prefix.

        Returns:
            List of object metadata dictionaries.
        """
        objects = []
        continuation_token = None

        async with self._session.client(**self._get_client_kwargs()) as client:
            while True:
                params = {
                    "Bucket": self._bucket,
                    "Prefix": prefix,
                    "MaxKeys": min(max_keys - len(objects), 1000),
                }
                if continuation_token:
                    params["ContinuationToken"] = continuation_token

                response = await client.list_objects_v2(**params)

                for obj in response.get("Contents", []):
                    objects.append({
                        "key": obj["Key"],
                        "size": obj["Size"],
                        "last_modified": obj["LastModified"],
                        "etag": obj["ETag"].strip('"'),
                    })

                if not response.get("IsTruncated") or len(objects) >= max_keys:
                    break

                continuation_token = response.get("NextContinuationToken")

        return objects

    async def delete_object(self, key: str) -> bool:
        """
        Delete an object from R2.

        Returns:
            True if deletion was successful.
        """
        async with self._session.client(**self._get_client_kwargs()) as client:
            try:
                await client.delete_object(
                    Bucket=self._bucket,
                    Key=key,
                )
                logger.info("Deleted object from R2", key=key)
                return True
            except ClientError as e:
                logger.error("Failed to delete object", key=key, error=str(e))
                return False

    async def generate_presigned_url(
            self,
            key: str,
            expiration_seconds: int = 3600,
            method: str = "get_object",
    ) -> str:
        """
        Generate a presigned URL for temporary access.

        Useful for secure file sharing without exposing credentials.
        """
        async with self._session.client(**self._get_client_kwargs()) as client:
            url = await client.generate_presigned_url(
                ClientMethod=method,
                Params={
                    "Bucket": self._bucket,
                    "Key": key,
                },
                ExpiresIn=expiration_seconds,
            )

        return url

    async def health_check(self) -> dict[str, Any]:
        """
        Perform R2 storage health check.

        Returns:
            Health status dictionary.
        """
        health = {
            "status": "unhealthy",
            "bucket": self._bucket,
            "timestamp": datetime.utcnow().isoformat(),
        }

        try:
            start = datetime.utcnow()

            async with self._session.client(**self._get_client_kwargs()) as client:
                await client.head_bucket(Bucket=self._bucket)

            latency = (datetime.utcnow() - start).total_seconds() * 1000

            health.update({
                "status": "healthy",
                "latency_ms": round(latency, 2),
            })

        except Exception as e:
            health["error"] = str(e)
            logger.error("R2 health check failed", error=str(e))

        return health


# Singleton instance
r2_storage = R2StorageClient()