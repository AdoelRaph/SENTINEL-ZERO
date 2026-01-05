"""
Sentinel-Zero Input Validation

Security-focused validators for:
- IP addresses and network ranges
- API inputs and parameters
- File uploads and content
- SQL injection prevention
- XSS prevention

Prevents common attack vectors and ensures data integrity.

Copyright (c) 2024 Sentinel Security Inc.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any
from uuid import UUID

from utils.logging import get_logger

logger = get_logger(__name__)


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


class SecurityValidator:
    """
    Comprehensive input validation for security operations.

    Prevents injection attacks, validates formats, and ensures
    data meets security requirements.
    """

    # Regex patterns
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )

    HOSTNAME_PATTERN = re.compile(
        r'^(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?'
        r'(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*$'
    )

    CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)

    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        r"(\bOR\b|\bAND\b).*?=.*?=",  # OR 1=1, AND 1=1
        r"UNION\s+SELECT",  # UNION SELECT
        r"DROP\s+TABLE",  # DROP TABLE
        r"DELETE\s+FROM",  # DELETE FROM
        r"INSERT\s+INTO",  # INSERT INTO
        r"UPDATE\s+\w+\s+SET",  # UPDATE ... SET
        r"--",  # SQL comments
        r"/\*.*?\*/",  # Multi-line comments
        r";\s*DROP",  # Command chaining
        r"xp_cmdshell",  # MSSQL command execution
    ]

    # XSS patterns
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",  # Script tags
        r"javascript:",  # Javascript protocol
        r"on\w+\s*=",  # Event handlers (onclick, onerror, etc)
        r"<iframe",  # Iframes
        r"<object",  # Object tags
        r"<embed",  # Embed tags
    ]

    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",  # Directory traversal
        r"\.\.\\"  # Windows traversal
        r"%2e%2e",  # URL encoded ..
        r"\.\.%2f",  # Mixed encoding
    ]

    @staticmethod
    def validate_ip_address(ip: str, allow_private: bool = True) -> str:
        """
        Validate and normalize an IP address.

        Args:
            ip: IP address string
            allow_private: Whether to allow private IP ranges

        Returns:
            Normalized IP address

        Raises:
            ValidationError: If IP is invalid
        """
        try:
            ip_obj = ipaddress.ip_address(ip)

            if not allow_private and ip_obj.is_private:
                raise ValidationError(f"Private IP addresses not allowed: {ip}")

            if ip_obj.is_loopback:
                raise ValidationError(f"Loopback addresses not allowed: {ip}")

            if ip_obj.is_multicast:
                raise ValidationError(f"Multicast addresses not allowed: {ip}")

            return str(ip_obj)

        except ValueError as e:
            raise ValidationError(f"Invalid IP address '{ip}': {e}")

    @staticmethod
    def validate_cidr_range(cidr: str, max_hosts: int | None = None) -> str:
        """
        Validate CIDR network notation.

        Args:
            cidr: CIDR notation (e.g., 192.168.1.0/24)
            max_hosts: Maximum allowed hosts in range

        Returns:
            Normalized CIDR notation

        Raises:
            ValidationError: If CIDR is invalid
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)

            if max_hosts and network.num_addresses > max_hosts:
                raise ValidationError(
                    f"Network range too large: {network.num_addresses} hosts "
                    f"(max: {max_hosts})"
                )

            return str(network)

        except ValueError as e:
            raise ValidationError(f"Invalid CIDR notation '{cidr}': {e}")

    @staticmethod
    def validate_port(port: int | str) -> int:
        """
        Validate TCP/UDP port number.

        Args:
            port: Port number (1-65535)

        Returns:
            Validated port as integer

        Raises:
            ValidationError: If port is invalid
        """
        try:
            port_int = int(port)

            if not 1 <= port_int <= 65535:
                raise ValidationError(f"Port must be 1-65535, got: {port_int}")

            return port_int

        except ValueError:
            raise ValidationError(f"Invalid port number: {port}")

    @staticmethod
    def validate_email(email: str) -> str:
        """
        Validate email address format.

        Args:
            email: Email address

        Returns:
            Normalized email (lowercase)

        Raises:
            ValidationError: If email is invalid
        """
        email = email.strip().lower()

        if not SecurityValidator.EMAIL_PATTERN.match(email):
            raise ValidationError(f"Invalid email format: {email}")

        if len(email) > 255:
            raise ValidationError("Email address too long (max 255 chars)")

        return email

    @staticmethod
    def validate_hostname(hostname: str) -> str:
        """
        Validate hostname format.

        Args:
            hostname: Hostname or FQDN

        Returns:
            Normalized hostname (lowercase)

        Raises:
            ValidationError: If hostname is invalid
        """
        hostname = hostname.strip().lower()

        if not SecurityValidator.HOSTNAME_PATTERN.match(hostname):
            raise ValidationError(f"Invalid hostname format: {hostname}")

        if len(hostname) > 255:
            raise ValidationError("Hostname too long (max 255 chars)")

        return hostname

    @staticmethod
    def validate_uuid(uuid_str: str) -> UUID:
        """
        Validate UUID format.

        Args:
            uuid_str: UUID string

        Returns:
            UUID object

        Raises:
            ValidationError: If UUID is invalid
        """
        try:
            return UUID(uuid_str)
        except ValueError:
            raise ValidationError(f"Invalid UUID format: {uuid_str}")

    @staticmethod
    def validate_cve_id(cve_id: str) -> str:
        """
        Validate CVE identifier format.

        Args:
            cve_id: CVE ID (e.g., CVE-2024-1234)

        Returns:
            Normalized CVE ID (uppercase)

        Raises:
            ValidationError: If CVE ID is invalid
        """
        cve_id = cve_id.strip().upper()

        if not SecurityValidator.CVE_PATTERN.match(cve_id):
            raise ValidationError(
                f"Invalid CVE ID format: {cve_id}. "
                "Expected format: CVE-YYYY-NNNN"
            )

        return cve_id

    @staticmethod
    def check_sql_injection(text: str, field_name: str = "input") -> None:
        """
        Check for SQL injection attempts.

        Args:
            text: Text to validate
            field_name: Name of field for error messages

        Raises:
            ValidationError: If SQL injection detected
        """
        text_upper = text.upper()

        for pattern in SecurityValidator.SQL_INJECTION_PATTERNS:
            if re.search(pattern, text_upper, re.IGNORECASE):
                logger.warning(
                    "SQL injection attempt detected",
                    field=field_name,
                    pattern=pattern,
                )
                raise ValidationError(
                    f"Potential SQL injection detected in {field_name}"
                )

    @staticmethod
    def check_xss(text: str, field_name: str = "input") -> None:
        """
        Check for XSS (Cross-Site Scripting) attempts.

        Args:
            text: Text to validate
            field_name: Name of field for error messages

        Raises:
            ValidationError: If XSS detected
        """
        text_lower = text.lower()

        for pattern in SecurityValidator.XSS_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                logger.warning(
                    "XSS attempt detected",
                    field=field_name,
                    pattern=pattern,
                )
                raise ValidationError(
                    f"Potential XSS attack detected in {field_name}"
                )

    @staticmethod
    def check_path_traversal(path: str) -> None:
        """
        Check for path traversal attempts.

        Args:
            path: File path to validate

        Raises:
            ValidationError: If path traversal detected
        """
        path_lower = path.lower()

        for pattern in SecurityValidator.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, path_lower):
                logger.warning(
                    "Path traversal attempt detected",
                    path=path,
                    pattern=pattern,
                )
                raise ValidationError("Potential path traversal attack detected")

    @staticmethod
    def sanitize_text(
            text: str,
            max_length: int | None = None,
            allow_html: bool = False,
    ) -> str:
        """
        Sanitize text input for safe storage/display.

        Args:
            text: Text to sanitize
            max_length: Maximum allowed length
            allow_html: Whether to preserve HTML (with sanitization)

        Returns:
            Sanitized text

        Raises:
            ValidationError: If text fails validation
        """
        # Check for attacks
        SecurityValidator.check_sql_injection(text)

        if not allow_html:
            SecurityValidator.check_xss(text)

        # Trim whitespace
        text = text.strip()

        # Check length
        if max_length and len(text) > max_length:
            raise ValidationError(
                f"Text too long: {len(text)} chars (max: {max_length})"
            )

        # Remove null bytes
        text = text.replace('\x00', '')

        # Normalize unicode
        import unicodedata
        text = unicodedata.normalize('NFKC', text)

        return text

    @staticmethod
    def validate_file_upload(
            filename: str,
            content: bytes,
            allowed_extensions: list[str] | None = None,
            max_size_mb: int = 100,
    ) -> tuple[str, bytes]:
        """
        Validate file upload for security.

        Args:
            filename: Original filename
            content: File content
            allowed_extensions: Allowed file extensions
            max_size_mb: Maximum file size in MB

        Returns:
            Tuple of (sanitized_filename, content)

        Raises:
            ValidationError: If file is invalid
        """
        # Check path traversal
        SecurityValidator.check_path_traversal(filename)

        # Sanitize filename
        safe_filename = Path(filename).name
        safe_filename = re.sub(r'[^\w\s.-]', '', safe_filename)

        # Check extension
        if allowed_extensions:
            ext = Path(safe_filename).suffix.lower()
            if ext not in allowed_extensions:
                raise ValidationError(
                    f"File type not allowed: {ext}. "
                    f"Allowed: {', '.join(allowed_extensions)}"
                )

        # Check size
        size_mb = len(content) / (1024 * 1024)
        if size_mb > max_size_mb:
            raise ValidationError(
                f"File too large: {size_mb:.2f}MB (max: {max_size_mb}MB)"
            )

        # Check for null bytes (possible exploit)
        if b'\x00' in content:
            raise ValidationError("File contains null bytes (potential exploit)")

        return safe_filename, content

    @staticmethod
    def validate_json_structure(
            data: dict[str, Any],
            required_fields: list[str],
            optional_fields: list[str] | None = None,
    ) -> None:
        """
        Validate JSON structure has required fields.

        Args:
            data: JSON data as dictionary
            required_fields: List of required field names
            optional_fields: List of optional field names

        Raises:
            ValidationError: If structure is invalid
        """
        if not isinstance(data, dict):
            raise ValidationError("Expected JSON object")

        # Check required fields
        missing = set(required_fields) - set(data.keys())
        if missing:
            raise ValidationError(f"Missing required fields: {', '.join(missing)}")

        # Check for unexpected fields
        allowed = set(required_fields)
        if optional_fields:
            allowed.update(optional_fields)

        unexpected = set(data.keys()) - allowed
        if unexpected:
            raise ValidationError(
                f"Unexpected fields: {', '.join(unexpected)}"
            )


# Convenience functions
def validate_ip(ip: str, allow_private: bool = True) -> str:
    """Validate IP address."""
    return SecurityValidator.validate_ip_address(ip, allow_private)


def validate_cidr(cidr: str) -> str:
    """Validate CIDR range."""
    return SecurityValidator.validate_cidr_range(cidr)


def validate_email(email: str) -> str:
    """Validate email address."""
    return SecurityValidator.validate_email(email)


def sanitize(text: str, max_length: int | None = None) -> str:
    """Sanitize text input."""
    return SecurityValidator.sanitize_text(text, max_length)


# Convenience exports
__all__ = [
    'SecurityValidator',
    'ValidationError',
    'validate_ip',
    'validate_cidr',
    'validate_email',
    'sanitize',
]