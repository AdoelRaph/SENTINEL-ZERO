"""
Sentinel-Zero Network Cartographer - WINDOWS FIXED

Async network scanner with proper Windows nmap path handling.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import nmap
from scapy.all import ARP, Ether, IP, TCP, UDP, sr1, srp, conf

from config import get_settings
from database.connection import db
from utils.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()

# Suppress scapy warnings
conf.verb = 0


@dataclass
class DiscoveredAsset:
    """Represents a discovered network asset."""

    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    os_accuracy: int = 0
    open_ports: list[int] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    is_server: bool = False
    discovery_method: str = "network_scan"
    raw_scan_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Complete scan operation result."""

    scan_id: UUID
    organization_id: UUID
    scan_type: str
    target_specification: str
    started_at: datetime
    completed_at: datetime | None = None
    assets_discovered: int = 0
    assets_updated: int = 0
    vulnerabilities_found: int = 0
    errors: list[str] = field(default_factory=list)
    discovered_assets: list[DiscoveredAsset] = field(default_factory=list)


class NetworkScanner:
    """
    Enterprise network scanner with Windows compatibility.

    Features:
    - ARP discovery for local network mapping
    - TCP SYN scanning for port discovery
    - Service version detection
    - OS fingerprinting
    - Proper Windows nmap path handling
    - Rate limiting to avoid network disruption
    """

    # Common server ports that indicate server role
    SERVER_PORTS = {
        22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
        1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
    }

    # Version patterns for outdated software detection
    OUTDATED_PATTERNS = {
        "openssh": r"OpenSSH[_\s]([0-7]\.[0-9])",
        "apache": r"Apache/([12]\.[0-4])",
        "nginx": r"nginx/([01]\.[0-9]|1\.[0-1][0-7])",
        "mysql": r"MySQL.*([0-4]\.|5\.[0-6])",
        "postgresql": r"PostgreSQL.*([0-9]\.|1[0-2]\.)",
    }

    def __init__(self):
        """Initialize scanner with proper nmap path handling."""
        self._nmap_scanner = None
        self._nmap_path = self._get_nmap_path()
        self._scan_semaphore = asyncio.Semaphore(settings.scanner.max_concurrent)
        self._active_scans: dict[UUID, ScanResult] = {}

        # Initialize nmap scanner if path found
        if self._nmap_path:
            try:
                self._nmap_scanner = nmap.PortScanner()
                logger.info(f"nmap initialized at: {self._nmap_path}")
            except Exception as e:
                logger.warning(f"Failed to initialize nmap: {e}")
                self._nmap_scanner = None
        else:
            logger.warning("nmap not found in system PATH or configured path")

    def _get_nmap_path(self) -> str | None:
        """
        Get nmap path from config or system PATH.

        Returns:
            Path to nmap executable or None if not found.
        """
        # First try configured path
        configured_path = settings.scanner.nmap_path
        if configured_path and Path(configured_path).exists():
            logger.info(f"Using configured nmap path: {configured_path}")
            return str(configured_path)

        # Try common Windows paths
        windows_paths = [
            Path("C:/Program Files/Nmap/nmap.exe"),
            Path("C:/Program Files (x86)/Nmap/nmap.exe"),
            Path(os.path.expanduser("~")) / "AppData/Local/nmap/nmap.exe",
        ]

        for path in windows_paths:
            if path.exists():
                logger.info(f"Found nmap at: {path}")
                return str(path)

        # Try searching in PATH environment variable
        path_env = os.getenv("PATH", "")
        for path_dir in path_env.split(os.pathsep):
            nmap_exe = Path(path_dir) / "nmap.exe"
            if nmap_exe.exists():
                logger.info(f"Found nmap in PATH: {nmap_exe}")
                return str(nmap_exe)

        # Last resort: try 'where nmap' command
        try:
            result = subprocess.run(
                ["where", "nmap"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                nmap_path = result.stdout.strip().split('\n')[0]
                if Path(nmap_path).exists():
                    logger.info(f"Found nmap via 'where' command: {nmap_path}")
                    return nmap_path
        except Exception as e:
            logger.debug(f"'where nmap' command failed: {e}")

        logger.warning("nmap executable not found")
        return None

    async def discover_network(
            self,
            organization_id: UUID,
            target: str,
            scan_type: str = "quick",
    ) -> ScanResult:
        """
        Discover all devices on the target network.

        Args:
            organization_id: Organization UUID for asset tracking.
            target: CIDR notation (e.g., "192.168.1.0/24") or IP range.
            scan_type: "quick", "standard", or "comprehensive".

        Returns:
            ScanResult with discovered assets.
        """
        import uuid
        scan_id = uuid.uuid4()

        result = ScanResult(
            scan_id=scan_id,
            organization_id=organization_id,
            scan_type=scan_type,
            target_specification=target,
            started_at=datetime.utcnow(),
        )

        self._active_scans[scan_id] = result

        logger.info(
            "Starting network discovery",
            scan_id=str(scan_id),
            target=target,
            scan_type=scan_type,
        )

        if not self._nmap_scanner:
            error_msg = "nmap not available - cannot perform network scan"
            logger.error(error_msg)
            result.errors.append(error_msg)
            result.completed_at = datetime.utcnow()
            return result

        try:
            # Phase 1: ARP Discovery (fast, local network only)
            live_hosts = await self._arp_discovery(target)

            logger.info(
                "ARP discovery complete",
                hosts_found=len(live_hosts),
            )

            # Phase 2: Port scanning based on scan type
            if scan_type == "quick":
                ports = settings.scanner.quick_scan_ports
            elif scan_type == "comprehensive":
                ports = settings.scanner.full_scan_ports
            else:
                ports = settings.scanner.quick_scan_ports

            # Scan each host concurrently
            tasks = [
                self._scan_host(host, ports, scan_type)
                for host in live_hosts
            ]

            discovered = await asyncio.gather(*tasks, return_exceptions=True)

            for item in discovered:
                if isinstance(item, Exception):
                    result.errors.append(str(item))
                elif item:
                    result.discovered_assets.append(item)

            # Phase 3: Store in database
            stored = await self._store_assets(organization_id, result.discovered_assets)
            result.assets_discovered = stored["new"]
            result.assets_updated = stored["updated"]

            # Phase 4: Correlate vulnerabilities
            vuln_count = await self._correlate_vulnerabilities(
                organization_id,
                result.discovered_assets,
            )
            result.vulnerabilities_found = vuln_count

            result.completed_at = datetime.utcnow()

            logger.info(
                "Network discovery complete",
                scan_id=str(scan_id),
                assets_discovered=result.assets_discovered,
                assets_updated=result.assets_updated,
                vulnerabilities_found=result.vulnerabilities_found,
            )

        except Exception as e:
            result.errors.append(str(e))
            logger.error("Network scan failed", scan_id=str(scan_id), error=str(e))

        finally:
            del self._active_scans[scan_id]
            await self._store_scan_job(result)

        return result

    async def _arp_discovery(self, target: str) -> list[str]:
        """
        Perform ARP discovery to find live hosts.

        Uses scapy for raw ARP requests.
        """
        loop = asyncio.get_event_loop()

        def _do_arp():
            try:
                arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
                answered, _ = srp(
                    arp_request,
                    timeout=settings.scanner.timeout_seconds,
                    verbose=False,
                )

                return [
                    received.psrc
                    for sent, received in answered
                ]
            except Exception as e:
                logger.error("ARP discovery error", error=str(e))
                return []

        return await loop.run_in_executor(None, _do_arp)

    async def _scan_host(
            self,
            ip_address: str,
            ports: str,
            scan_type: str,
    ) -> DiscoveredAsset | None:
        """
        Perform detailed scan of a single host.

        Uses nmap for port scanning and OS detection.
        """
        if not self._nmap_scanner:
            return None

        async with self._scan_semaphore:
            loop = asyncio.get_event_loop()

            def _do_nmap_scan():
                try:
                    # Build nmap arguments based on scan type
                    args = "-sV"  # Version detection

                    if scan_type == "comprehensive":
                        args += " -O -A"  # OS detection + aggressive
                    elif scan_type == "standard":
                        args += " -O"  # OS detection

                    self._nmap_scanner.scan(
                        ip_address,
                        ports,
                        arguments=args,
                        timeout=settings.scanner.timeout_seconds,
                    )

                    if ip_address not in self._nmap_scanner.all_hosts():
                        return None

                    host_data = self._nmap_scanner[ip_address]

                    # Parse results
                    asset = DiscoveredAsset(
                        ip_address=ip_address,
                        raw_scan_data=dict(host_data),
                    )

                    # Extract MAC address
                    if "mac" in host_data.get("addresses", {}):
                        asset.mac_address = host_data["addresses"]["mac"]

                    # Extract hostname
                    hostnames = host_data.get("hostnames", [])
                    if hostnames:
                        asset.hostname = hostnames[0].get("name")

                    # Extract OS information
                    if "osmatch" in host_data:
                        os_matches = host_data["osmatch"]
                        if os_matches:
                            best_match = os_matches[0]
                            asset.os_family = best_match.get("osclass", [{}])[0].get("osfamily") if best_match.get(
                                "osclass") else None
                            asset.os_version = best_match.get("name")
                            asset.os_accuracy = int(best_match.get("accuracy", 0))

                    # Extract open ports and services
                    for proto in ["tcp", "udp"]:
                        if proto in host_data:
                            for port, port_data in host_data[proto].items():
                                if port_data.get("state") == "open":
                                    asset.open_ports.append(port)
                                    asset.services.append({
                                        "port": port,
                                        "protocol": proto,
                                        "service": port_data.get("name"),
                                        "product": port_data.get("product"),
                                        "version": port_data.get("version"),
                                        "extrainfo": port_data.get("extrainfo"),
                                    })

                    # Determine if server based on open ports
                    asset.is_server = bool(
                        set(asset.open_ports) & self.SERVER_PORTS
                    )

                    return asset

                except Exception as e:
                    logger.warning(
                        "Host scan failed",
                        ip=ip_address,
                        error=str(e),
                    )
                    return None

            return await loop.run_in_executor(None, _do_nmap_scan)

    async def _store_assets(
            self,
            organization_id: UUID,
            assets: list[DiscoveredAsset],
    ) -> dict[str, int]:
        """Store discovered assets in database."""
        new_count = 0
        updated_count = 0

        async with db.raw_connection() as conn:
            for asset in assets:
                # Check if exists
                existing = await conn.fetchval("""
                                               SELECT id
                                               FROM assets
                                               WHERE organization_id = $1
                                                 AND ip_address = $2::inet
                                               """, organization_id, asset.ip_address)

                if existing:
                    # Update existing asset
                    await conn.execute("""
                                       UPDATE assets
                                       SET mac_address  = COALESCE($3::macaddr, mac_address),
                                           hostname     = COALESCE($4, hostname),
                                           os_family    = COALESCE($5, os_family),
                                           os_version   = COALESCE($6, os_version),
                                           is_server    = $7,
                                           open_ports   = $8,
                                           services     = $9,
                                           last_seen_at = NOW(),
                                           status       = 'active',
                                           updated_at   = NOW()
                                       WHERE organization_id = $1
                                         AND ip_address = $2::inet
                                       """,
                                       organization_id,
                                       asset.ip_address,
                                       asset.mac_address,
                                       asset.hostname,
                                       asset.os_family,
                                       asset.os_version,
                                       asset.is_server,
                                       asset.open_ports,
                                       asset.services,
                                       )
                    updated_count += 1
                else:
                    # Insert new asset
                    await conn.execute("""
                                       INSERT INTO assets (organization_id, ip_address, mac_address, hostname,
                                                           os_family, os_version, is_server, open_ports,
                                                           services, discovery_method)
                                       VALUES ($1, $2::inet, $3::macaddr, $4, $5, $6, $7, $8, $9, $10)
                                       """,
                                       organization_id,
                                       asset.ip_address,
                                       asset.mac_address,
                                       asset.hostname,
                                       asset.os_family,
                                       asset.os_version,
                                       asset.is_server,
                                       asset.open_ports,
                                       asset.services,
                                       asset.discovery_method,
                                       )
                    new_count += 1

        return {"new": new_count, "updated": updated_count}

    async def _correlate_vulnerabilities(
            self,
            organization_id: UUID,
            assets: list[DiscoveredAsset],
    ) -> int:
        """
        Correlate discovered assets with known vulnerabilities.

        Checks for outdated software and known CVEs.
        """
        vuln_count = 0

        async with db.raw_connection() as conn:
            for asset in assets:
                for service in asset.services:
                    product = service.get("product", "").lower()
                    version = service.get("version", "")

                    if not product or not version:
                        continue

                    # Check for outdated patterns
                    is_outdated = False
                    for software, pattern in self.OUTDATED_PATTERNS.items():
                        if software in product:
                            full_string = f"{product} {version}"
                            if re.search(pattern, full_string, re.IGNORECASE):
                                is_outdated = True
                                break

                    if is_outdated:
                        # Find matching CVEs
                        matching_cves = await conn.fetch("""
                                                         SELECT id, cve_id, severity
                                                         FROM known_threats
                                                         WHERE $1 = ANY (SELECT jsonb_array_elements_text(cpe_matches))
                                                            OR description ILIKE '%' || $2 || '%'
                                                             LIMIT 10
                                                         """, product, product)

                        # Get asset ID
                        asset_id = await conn.fetchval("""
                                                       SELECT id
                                                       FROM assets
                                                       WHERE organization_id = $1
                                                         AND ip_address = $2::inet
                                                       """, organization_id, asset.ip_address)

                        if asset_id and matching_cves:
                            for cve in matching_cves:
                                # Insert vulnerability association
                                await conn.execute("""
                                                   INSERT INTO asset_vulnerabilities (organization_id, asset_id,
                                                                                      threat_id,
                                                                                      detected_by, detection_confidence,
                                                                                      affected_component,
                                                                                      installed_version)
                                                   VALUES ($1, $2, $3, $4, $5, $6,
                                                           $7) ON CONFLICT (asset_id, threat_id) DO NOTHING
                                                   """,
                                                   organization_id,
                                                   asset_id,
                                                   cve["id"],
                                                   "network_scan",
                                                   0.75,
                                                   product,
                                                   version,
                                                   )
                                vuln_count += 1

        return vuln_count

    async def _store_scan_job(self, result: ScanResult) -> None:
        """Store scan job record for auditing."""
        async with db.raw_connection() as conn:
            await conn.execute("""
                               INSERT INTO scan_jobs (id, organization_id, scan_type, target_specification,
                                                      status, started_at, completed_at, assets_discovered,
                                                      assets_updated, vulnerabilities_found, errors_encountered,
                                                      results_summary)
                               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                               """,
                               result.scan_id,
                               result.organization_id,
                               result.scan_type,
                               result.target_specification,
                               "completed" if result.completed_at else "failed",
                               result.started_at,
                               result.completed_at,
                               result.assets_discovered,
                               result.assets_updated,
                               result.vulnerabilities_found,
                               len(result.errors),
                               {
                                   "discovered_ips": [a.ip_address for a in result.discovered_assets],
                                   "errors": result.errors[:10],
                               },
                               )

    async def detect_suspicious_ports(
            self,
            organization_id: UUID,
    ) -> list[dict[str, Any]]:
        """
        Detect non-server assets with suspicious listening ports.

        Flags potential backdoors based on:
        - Non-server devices listening on ports > 1024
        - Unexpected services
        """
        async with db.raw_connection() as conn:
            suspicious = await conn.fetch("""
                                          SELECT id,
                                                 ip_address,
                                                 hostname,
                                                 open_ports,
                                                 services,
                                                 is_server,
                                                 asset_type
                                          FROM assets
                                          WHERE organization_id = $1
                                            AND is_server = FALSE
                                            AND array_length(open_ports, 1) > 0
                                            AND EXISTS (SELECT 1
                                                        FROM unnest(open_ports) AS p
                                                        WHERE p > $2)
                                            AND status = 'active'
                                          """, organization_id, settings.ml.suspicious_port_threshold)

            return [dict(row) for row in suspicious]

    def get_active_scans(self) -> list[dict[str, Any]]:
        """Get list of currently running scans."""
        return [
            {
                "scan_id": str(scan_id),
                "target": result.target_specification,
                "scan_type": result.scan_type,
                "started_at": result.started_at.isoformat(),
                "assets_found": len(result.discovered_assets),
            }
            for scan_id, result in self._active_scans.items()
        ]


# Module-level instance - gracefully handles missing nmap
network_scanner = NetworkScanner()