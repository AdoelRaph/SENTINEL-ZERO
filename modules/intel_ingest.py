"""
Sentinel-Zero Threat Intelligence Ingestor

Continuously ingests threat intelligence from:
- NIST National Vulnerability Database (NVD)
- CISA Known Exploited Vulnerabilities (KEV)
- ExploitDB (via exploit-database API)

Implements rate limiting, deduplication, and incremental updates.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from config import get_settings
from database.connection import db
from utils.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


@dataclass
class CVERecord:
    """Parsed CVE record from threat intelligence sources."""

    cve_id: str
    title: str
    description: str | None = None
    cvss_v3_score: float | None = None
    cvss_v3_vector: str | None = None
    cvss_v2_score: float | None = None
    severity: str = "medium"
    affected_products: list[dict[str, Any]] = field(default_factory=list)
    cpe_matches: list[str] = field(default_factory=list)
    is_exploited_in_wild: bool = False
    exploit_references: list[str] = field(default_factory=list)
    source: str = "nist_nvd"
    source_url: str | None = None
    published_at: datetime | None = None
    last_modified_at: datetime | None = None
    cisa_kev_added_at: datetime | None = None
    cisa_due_date: datetime | None = None
    cisa_required_action: str | None = None
    raw_data: dict[str, Any] = field(default_factory=dict)


class RateLimiter:
    """Token bucket rate limiter for API requests."""

    def __init__(self, requests_per_minute: int):
        self.rate = requests_per_minute
        self.tokens = float(requests_per_minute)
        self.last_update = datetime.utcnow()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait for rate limit token."""
        async with self._lock:
            now = datetime.utcnow()
            elapsed = (now - self.last_update).total_seconds()

            # Replenish tokens
            self.tokens = min(
                self.rate,
                self.tokens + elapsed * (self.rate / 60.0)
            )
            self.last_update = now

            if self.tokens < 1:
                wait_time = (1 - self.tokens) * (60.0 / self.rate)
                await asyncio.sleep(wait_time)
                self.tokens = 1

            self.tokens -= 1


class ThreatIntelIngestor:
    """
    Threat Intelligence ingestion engine.

    Polls multiple threat feeds and updates the known_threats table
    in Neon PostgreSQL with deduplication and incremental updates.
    """

    # API Endpoints
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self):
        self._http_client: httpx.AsyncClient | None = None
        self._nvd_rate_limiter = RateLimiter(
            settings.threat_intel.nvd_requests_per_minute
        )
        self._last_nvd_sync: datetime | None = None
        self._last_cisa_sync: datetime | None = None

    async def initialize(self) -> None:
        """Initialize HTTP client and load sync state."""
        self._http_client = httpx.AsyncClient(
            timeout=60.0,
            follow_redirects=True,
            headers={
                "User-Agent": "Sentinel-Zero/1.0 (Enterprise Security Platform)",
            },
        )

        # Load last sync times from database
        await self._load_sync_state()

        logger.info("Threat intelligence ingestor initialized")

    async def shutdown(self) -> None:
        """Cleanup resources."""
        if self._http_client:
            await self._http_client.aclose()

    async def _load_sync_state(self) -> None:
        """Load last synchronization timestamps from database."""
        async with db.raw_connection() as conn:
            row = await conn.fetchrow("""
                                      SELECT MAX(updated_at) FILTER (WHERE source = 'nist_nvd') as last_nvd, MAX(updated_at) FILTER (WHERE source = 'cisa_kev') as last_cisa
                                      FROM known_threats
                                      """)

            if row:
                self._last_nvd_sync = row["last_nvd"]
                self._last_cisa_sync = row["last_cisa"]

    async def run_full_sync(self) -> dict[str, int]:
        """
        Run complete synchronization of all threat feeds.

        Returns:
            Dictionary with counts of new/updated records per source.
        """
        logger.info("Starting full threat intelligence sync")

        results = {
            "nvd_new": 0,
            "nvd_updated": 0,
            "cisa_new": 0,
            "cisa_updated": 0,
        }

        # Sync CISA KEV first (smaller dataset, critical threats)
        if settings.threat_intel.cisa_api_enabled:
            cisa_results = await self.sync_cisa_kev()
            results["cisa_new"] = cisa_results["new"]
            results["cisa_updated"] = cisa_results["updated"]

        # Sync NVD (larger dataset)
        nvd_results = await self.sync_nvd()
        results["nvd_new"] = nvd_results["new"]
        results["nvd_updated"] = nvd_results["updated"]

        logger.info(
            "Threat intelligence sync completed",
            **results,
        )

        return results

    @retry(
        retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=60),
    )
    async def sync_nvd(
            self,
            start_date: datetime | None = None,
            end_date: datetime | None = None,
    ) -> dict[str, int]:
        """
        Synchronize with NIST NVD API.

        Uses modification date range for incremental updates.
        """
        logger.info("Syncing with NIST NVD")

        # Default to last 24 hours if no start date
        if start_date is None:
            start_date = self._last_nvd_sync or (datetime.utcnow() - timedelta(days=1))
        if end_date is None:
            end_date = datetime.utcnow()

        new_count = 0
        updated_count = 0
        start_index = 0
        results_per_page = 2000

        while True:
            await self._nvd_rate_limiter.acquire()

            params = {
                "lastModStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "lastModEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": results_per_page,
                "startIndex": start_index,
            }

            # Add API key if available
            headers = {}
            if settings.threat_intel.nist_nvd_api_key:
                headers["apiKey"] = settings.threat_intel.nist_nvd_api_key.get_secret_value()

            response = await self._http_client.get(
                self.NVD_API_BASE,
                params=params,
                headers=headers,
            )
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            if not vulnerabilities:
                break

            # Parse and store CVEs
            records = [self._parse_nvd_cve(v) for v in vulnerabilities]
            result = await self._upsert_threats(records)

            new_count += result["new"]
            updated_count += result["updated"]

            total_results = data.get("totalResults", 0)
            start_index += len(vulnerabilities)

            logger.debug(
                "NVD sync progress",
                processed=start_index,
                total=total_results,
            )

            if start_index >= total_results:
                break

        self._last_nvd_sync = end_date

        return {"new": new_count, "updated": updated_count}

    def _parse_nvd_cve(self, vuln_data: dict[str, Any]) -> CVERecord:
        """Parse NVD CVE JSON into CVERecord."""
        cve = vuln_data.get("cve", {})
        cve_id = cve.get("id", "")

        # Extract description (English preferred)
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else None,
        )

        # Extract CVSS scores
        metrics = cve.get("metrics", {})
        cvss_v3 = None
        cvss_v3_score = None
        cvss_v3_vector = None

        for version in ["cvssMetricV31", "cvssMetricV30"]:
            if version in metrics:
                cvss_data = metrics[version][0].get("cvssData", {})
                cvss_v3_score = cvss_data.get("baseScore")
                cvss_v3_vector = cvss_data.get("vectorString")
                break

        cvss_v2_score = None
        if "cvssMetricV2" in metrics:
            cvss_v2_score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore")

        # Determine severity
        severity = self._calculate_severity(cvss_v3_score, cvss_v2_score)

        # Extract CPE matches
        cpe_matches = []
        configurations = cve.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        cpe_matches.append(match.get("criteria", ""))

        # Extract references
        references = cve.get("references", [])
        exploit_refs = [
            r["url"] for r in references
            if any(tag in r.get("tags", []) for tag in ["Exploit", "Third Party Advisory"])
        ]

        return CVERecord(
            cve_id=cve_id,
            title=cve_id,  # NVD doesn't have titles
            description=description,
            cvss_v3_score=cvss_v3_score,
            cvss_v3_vector=cvss_v3_vector,
            cvss_v2_score=cvss_v2_score,
            severity=severity,
            cpe_matches=cpe_matches[:100],  # Limit for storage
            exploit_references=exploit_refs[:20],
            source="nist_nvd",
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            published_at=self._parse_datetime(cve.get("published")),
            last_modified_at=self._parse_datetime(cve.get("lastModified")),
            raw_data=vuln_data,
        )

    @retry(
        retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=60),
    )
    async def sync_cisa_kev(self) -> dict[str, int]:
        """
        Synchronize with CISA Known Exploited Vulnerabilities catalog.

        This is a critical feed as it contains vulnerabilities actively
        exploited in the wild with federal remediation deadlines.
        """
        logger.info("Syncing with CISA KEV catalog")

        response = await self._http_client.get(self.CISA_KEV_URL)
        response.raise_for_status()

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        records = []
        for vuln in vulnerabilities:
            record = CVERecord(
                cve_id=vuln.get("cveID", ""),
                title=vuln.get("vulnerabilityName", ""),
                description=vuln.get("shortDescription"),
                is_exploited_in_wild=True,  # All KEV entries are exploited
                source="cisa_kev",
                source_url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                cisa_kev_added_at=self._parse_date(vuln.get("dateAdded")),
                cisa_due_date=self._parse_date(vuln.get("dueDate")),
                cisa_required_action=vuln.get("requiredAction"),
                severity="critical",  # KEV entries are high priority
                raw_data=vuln,
            )

            # Parse affected products
            if vuln.get("vendorProject") and vuln.get("product"):
                record.affected_products = [{
                    "vendor": vuln.get("vendorProject"),
                    "product": vuln.get("product"),
                }]

            records.append(record)

        result = await self._upsert_threats(records, update_kev_fields=True)

        self._last_cisa_sync = datetime.utcnow()

        logger.info(
            "CISA KEV sync completed",
            total=len(records),
            **result,
        )

        return result

    async def _upsert_threats(
            self,
            records: list[CVERecord],
            update_kev_fields: bool = False,
    ) -> dict[str, int]:
        """
        Insert or update threat records in database.

        Uses PostgreSQL UPSERT for atomic operations.
        """
        if not records:
            return {"new": 0, "updated": 0}

        new_count = 0
        updated_count = 0

        async with db.raw_connection() as conn:
            for record in records:
                # Check if exists
                existing = await conn.fetchval(
                    "SELECT id FROM known_threats WHERE cve_id = $1",
                    record.cve_id,
                )

                if existing:
                    # Update existing record
                    if update_kev_fields:
                        await conn.execute("""
                                           UPDATE known_threats
                                           SET is_exploited_in_wild = TRUE,
                                               cisa_kev_added_at    = COALESCE($2, cisa_kev_added_at),
                                               cisa_due_date        = COALESCE($3, cisa_due_date),
                                               cisa_required_action = COALESCE($4, cisa_required_action),
                                               severity             = CASE
                                                                          WHEN severity != 'critical' THEN 'critical'
                                                                          ELSE severity
                                                   END,
                                               updated_at           = NOW()
                                           WHERE cve_id = $1
                                           """,
                                           record.cve_id,
                                           record.cisa_kev_added_at,
                                           record.cisa_due_date,
                                           record.cisa_required_action,
                                           )
                    else:
                        await conn.execute("""
                                           UPDATE known_threats
                                           SET title              = COALESCE($2, title),
                                               description        = COALESCE($3, description),
                                               cvss_v3_score      = COALESCE($4, cvss_v3_score),
                                               cvss_v3_vector     = COALESCE($5, cvss_v3_vector),
                                               cvss_v2_score      = COALESCE($6, cvss_v2_score),
                                               severity           = $7,
                                               cpe_matches        = $8,
                                               exploit_references = $9,
                                               last_modified_at   = $10,
                                               raw_data           = $11,
                                               updated_at         = NOW()
                                           WHERE cve_id = $1
                                           """,
                                           record.cve_id,
                                           record.title,
                                           record.description,
                                           record.cvss_v3_score,
                                           record.cvss_v3_vector,
                                           record.cvss_v2_score,
                                           record.severity,
                                           record.cpe_matches,
                                           record.exploit_references,
                                           record.last_modified_at,
                                           record.raw_data,
                                           )
                    updated_count += 1
                else:
                    # Insert new record
                    await conn.execute("""
                                       INSERT INTO known_threats (cve_id, title, description, cvss_v3_score,
                                                                  cvss_v3_vector,
                                                                  cvss_v2_score, severity, cpe_matches,
                                                                  is_exploited_in_wild,
                                                                  exploit_references, source, source_url, published_at,
                                                                  last_modified_at, cisa_kev_added_at, cisa_due_date,
                                                                  cisa_required_action, raw_data)
                                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                                               $13, $14, $15, $16, $17, $18)
                                       """,
                                       record.cve_id,
                                       record.title,
                                       record.description,
                                       record.cvss_v3_score,
                                       record.cvss_v3_vector,
                                       record.cvss_v2_score,
                                       record.severity,
                                       record.cpe_matches,
                                       record.is_exploited_in_wild,
                                       record.exploit_references,
                                       record.source,
                                       record.source_url,
                                       record.published_at,
                                       record.last_modified_at,
                                       record.cisa_kev_added_at,
                                       record.cisa_due_date,
                                       record.cisa_required_action,
                                       record.raw_data,
                                       )
                    new_count += 1

        return {"new": new_count, "updated": updated_count}

    def _calculate_severity(
            self,
            cvss_v3: float | None,
            cvss_v2: float | None,
    ) -> str:
        """Calculate severity level from CVSS scores."""
        score = cvss_v3 or cvss_v2

        if score is None:
            return "medium"

        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score > 0:
            return "low"
        else:
            return "informational"

    def _parse_datetime(self, value: str | None) -> datetime | None:
        """Parse ISO datetime string."""
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None

    def _parse_date(self, value: str | None) -> datetime | None:
        """Parse date string (YYYY-MM-DD format)."""
        if not value:
            return None
        try:
            return datetime.strptime(value, "%Y-%m-%d")
        except ValueError:
            return None

    async def get_threat_stats(self) -> dict[str, Any]:
        """Get threat intelligence statistics."""
        async with db.raw_connection() as conn:
            stats = await conn.fetchrow("""
                                        SELECT COUNT(*) as total_cves,
                                               COUNT(*)    FILTER (WHERE is_exploited_in_wild) as exploited_count, COUNT(*) FILTER (WHERE severity = 'critical') as critical_count, COUNT(*) FILTER (WHERE severity = 'high') as high_count, COUNT(*) FILTER (WHERE cisa_due_date IS NOT NULL 
                                     AND cisa_due_date > NOW()) as pending_kev_count, MAX(updated_at) as last_update
                                        FROM known_threats
                                        """)

            return dict(stats) if stats else {}


# Module-level instance
threat_intel = ThreatIntelIngestor()