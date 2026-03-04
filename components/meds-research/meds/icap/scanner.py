import hashlib
import os
import random
from datetime import datetime, timezone
from typing import Optional

import httpx
from pydantic import BaseModel

from meds.utils.logger import get_logger

logger = get_logger("meds.icap")

# When set, scanner calls the live policy-engine instead of simulating
POLICY_ENGINE_URL = os.getenv("POLICY_ENGINE_URL", "").rstrip("/")


class ICAPScanResult(BaseModel):
    threat_found: bool
    threat_type: Optional[str] = None
    coverage_score: int
    low_coverage_warning: bool
    scanned_at: str


class ICAPScanner:
    def scan(self, version: str, application_name: str) -> ICAPScanResult:
        if POLICY_ENGINE_URL:
            try:
                return self._remote_scan(version, application_name)
            except Exception as e:
                logger.warning(
                    "remote_icap_scan_failed",
                    error=str(e),
                    policy_engine_url=POLICY_ENGINE_URL,
                    fallback="simulation",
                )
        return self._simulated_scan(version, application_name)

    def _remote_scan(self, version: str, application_name: str) -> ICAPScanResult:
        """Call the policy-engine ICAP status endpoint for a real compliance check."""
        url = f"{POLICY_ENGINE_URL}/api/integration/icap/policy-status/{application_name}"
        response = httpx.get(url, timeout=5.0)
        response.raise_for_status()
        data = response.json()

        compliance_score: float = data.get("compliance_score", 1.0)
        policy_approved: bool = data.get("policy_approved", True)
        violations: int = data.get("violations", 0)

        coverage_score = int(compliance_score * 100)
        threat_found = not policy_approved or violations > 0
        threat_type = "policy_violation" if threat_found else None

        result = ICAPScanResult(
            threat_found=threat_found,
            threat_type=threat_type,
            coverage_score=coverage_score,
            low_coverage_warning=coverage_score < 75,
            scanned_at=datetime.now(timezone.utc).isoformat(),
        )

        logger.info(
            "icap_scan_complete",
            version=version,
            application_name=application_name,
            threat_found=threat_found,
            coverage_score=coverage_score,
            mode="remote",
        )
        return result

    def _simulated_scan(self, version: str, application_name: str) -> ICAPScanResult:
        """Deterministic simulation used when policy-engine is unreachable."""
        seed = int(hashlib.sha256(f"{version}:{application_name}".encode()).hexdigest(), 16)
        rng = random.Random(seed)

        version_lower = version.lower()

        if "alpha" in version_lower:
            threat_threshold = 0.40
            cov_lo, cov_hi = 60, 79
        elif "beta" in version_lower:
            threat_threshold = 0.25
            cov_lo, cov_hi = 70, 89
        elif "rc" in version_lower:
            threat_threshold = 0.10
            cov_lo, cov_hi = 80, 94
        else:
            threat_threshold = 0.05
            cov_lo, cov_hi = 85, 99

        threat_found = rng.random() < threat_threshold
        threat_type = rng.choice(["malware", "vulnerability", "suspicious_pattern"]) if threat_found else None
        coverage_score = rng.randint(cov_lo, cov_hi)
        low_coverage_warning = coverage_score < 75

        result = ICAPScanResult(
            threat_found=threat_found,
            threat_type=threat_type,
            coverage_score=coverage_score,
            low_coverage_warning=low_coverage_warning,
            scanned_at=datetime.now(timezone.utc).isoformat(),
        )

        logger.info(
            "icap_scan_complete",
            version=version,
            application_name=application_name,
            threat_found=threat_found,
            coverage_score=coverage_score,
            mode="simulated",
        )

        return result
