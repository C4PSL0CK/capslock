import hashlib
import random
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel

from meds.utils.logger import get_logger

logger = get_logger("meds.icap")


class ICAPScanResult(BaseModel):
    threat_found: bool
    threat_type: Optional[str] = None
    coverage_score: int
    low_coverage_warning: bool
    scanned_at: str


class ICAPScanner:
    def scan(self, version: str, application_name: str) -> ICAPScanResult:
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
        )

        return result
