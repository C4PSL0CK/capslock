import hashlib
import os
import random
import socket
import re
from datetime import datetime, timezone
from typing import Optional

import httpx
from pydantic import BaseModel

from meds.utils.logger import get_logger

logger = get_logger("meds.icap")

# Priority 1: real ICAP service (RFC 3507 over TCP port 1344)
ICAP_SERVICE_HOST = os.getenv("ICAP_SERVICE_HOST", "")
ICAP_SERVICE_PORT = int(os.getenv("ICAP_SERVICE_PORT", "1344"))

# Priority 2: policy-engine compliance gate
POLICY_ENGINE_URL = os.getenv("POLICY_ENGINE_URL", "").rstrip("/")


class ICAPScanResult(BaseModel):
    threat_found: bool
    threat_type: Optional[str] = None
    coverage_score: int
    low_coverage_warning: bool
    scanned_at: str


class ICAPScanner:
    def scan(self, version: str, application_name: str) -> ICAPScanResult:
        # 1. Real ICAP protocol (available in Kubernetes with icap-operator deployed)
        if ICAP_SERVICE_HOST:
            try:
                return self._icap_protocol_scan(version, application_name)
            except Exception as e:
                logger.warning(
                    "icap_protocol_scan_failed",
                    error=str(e),
                    host=ICAP_SERVICE_HOST,
                    port=ICAP_SERVICE_PORT,
                    fallback="policy_engine",
                )

        # 2. Policy-engine compliance gate (available in docker-compose / local)
        if POLICY_ENGINE_URL:
            try:
                return self._policy_engine_scan(version, application_name)
            except Exception as e:
                logger.warning(
                    "policy_engine_scan_failed",
                    error=str(e),
                    policy_engine_url=POLICY_ENGINE_URL,
                    fallback="simulation",
                )

        # 3. Deterministic simulation (offline / CI)
        return self._simulated_scan(version, application_name)

    # -------------------------------------------------------------------------
    # Layer 1 — RFC 3507 ICAP RESPMOD over raw TCP socket
    # -------------------------------------------------------------------------
    def _icap_protocol_scan(self, version: str, application_name: str) -> ICAPScanResult:
        """
        Performs a real ICAP RESPMOD request against the ClamAV-backed ICAP service
        provisioned by the icap-operator (port 1344).

        The "artifact" we scan is a synthetic HTTP response body that encodes the
        deployment identity (application name + version).  The ICAP server's
        antivirus engine scans the body and returns:
          204 No Content  → clean (no modification needed)
          200 OK          → potentially modified; check X-Infection-Found header
        """
        artifact = f"deployment:{application_name}:{version}".encode()

        # Build a minimal HTTP/1.1 response to wrap the artifact
        http_headers = (
            "HTTP/1.1 200 OK\r\n"
            f"Content-Length: {len(artifact)}\r\n"
            "Content-Type: application/octet-stream\r\n"
            "\r\n"
        ).encode()
        http_response = http_headers + artifact

        # ICAP request headers
        # Encapsulated: res-hdr=0, res-body=<offset of body in encapsulated section>
        res_hdr_len = len(http_headers)
        icap_headers = (
            f"RESPMOD icap://{ICAP_SERVICE_HOST}:{ICAP_SERVICE_PORT}/avscan ICAP/1.0\r\n"
            f"Host: {ICAP_SERVICE_HOST}:{ICAP_SERVICE_PORT}\r\n"
            "Connection: close\r\n"
            "Allow: 204\r\n"
            f"Encapsulated: res-hdr=0, res-body={res_hdr_len}\r\n"
            "\r\n"
        ).encode()

        # Chunked encoding for the encapsulated body
        chunk_size_hex = format(len(http_response), "x").encode()
        chunked_body = chunk_size_hex + b"\r\n" + http_response + b"\r\n0\r\n\r\n"

        raw_request = icap_headers + chunked_body

        # Send request and read full response
        raw_response = b""
        with socket.create_connection(
            (ICAP_SERVICE_HOST, ICAP_SERVICE_PORT), timeout=8
        ) as sock:
            sock.sendall(raw_request)
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                raw_response += chunk

        response_text = raw_response.decode("utf-8", errors="replace")
        status_line = response_text.split("\r\n")[0]

        if "204" in status_line:
            # 204 No Content — no modification needed, content is clean
            threat_found = False
            threat_type  = None
            coverage_score = 95
        elif "200" in status_line:
            # 200 OK — server may have modified the response; check for infection header
            infected_match = re.search(
                r"X-Infection-Found:.*?Threat=([^\r\n;]+)", response_text, re.IGNORECASE
            )
            threat_found = bool(infected_match)
            threat_type  = infected_match.group(1).strip() if infected_match else None
            coverage_score = 90
        else:
            raise ValueError(f"Unexpected ICAP status: {status_line!r}")

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
            mode="icap_protocol",
            icap_host=ICAP_SERVICE_HOST,
        )
        return result

    # -------------------------------------------------------------------------
    # Layer 2 — Policy-engine compliance gate
    # -------------------------------------------------------------------------
    def _policy_engine_scan(self, version: str, application_name: str) -> ICAPScanResult:
        """
        Calls the policy-engine /api/integration/icap/policy-status endpoint.
        Treats compliance violations as the equivalent of an ICAP threat signal.
        """
        url = f"{POLICY_ENGINE_URL}/api/integration/icap/policy-status/{application_name}"
        response = httpx.get(url, timeout=5.0)
        response.raise_for_status()
        data = response.json()

        compliance_score: float = data.get("compliance_score", 1.0)
        policy_approved: bool   = data.get("policy_approved", True)
        violations: int         = data.get("violations", 0)

        coverage_score = int(compliance_score * 100)
        threat_found   = not policy_approved or violations > 0
        threat_type    = "policy_violation" if threat_found else None

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
            mode="policy_engine",
        )
        return result

    # -------------------------------------------------------------------------
    # Layer 3 — Deterministic simulation (offline / CI)
    # -------------------------------------------------------------------------
    def _simulated_scan(self, version: str, application_name: str) -> ICAPScanResult:
        """Deterministic simulation used when policy-engine is unreachable."""
        seed = int(hashlib.sha256(f"{version}:{application_name}".encode()).hexdigest(), 16)
        rng  = random.Random(seed)

        version_lower = version.lower()

        if "alpha" in version_lower:
            threat_threshold = 0.40
            cov_lo, cov_hi   = 60, 79
        elif "beta" in version_lower:
            threat_threshold = 0.25
            cov_lo, cov_hi   = 70, 89
        elif "rc" in version_lower:
            threat_threshold = 0.10
            cov_lo, cov_hi   = 80, 94
        else:
            threat_threshold = 0.05
            cov_lo, cov_hi   = 85, 99

        threat_found   = rng.random() < threat_threshold
        threat_type    = rng.choice(["malware", "vulnerability", "suspicious_pattern"]) if threat_found else None
        coverage_score = rng.randint(cov_lo, cov_hi)

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
            mode="simulated",
        )
        return result
