import re
from typing import List, Dict, Any, Optional


class RiskFactor:
    def __init__(self, name: str, score: int, weight: float, reason: str):
        self.name = name
        self.score = score
        self.weight = weight
        self.weighted_score = round(score * weight, 2)
        self.reason = reason

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "score": self.score,
            "weight": self.weight,
            "weighted_score": self.weighted_score,
            "reason": self.reason,
        }


class RiskScorer:
    """
    6-factor weighted risk scorer for environment promotions.

    Factors and weights (sum = 1.00):
      config_complexity   0.20  — version maturity (alpha/beta/rc/major/minor/patch)
      policy_changes      0.25  — number and type of policy additions/removals
      version_delta       0.15  — semantic versioning distance analysis
      environment_trans   0.10  — validity and risk of the env transition
      icap_coverage       0.20  — ICAP scan coverage quality (lower = higher risk)
      compliance_posture  0.10  — policy-engine compliance score (lower = higher risk)
    """

    WEIGHTS = {
        "config_complexity":  0.20,
        "policy_changes":     0.25,
        "version_delta":      0.15,
        "environment_trans":  0.10,
        "icap_coverage":      0.20,
        "compliance_posture": 0.10,
    }

    # Enforced promotion order
    _ENV_ORDER = ["development", "staging", "production"]
    _VALID_TRANS = {
        "development": ["staging"],
        "staging":     ["production"],
        "production":  [],
    }

    def calculate_risk_score(
        self,
        version: str,
        source_environment: str,
        target_environment: str,
        add_policies: List[str],
        remove_policies: List[str],
        max_allowed_score: int,
        icap_coverage_score: Optional[int] = None,   # 0-100 from ICAP scanner
        compliance_score: Optional[float] = None,    # 0.0-1.0 from policy engine
    ) -> Dict[str, Any]:
        factors = [
            self._assess_config_complexity(version),
            self._assess_policy_changes(add_policies, remove_policies),
            self._assess_version_delta(version),
            self._assess_environment_transition(source_environment, target_environment),
            self._assess_icap_coverage(icap_coverage_score),
            self._assess_compliance_posture(compliance_score),
        ]
        total_score = int(sum(f.weighted_score for f in factors))
        recommendation = self._generate_recommendation(total_score, max_allowed_score)
        return {
            "total_score": total_score,
            "max_allowed": max_allowed_score,
            "factors": [f.to_dict() for f in factors],
            "recommendation": recommendation,
        }

    # ── Factor assessors ──────────────────────────────────────────────────────

    def _assess_config_complexity(self, version: str) -> RiskFactor:
        v = version.lower()
        if "alpha" in v:
            score, reason = 90, "Alpha pre-release — very high instability risk"
        elif "beta" in v:
            score, reason = 70, "Beta pre-release — high instability risk"
        elif "rc" in v:
            score, reason = 55, "Release candidate — moderate instability risk"
        elif self._is_major_bump(version):
            score, reason = 70, "Major version bump — breaking changes possible"
        elif self._is_minor_bump(version):
            score, reason = 35, "Minor version bump — additive changes, low breaking risk"
        else:
            score, reason = 15, "Patch version — bug fixes only, minimal risk"
        return RiskFactor("config_complexity", score, self.WEIGHTS["config_complexity"], reason)

    def _assess_policy_changes(self, add_policies: List[str], remove_policies: List[str]) -> RiskFactor:
        adds = len(add_policies)
        removes = len(remove_policies)
        total = adds + removes
        # Removals are higher risk than additions (loosening security posture)
        removal_penalty = removes * 15
        base_score = {0: 0, 1: 20, 2: 35}.get(total, min(90, 35 + (total - 2) * 15))
        score = min(100, base_score + removal_penalty)
        if total == 0:
            reason = "No policy changes — zero policy risk"
        else:
            parts = []
            if adds:
                parts.append(f"{adds} addition{'s' if adds > 1 else ''}")
            if removes:
                parts.append(f"{removes} removal{'s' if removes > 1 else ''} (+{removal_penalty} removal penalty)")
            level = "high" if score > 60 else "moderate" if score > 30 else "low"
            reason = f"{', '.join(parts)} — {level} policy risk"
        return RiskFactor("policy_changes", score, self.WEIGHTS["policy_changes"], reason)

    def _assess_version_delta(self, version: str) -> RiskFactor:
        v = version.lower()
        if "alpha" in v:
            score, reason = 80, "Pre-release: unstable API surface, no compatibility guarantee"
        elif "beta" in v:
            score, reason = 65, "Pre-release: feature-complete but not hardened"
        elif "rc" in v:
            score, reason = 45, "Release candidate: known-issue list may still change"
        elif self._is_major_bump(version):
            score, reason = 65, "Major bump: semantic versioning signals breaking changes"
        elif self._is_minor_bump(version):
            score, reason = 30, "Minor bump: additive changes, backwards-compatible"
        else:
            score, reason = 10, "Patch bump: targeted bug fixes, high confidence"
        return RiskFactor("version_delta", score, self.WEIGHTS["version_delta"], reason)

    def _assess_environment_transition(self, source: str, target: str) -> RiskFactor:
        allowed = self._VALID_TRANS.get(source.lower(), [])
        if target.lower() == source.lower():
            score, reason = 100, f"Same-environment promotion blocked: {source} → {target}"
        elif target.lower() not in allowed:
            try:
                si = self._ENV_ORDER.index(source.lower())
                ti = self._ENV_ORDER.index(target.lower())
                if ti < si:
                    score, reason = 100, f"Backward promotion blocked: {source} → {target}"
                else:
                    via = " → ".join(self._ENV_ORDER[si + 1: ti + 1])
                    score, reason = 100, f"Stage-skipping blocked: {source} → {target} (must pass through {via})"
            except ValueError:
                score, reason = 80, f"Unknown environment: {source} → {target}"
        elif source.lower() == "development" and target.lower() == "staging":
            score, reason = 15, "Standard promotion: development → staging"
        elif source.lower() == "staging" and target.lower() == "production":
            score, reason = 25, "Gate promotion: staging → production"
        else:
            score, reason = 20, f"Valid transition: {source} → {target}"
        return RiskFactor("environment_transition", score, self.WEIGHTS["environment_trans"], reason)

    def _assess_icap_coverage(self, coverage_score: Optional[int]) -> RiskFactor:
        if coverage_score is None:
            score, reason = 60, "ICAP coverage unknown — no scan data available"
        elif coverage_score >= 90:
            score, reason = 5, f"Excellent ICAP coverage ({coverage_score}/100)"
        elif coverage_score >= 80:
            score, reason = 20, f"Good ICAP coverage ({coverage_score}/100)"
        elif coverage_score >= 70:
            score, reason = 45, f"Moderate ICAP coverage ({coverage_score}/100) — low coverage warning"
        elif coverage_score >= 60:
            score, reason = 70, f"Poor ICAP coverage ({coverage_score}/100) — review scan config"
        else:
            score, reason = 90, f"Critical ICAP coverage gap ({coverage_score}/100)"
        return RiskFactor("icap_coverage", score, self.WEIGHTS["icap_coverage"], reason)

    def _assess_compliance_posture(self, compliance_score: Optional[float]) -> RiskFactor:
        if compliance_score is None:
            score, reason = 50, "Compliance posture unknown — policy engine unreachable"
        else:
            pct = int(compliance_score * 100)
            if pct >= 90:
                score, reason = 5, f"Strong compliance posture ({pct}% — all controls passing)"
            elif pct >= 75:
                score, reason = 25, f"Adequate compliance posture ({pct}% — minor gaps)"
            elif pct >= 60:
                score, reason = 55, f"Degraded compliance posture ({pct}% — policy violations present)"
            else:
                score, reason = 80, f"Critical compliance gap ({pct}% — significant violations)"
        return RiskFactor("compliance_posture", score, self.WEIGHTS["compliance_posture"], reason)

    # ── Recommendation ────────────────────────────────────────────────────────

    def _generate_recommendation(self, score: int, max_allowed: int) -> str:
        if score > max_allowed:
            return f"REJECTED — Risk score {score} exceeds maximum {max_allowed}"
        elif score > int(max_allowed * 0.75):
            return f"APPROVED (approval required) — Elevated risk ({score}/{max_allowed}), manual sign-off needed"
        elif score > int(max_allowed * 0.5):
            return f"APPROVED — Moderate risk ({score}/{max_allowed}), monitor closely"
        else:
            return f"APPROVED — Low risk ({score}/{max_allowed}), safe to auto-promote"

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _is_major_bump(self, version: str) -> bool:
        m = re.match(r"v?(\d+)\.(\d+)\.(\d+)", version)
        if m:
            return m.group(2) == "0" and m.group(3) == "0"
        return ".0.0" in version

    def _is_minor_bump(self, version: str) -> bool:
        m = re.match(r"v?(\d+)\.(\d+)\.(\d+)", version)
        if m:
            return m.group(3) == "0" and not (m.group(2) == "0" and m.group(3) == "0")
        return ".0" in version and ".0.0" not in version
