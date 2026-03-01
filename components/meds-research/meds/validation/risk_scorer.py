from typing import List, Dict, Any

class RiskFactor:
    def __init__(self, name: str, score: int, weight: float, reason: str):
        self.name = name
        self.score = score
        self.weight = weight
        self.weighted_score = score * weight
        self.reason = reason

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "score": self.score,
            "weight": self.weight,
            "weighted_score": self.weighted_score,
            "reason": self.reason
        }

class RiskScorer:
    def __init__(self):
        self.config_weight = 0.30
        self.policy_weight = 0.40
        self.version_weight = 0.20
        self.environment_weight = 0.10

    def calculate_risk_score(
        self,
        version: str,
        source_environment: str,
        target_environment: str,
        add_policies: List[str],
        remove_policies: List[str],
        max_allowed_score: int
    ) -> Dict[str, Any]:
        
        factors = [
            self._assess_config_complexity(version),
            self._assess_policy_changes(add_policies, remove_policies),
            self._assess_version_delta(version),
            self._assess_environment_transition(source_environment, target_environment)
        ]
        
        total_score = sum(f.weighted_score for f in factors)
        total_score = int(total_score)
        
        recommendation = self._generate_recommendation(total_score, max_allowed_score)
        
        return {
            "total_score": total_score,
            "max_allowed": max_allowed_score,
            "factors": [f.to_dict() for f in factors],
            "recommendation": recommendation
        }

    def _assess_config_complexity(self, version: str) -> RiskFactor:
        score = 50
        reason = "Standard version change"
        
        if "alpha" in version.lower():
            score = 90
            reason = "Alpha version detected (very high risk)"
        elif "beta" in version.lower():
            score = 70
            reason = "Beta version detected (high risk)"
        elif "rc" in version.lower():
            score = 60
            reason = "Release candidate version"
        elif self._is_major_version(version):
            score = 70
            reason = "Major version change detected (high complexity)"
        elif self._is_minor_version(version):
            score = 40
            reason = "Minor version change (moderate complexity)"
        else:
            score = 20
            reason = "Patch version change (low complexity)"
        
        return RiskFactor("configuration_complexity", score, self.config_weight, reason)

    def _assess_policy_changes(self, add_policies: List[str], remove_policies: List[str]) -> RiskFactor:
        total_changes = len(add_policies) + len(remove_policies)
        
        if total_changes == 0:
            score = 0
            reason = "No policy changes"
        elif total_changes <= 2:
            score = 30
            reason = f"{total_changes} policy changes (low risk)"
        elif total_changes <= 4:
            score = 60
            reason = f"{total_changes} policy changes (medium risk)"
        else:
            score = 90
            reason = f"{total_changes} policy changes (high risk)"
        
        return RiskFactor("policy_changes", score, self.policy_weight, reason)

    def _assess_version_delta(self, version: str) -> RiskFactor:
        score = 30
        reason = "Stable release version"
        
        if "alpha" in version.lower():
            score = 80
            reason = "Pre-release version (very high risk)"
        elif "beta" in version.lower():
            score = 70
            reason = "Pre-release version (high risk)"
        elif "rc" in version.lower():
            score = 50
            reason = "Release candidate version (medium risk)"
        
        return RiskFactor("version_delta", score, self.version_weight, reason)

    def _assess_environment_transition(self, source: str, target: str) -> RiskFactor:
        score = 20
        reason = "Standard environment progression"
        
        risk_matrix = {
            ("development", "staging"): (20, "Standard progression: development → staging"),
            ("staging", "production"): (30, "Standard progression: staging → production"),
            ("development", "production"): (90, "Skipping staging environment (very high risk)")
        }
        
        key = (source.lower(), target.lower())
        if key in risk_matrix:
            score, reason = risk_matrix[key]
        
        return RiskFactor("environment_transition", score, self.environment_weight, reason)

    def _generate_recommendation(self, score: int, max_allowed: int) -> str:
        if score > max_allowed:
            return f"REJECTED - Risk score {score} exceeds maximum {max_allowed}"
        elif score > max_allowed * 0.8:
            return "APPROVED - Elevated risk, manual review recommended"
        elif score > max_allowed * 0.6:
            return "APPROVED - Moderate risk, monitor closely"
        else:
            return "APPROVED - Low risk, safe to proceed"

    def _is_major_version(self, version: str) -> bool:
        return ".0.0" in version

    def _is_minor_version(self, version: str) -> bool:
        return ".0" in version and ".0.0" not in version
