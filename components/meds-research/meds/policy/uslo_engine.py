from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from meds.policy.standards import POLICY_CATALOG


class PolicyEvolutionTracker:
    """
    Unified Security Lifecycle Orchestration (USLO) engine.

    Policy lifecycle per environment type:
      development → enforce mode  — violations block immediately, fast feedback loop
      staging     → audit mode    — violations logged as warnings, promotion proceeds
      production  → enforce mode  — violations hard-block, rollback recommended

    In audit mode, violations are recorded but do NOT block the promotion.
    In enforce mode, violations in the policy plan will cause the promotion to
    fail unless the caller explicitly overrides (e.g. emergency deploy).
    """

    ENV_POLICY_MODES: Dict[str, Dict[str, Any]] = {
        "development": {"mode": "enforce", "grace_period": "0h",  "auto_escalate": False},
        "staging":     {"mode": "audit",   "grace_period": "8h",  "auto_escalate": True},
        "production":  {"mode": "enforce", "grace_period": "0h",  "auto_escalate": False},
    }

    def plan_migration(self, promotion: Any, source_env: Any, target_env: Any) -> Dict[str, Any]:
        env_type = target_env.type
        mode_cfg = self.ENV_POLICY_MODES.get(
            env_type, {"mode": "enforce", "grace_period": "0h", "auto_escalate": False}
        )

        add_policies    = promotion.spec.policy_migration.add_policies
        remove_policies = promotion.spec.policy_migration.remove_policies

        changes    = []
        violations = []
        warnings   = []

        for policy_name in add_policies:
            result = self._apply_policy_addition(policy_name, target_env, mode_cfg)
            changes.append(result)
            if result.get("violation"):
                violations.append(result)

        for policy_name in remove_policies:
            result = self._apply_policy_removal(policy_name, target_env, mode_cfg)
            changes.append(result)
            if result.get("violation"):
                violations.append(result)

        # Check for required-but-missing policies
        missing_required = self._check_required_policies(target_env, add_policies)
        for mp in missing_required:
            warnings.append({
                "policy": mp,
                "warning": f"Required policy '{mp}' not in target environment and not being added",
            })

        # Determine effective compliance impact
        if violations and mode_cfg["mode"] == "enforce":
            compliance_impact = "BLOCKED"
            status = "violations_blocked"
        elif violations and mode_cfg["mode"] == "audit":
            compliance_impact = "WARNING"
            status = "violations_logged"
        elif warnings:
            compliance_impact = "ADVISORY"
            status = "missing_policies_warned"
        elif not changes:
            compliance_impact = "NONE"
            status = "no_policy_changes"
        else:
            compliance_impact = "LOW" if len(changes) <= 2 else "MEDIUM" if len(changes) <= 4 else "HIGH"
            status = "policies_applied"

        return {
            "target_environment": env_type,
            "effective_mode":     mode_cfg["mode"],
            "grace_period":       mode_cfg["grace_period"],
            "auto_escalate":      mode_cfg["auto_escalate"],
            "changes":            changes,
            "violations":         violations,
            "warnings":           warnings,
            "compliance_impact":  compliance_impact,
            "status":             status,
            "applied_at":         datetime.now(timezone.utc).isoformat(),
        }

    def get_effective_mode(self, environment_type: str) -> str:
        return self.ENV_POLICY_MODES.get(environment_type, {}).get("mode", "enforce")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _apply_policy_addition(self, policy_name: str, target_env: Any, mode_cfg: Dict) -> Dict[str, Any]:
        if policy_name not in POLICY_CATALOG:
            return {
                "policy":      policy_name,
                "action":      "add",
                "violation":   True,
                "severity":    "HIGH",
                "reason":      f"Policy '{policy_name}' not found in catalog",
                "mode":        mode_cfg["mode"],
            }

        policy   = POLICY_CATALOG[policy_name]
        env_type = target_env.type

        if policy_name in target_env.policies:
            return {
                "policy":    policy_name,
                "action":    "add",
                "violation": False,
                "note":      "Policy already active in target environment",
                "mode":      mode_cfg["mode"],
                "severity":  policy.severity,
            }

        # CRITICAL policies into production require staged rollout
        if env_type == "production" and policy.severity == "CRITICAL":
            violation = (mode_cfg["mode"] == "enforce")
            return {
                "policy":       policy_name,
                "action":       "add",
                "violation":    violation,
                "severity":     policy.severity,
                "reason":       "CRITICAL severity policy requires staged rollout via staging first",
                "mode":         mode_cfg["mode"],
                "grace_period": mode_cfg["grace_period"],
            }

        return {
            "policy":              policy_name,
            "action":              "add",
            "violation":           False,
            "mode":                mode_cfg["mode"],
            "grace_period":        mode_cfg["grace_period"],
            "severity":            policy.severity,
            "compliance_mappings": [str(k) for k in policy.compliance_mappings.keys()],
        }

    def _apply_policy_removal(self, policy_name: str, target_env: Any, mode_cfg: Dict) -> Dict[str, Any]:
        env_type = target_env.type
        # All removals in production are flagged as violations
        if env_type == "production":
            return {
                "policy":    policy_name,
                "action":    "remove",
                "violation": True,
                "severity":  "HIGH",
                "reason":    "Policy removal in production requires compliance review",
                "mode":      mode_cfg["mode"],
            }
        return {
            "policy":    policy_name,
            "action":    "remove",
            "violation": False,
            "mode":      mode_cfg["mode"],
            "note":      f"Policy removed in {env_type} — monitor compliance posture",
        }

    def _check_required_policies(self, target_env: Any, add_policies: List[str]) -> List[str]:
        env_type = target_env.type
        if env_type not in ("staging", "production"):
            return []
        required = [
            name for name, p in POLICY_CATALOG.items()
            if env_type in p.required_for
            and name not in target_env.policies
            and name not in add_policies
        ]
        return required[:3]
