from typing import List, Dict, Any
from meds.policy.standards import POLICY_CATALOG

class PolicyEvolutionTracker:
    def __init__(self, version_store=None):
        self.version_store = version_store

    def plan_migration(self, promotion: Any, source_env: Any, target_env: Any) -> Dict[str, Any]:
        plan = {
            "changes": [],
            "compliance_impact": "",
            "missing_required_policies": []
        }
        
        add_policies = promotion.spec.policy_migration.add_policies
        
        for policy_name in add_policies:
            change = self._plan_policy_addition(policy_name, target_env)
            plan["changes"].append(change)
        
        if len(add_policies) == 0:
            plan["compliance_impact"] = "NONE - No policy changes"
        elif len(add_policies) <= 2:
            plan["compliance_impact"] = "LOW - Minor policy changes"
        elif len(add_policies) <= 4:
            plan["compliance_impact"] = "MEDIUM - Moderate policy changes"
        else:
            plan["compliance_impact"] = "HIGH - Significant policy changes"
        
        return plan

    def _plan_policy_addition(self, policy_name: str, target_env: Any) -> Dict[str, Any]:
        if policy_name not in POLICY_CATALOG:
            return {"policy": policy_name, "action": "add", "error": "Policy not found"}
        
        policy = POLICY_CATALOG[policy_name]
        env_type = target_env.type
        
        if env_type == "production":
            mode = "audit"
            grace_period = "48h"
        elif env_type == "staging":
            mode = "audit"
            grace_period = "8h"
        else:
            mode = "enforce"
            grace_period = "0h"
        
        return {
            "policy": policy_name,
            "action": "add",
            "mode": mode,
            "grace_period": grace_period,
            "severity": policy.severity
        }
