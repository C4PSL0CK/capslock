from typing import Dict, Any
from meds.models.promotion import Promotion, Environment
from meds.validation.risk_scorer import RiskScorer
from meds.policy.uslo_engine import PolicyEvolutionTracker

class PromotionController:
    def __init__(self):
        self.risk_scorer = RiskScorer()
        self.uslo_engine = PolicyEvolutionTracker()

    def process_promotion(self, promotion: Promotion, source_env: Environment, target_env: Environment) -> Dict[str, Any]:
        risk_result = self.risk_scorer.calculate_risk_score(
            version=promotion.spec.version,
            source_environment=promotion.spec.source_environment,
            target_environment=promotion.spec.target_environment,
            add_policies=promotion.spec.policy_migration.add_policies,
            remove_policies=promotion.spec.policy_migration.remove_policies,
            max_allowed_score=target_env.max_risk_score
        )
        
        policy_plan = self.uslo_engine.plan_migration(promotion, source_env, target_env)
        
        if risk_result["total_score"] > target_env.max_risk_score:
            decision = "REJECTED"
            phase = "FAILED"
        else:
            decision = "APPROVED"
            phase = "SUCCEEDED"
        
        promotion.status.phase = phase
        promotion.status.risk_score = risk_result["total_score"]
        promotion.status.decision = decision
        promotion.status.message = risk_result["recommendation"]
        
        return {
            "phase": phase,
            "decision": decision,
            "risk_assessment": risk_result,
            "policy_plan": policy_plan,
            "message": risk_result["recommendation"]
        }
