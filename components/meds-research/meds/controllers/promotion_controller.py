import os
from typing import Dict, Any, Optional

import httpx

from meds.models.promotion import Promotion, Environment
from meds.validation.risk_scorer import RiskScorer
from meds.policy.uslo_engine import PolicyEvolutionTracker
from meds.icap.scanner import ICAPScanner
from meds.audit.log import AuditLogger
from meds.policy.version_store import PolicyVersionStore
from meds.utils.logger import get_logger

POLICY_ENGINE_URL = os.getenv("POLICY_ENGINE_URL", "").rstrip("/")


class PromotionController:
    def __init__(
        self,
        icap_scanner: Optional[ICAPScanner] = None,
        audit_logger: Optional[AuditLogger] = None,
        version_store: Optional[PolicyVersionStore] = None,
    ):
        self.risk_scorer = RiskScorer()
        self.uslo_engine = PolicyEvolutionTracker()
        self.icap_scanner = icap_scanner or ICAPScanner()
        self.audit_logger = audit_logger or AuditLogger()
        self.version_store = version_store or PolicyVersionStore()
        self.logger = get_logger("meds.controller")

    def process_promotion(
        self, promotion: Promotion, source_env: Environment, target_env: Environment
    ) -> Dict[str, Any]:
        promotion_id = promotion.metadata["id"]
        version = promotion.spec.version
        app_name = promotion.spec.application.name

        # --- ICAP hard gate ---
        icap_result = self.icap_scanner.scan(version, app_name)

        if icap_result.threat_found:
            message = f"REJECTED - ICAP threat detected: {icap_result.threat_type}"
            promotion.status.phase = "FAILED"
            promotion.status.risk_score = None
            promotion.status.decision = "REJECTED"
            promotion.status.message = message

            self.audit_logger.log(
                "icap_threat_detected",
                details={"threat_type": icap_result.threat_type, "coverage_score": icap_result.coverage_score},
                promotion_id=promotion_id,
                environment=target_env.name,
            )
            self.audit_logger.log(
                "promotion_rejected",
                details={"reason": "icap_threat", "threat_type": icap_result.threat_type},
                promotion_id=promotion_id,
                environment=target_env.name,
            )
            self.audit_logger.log(
                "promotion_created",
                details={"name": promotion.metadata["name"], "decision": "REJECTED"},
                promotion_id=promotion_id,
                environment=target_env.name,
            )

            return {
                "phase": "FAILED",
                "decision": "REJECTED",
                "risk_assessment": None,
                "policy_plan": None,
                "message": message,
                "icap_scan": icap_result.model_dump(),
            }

        # --- Risk scoring ---
        risk_result = self.risk_scorer.calculate_risk_score(
            version=version,
            source_environment=promotion.spec.source_environment,
            target_environment=promotion.spec.target_environment,
            add_policies=promotion.spec.policy_migration.add_policies,
            remove_policies=promotion.spec.policy_migration.remove_policies,
            max_allowed_score=target_env.max_risk_score,
        )

        policy_plan = self.uslo_engine.plan_migration(promotion, source_env, target_env)

        if risk_result["total_score"] > target_env.max_risk_score:
            decision = "REJECTED"
            phase = "FAILED"
        else:
            decision = "APPROVED"
            phase = "SUCCEEDED"

        # Build message
        message = risk_result["recommendation"]
        if icap_result.low_coverage_warning:
            message += f" | ICAP low coverage warning (score: {icap_result.coverage_score})"

        promotion.status.phase = phase
        promotion.status.risk_score = risk_result["total_score"]
        promotion.status.decision = decision
        promotion.status.message = message

        if decision == "APPROVED":
            self.version_store.save_version(
                environment=target_env.name,
                policies=target_env.policies,
                promotion_id=promotion_id,
                note=f"Promotion '{promotion.metadata['name']}' approved",
            )
            self.audit_logger.log(
                "promotion_approved",
                details={"risk_score": risk_result["total_score"], "max_allowed": target_env.max_risk_score},
                promotion_id=promotion_id,
                environment=target_env.name,
            )
            self._notify_policy_engine(
                namespace=promotion.spec.application.namespace,
                environment=target_env.name,
                promotion_id=promotion_id,
                version=version,
            )
        else:
            self.audit_logger.log(
                "promotion_rejected",
                details={"risk_score": risk_result["total_score"], "max_allowed": target_env.max_risk_score},
                promotion_id=promotion_id,
                environment=target_env.name,
            )

        self.audit_logger.log(
            "promotion_created",
            details={"name": promotion.metadata["name"], "decision": decision},
            promotion_id=promotion_id,
            environment=target_env.name,
        )

        return {
            "phase": phase,
            "decision": decision,
            "risk_assessment": risk_result,
            "policy_plan": policy_plan,
            "message": message,
            "icap_scan": icap_result.model_dump(),
        }

    def _notify_policy_engine(
        self, namespace: str, environment: str, promotion_id: str, version: str
    ) -> None:
        """Fire-and-forget notification to the policy-engine after a promotion is approved."""
        if not POLICY_ENGINE_URL:
            return
        try:
            httpx.post(
                f"{POLICY_ENGINE_URL}/api/integration/meds/notify",
                json={
                    "namespace": namespace,
                    "environment": environment,
                    "promotion_id": promotion_id,
                    "version": version,
                },
                timeout=5.0,
            )
            self.logger.info(
                "policy_engine_notified",
                namespace=namespace,
                environment=environment,
                promotion_id=promotion_id,
            )
        except Exception as e:
            self.logger.warning(
                "policy_engine_notify_failed",
                error=str(e),
                namespace=namespace,
            )
