import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

import httpx

from meds.models.promotion import Promotion, Environment
from meds.validation.risk_scorer import RiskScorer
from meds.policy.uslo_engine import PolicyEvolutionTracker
from meds.icap.scanner import ICAPScanner
from meds.audit.log import AuditLogger
from meds.policy.version_store import PolicyVersionStore
from meds.gitops.orchestrator import GitOpsOrchestrator
from meds.utils.logger import get_logger

POLICY_ENGINE_URL = os.getenv("POLICY_ENGINE_URL", "").rstrip("/")

# TLS configuration for inter-component calls
CA_CERT_PATH   = os.getenv("CA_CERT_PATH", "")
MTLS_CERT_PATH = os.getenv("MTLS_CERT_PATH", "")
MTLS_KEY_PATH  = os.getenv("MTLS_KEY_PATH", "")


def _make_http_client(timeout: float = 5.0) -> httpx.Client:
    """Return an httpx Client with optional mTLS configuration."""
    kwargs: dict = {"timeout": timeout}
    if CA_CERT_PATH:
        kwargs["verify"] = CA_CERT_PATH
    if MTLS_CERT_PATH and MTLS_KEY_PATH:
        kwargs["cert"] = (MTLS_CERT_PATH, MTLS_KEY_PATH)
    return httpx.Client(**kwargs)


# Valid promotion state machine transitions
_VALID_TRANSITIONS: Dict[str, list] = {
    "development": ["staging"],
    "staging":     ["production"],
    "production":  [],
}
_ENV_ORDER = ["development", "staging", "production"]


def validate_transition(source: str, target: str) -> Tuple[bool, str]:
    """Return (ok, error_message). ok=True means transition is allowed."""
    s, t = source.lower(), target.lower()
    if s == t:
        return False, f"Cannot promote to the same environment ({s})"
    allowed = _VALID_TRANSITIONS.get(s, [])
    if t in allowed:
        return True, ""
    try:
        si, ti = _ENV_ORDER.index(s), _ENV_ORDER.index(t)
        if ti < si:
            return False, f"Backward promotion blocked: {source} → {target}"
        via = " → ".join(_ENV_ORDER[si + 1: ti + 1])
        return False, f"Stage-skipping blocked: {source} → {target} (must pass through {via})"
    except ValueError:
        return False, f"Unknown environment in transition: {source} → {target}"


class PromotionController:
    def __init__(
        self,
        icap_scanner:  Optional[ICAPScanner]      = None,
        audit_logger:  Optional[AuditLogger]      = None,
        version_store: Optional[PolicyVersionStore] = None,
    ):
        self.risk_scorer  = RiskScorer()
        self.uslo_engine  = PolicyEvolutionTracker()
        self.gitops       = GitOpsOrchestrator()
        self.icap_scanner = icap_scanner  or ICAPScanner()
        self.audit_logger = audit_logger  or AuditLogger()
        self.version_store = version_store or PolicyVersionStore()
        self.logger       = get_logger("meds.controller")

    # ── Public entry point ────────────────────────────────────────────────────

    def process_promotion(
        self, promotion: Promotion, source_env: Environment, target_env: Environment
    ) -> Dict[str, Any]:
        promotion_id = promotion.metadata["id"]
        version      = promotion.spec.version
        app_name     = promotion.spec.application.name

        # ── 1. State machine gate ──────────────────────────────────────────
        ok, err = validate_transition(
            promotion.spec.source_environment,
            promotion.spec.target_environment,
        )
        if not ok:
            promotion.status.phase    = "FAILED"
            promotion.status.decision = "REJECTED"
            promotion.status.message  = f"REJECTED — {err}"
            self.audit_logger.log(
                "promotion_rejected",
                details={"reason": "invalid_transition", "message": err},
                promotion_id=promotion_id,
                environment=target_env.name,
            )
            self.audit_logger.log(
                "promotion_created",
                details={"name": promotion.metadata["name"], "decision": "REJECTED"},
                promotion_id=promotion_id,
                environment=target_env.name,
            )
            return self._result("FAILED", "REJECTED", None, None, promotion.status.message, None)

        # ── 2. ICAP hard gate ──────────────────────────────────────────────
        icap_result = self.icap_scanner.scan(version, app_name)

        if icap_result.threat_found:
            msg = f"REJECTED — ICAP threat detected: {icap_result.threat_type}"
            promotion.status.phase    = "FAILED"
            promotion.status.decision = "REJECTED"
            promotion.status.message  = msg
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
            return self._result("FAILED", "REJECTED", None, None, msg, icap_result.model_dump())

        # ── 3. Compliance posture (best-effort from policy engine) ─────────
        compliance_score = self._fetch_compliance_score(promotion.spec.application.namespace)

        # ── 4. 6-factor risk scoring ───────────────────────────────────────
        risk_result = self.risk_scorer.calculate_risk_score(
            version              = version,
            source_environment   = promotion.spec.source_environment,
            target_environment   = promotion.spec.target_environment,
            add_policies         = promotion.spec.policy_migration.add_policies,
            remove_policies      = promotion.spec.policy_migration.remove_policies,
            max_allowed_score    = target_env.max_risk_score,
            icap_coverage_score  = icap_result.coverage_score,
            compliance_score     = compliance_score,
        )

        # ── 5. USLO policy plan (Audit/Enforce mode) ───────────────────────
        policy_plan = self.uslo_engine.plan_migration(promotion, source_env, target_env)
        effective_mode = self.uslo_engine.get_effective_mode(target_env.type)
        promotion.status.policy_mode = effective_mode

        total_score = risk_result["total_score"]
        max_score   = target_env.max_risk_score

        # ── 6. Decision ────────────────────────────────────────────────────
        if total_score > max_score:
            decision = "REJECTED"
            phase    = "FAILED"
        elif total_score > int(max_score * target_env.approval_threshold):
            # Elevated risk — hold for human approval
            decision = "PENDING_APPROVAL"
            phase    = "PENDING_APPROVAL"
        else:
            decision = "APPROVED"
            phase    = "SUCCEEDED"

        # Append USLO audit-mode note
        if effective_mode == "audit" and policy_plan.get("violations"):
            risk_result["recommendation"] += f" | {len(policy_plan['violations'])} policy violation(s) logged (audit mode)"

        # Append ICAP low-coverage warning
        msg = risk_result["recommendation"]
        if icap_result.low_coverage_warning:
            msg += f" | ICAP low coverage warning (score: {icap_result.coverage_score})"

        promotion.status.phase      = phase
        promotion.status.risk_score = total_score
        promotion.status.decision   = decision
        promotion.status.message    = msg

        # ── 7. Persist policy version snapshot ────────────────────────────
        if decision == "APPROVED":
            prev_version = self.version_store.save_version(
                environment  = target_env.name,
                policies     = target_env.policies,
                promotion_id = promotion_id,
                note         = f"Promotion '{promotion.metadata['name']}' approved",
            )
            promotion.status.rollback_version_id = prev_version.version_id

            # ── 8. GitOps deploy ───────────────────────────────────────────
            gitops_status = self.gitops.deploy(promotion, target_env)
            from meds.models.promotion import GitOpsStatus
            promotion.status.gitops = GitOpsStatus(**{
                k: v for k, v in gitops_status.items()
                if k in GitOpsStatus.model_fields
            })

            self.audit_logger.log(
                "promotion_approved",
                details={
                    "risk_score": total_score,
                    "max_allowed": max_score,
                    "gitops_agent": gitops_status["agent"],
                    "cluster": target_env.cluster,
                    "compliance_score": compliance_score,
                },
                promotion_id = promotion_id,
                environment  = target_env.name,
            )
            self._notify_policy_engine(
                namespace    = promotion.spec.application.namespace,
                environment  = target_env.name,
                promotion_id = promotion_id,
                version      = version,
            )

        elif decision == "PENDING_APPROVAL":
            promotion.status.approval_required = True
            self.audit_logger.log(
                "promotion_pending_approval",
                details={"risk_score": total_score, "max_allowed": max_score, "threshold": int(max_score * target_env.approval_threshold)},
                promotion_id = promotion_id,
                environment  = target_env.name,
            )

        else:  # REJECTED
            self.audit_logger.log(
                "promotion_rejected",
                details={"risk_score": total_score, "max_allowed": max_score},
                promotion_id = promotion_id,
                environment  = target_env.name,
            )

        self.audit_logger.log(
            "promotion_created",
            details={"name": promotion.metadata["name"], "decision": decision},
            promotion_id = promotion_id,
            environment  = target_env.name,
        )

        return self._result(phase, decision, risk_result, policy_plan, msg, icap_result.model_dump())

    def complete_approval(
        self,
        promotion:   Promotion,
        target_env:  Environment,
        approved_by: str = "operator",
    ) -> Dict[str, Any]:
        """Execute the GitOps deploy after a human approves a PENDING_APPROVAL promotion."""
        promotion_id = promotion.metadata["id"]

        # Save policy version and deploy
        prev_version = self.version_store.save_version(
            environment  = target_env.name,
            policies     = target_env.policies,
            promotion_id = promotion_id,
            note         = f"Promotion '{promotion.metadata['name']}' manually approved by {approved_by}",
        )
        promotion.status.rollback_version_id = prev_version.version_id

        gitops_status = self.gitops.deploy(promotion, target_env)
        from meds.models.promotion import GitOpsStatus
        promotion.status.gitops     = GitOpsStatus(**{k: v for k, v in gitops_status.items() if k in GitOpsStatus.model_fields})
        promotion.status.phase      = "SUCCEEDED"
        promotion.status.decision   = "APPROVED"
        promotion.status.approved_by = approved_by
        promotion.status.approved_at = datetime.now(timezone.utc).isoformat()

        self.audit_logger.log(
            "promotion_approved",
            details={"approved_by": approved_by, "gitops_agent": gitops_status["agent"], "cluster": target_env.cluster},
            promotion_id = promotion_id,
            environment  = target_env.name,
            actor        = approved_by,
        )
        self._notify_policy_engine(
            namespace    = promotion.spec.application.namespace,
            environment  = target_env.name,
            promotion_id = promotion_id,
            version      = promotion.spec.version,
        )
        return gitops_status

    def execute_rollback(
        self,
        promotion:   Promotion,
        target_env:  Environment,
        version_id:  str,
        reason:      str = "manual",
        actor:       str = "system",
    ) -> Dict[str, Any]:
        """Roll back a promotion to a previous policy version and re-sync via GitOps."""
        promotion_id = promotion.metadata["id"]

        # GitOps rollback
        gitops_result = self.gitops.rollback(promotion, target_env, version_id)

        promotion.status.phase   = "ROLLED_BACK"
        promotion.status.message = f"Rolled back to version {version_id} — reason: {reason}"

        self.audit_logger.log(
            "promotion_rollback",
            details={"version_id": version_id, "reason": reason, "gitops_agent": gitops_result["agent"]},
            promotion_id = promotion_id,
            environment  = target_env.name,
            actor        = actor,
        )
        return gitops_result

    # ── Private helpers ───────────────────────────────────────────────────────

    def _fetch_compliance_score(self, namespace: str) -> Optional[float]:
        if not POLICY_ENGINE_URL:
            return None
        try:
            with _make_http_client(timeout=3.0) as client:
                r = client.get(
                    f"{POLICY_ENGINE_URL}/api/integration/icap/policy-status/{namespace}",
                )
            r.raise_for_status()
            return float(r.json().get("compliance_score", 1.0))
        except Exception:
            return None

    def _notify_policy_engine(
        self, namespace: str, environment: str, promotion_id: str, version: str
    ) -> None:
        if not POLICY_ENGINE_URL:
            return
        try:
            with _make_http_client(timeout=5.0) as client:
                client.post(
                    f"{POLICY_ENGINE_URL}/api/integration/meds/notify",
                    json={"namespace": namespace, "environment": environment,
                          "promotion_id": promotion_id, "version": version},
                )
        except Exception as e:
            self.logger.warning("policy_engine_notify_failed", error=str(e))

    @staticmethod
    def _result(
        phase: str, decision: str,
        risk_assessment: Optional[dict], policy_plan: Optional[dict],
        message: str, icap_scan: Optional[dict],
    ) -> Dict[str, Any]:
        return {
            "phase":           phase,
            "decision":        decision,
            "risk_assessment": risk_assessment,
            "policy_plan":     policy_plan,
            "message":         message,
            "icap_scan":       icap_scan,
        }
