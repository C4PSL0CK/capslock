"""
End-to-end tests for the full MEDS promotion pipeline.
Tests the complete Dev → Staging → Production promotion workflow
with policy enforcement, ICAP scanning, and rollback.
"""
import pytest
from unittest.mock import MagicMock, patch
from meds.models.promotion import Promotion, PromotionSpec, PromotionStatus, Environment, ApplicationRef, PolicyMigration
from meds.controllers.promotion_controller import PromotionController, validate_transition
from meds.audit.log import AuditLogger
from meds.icap.scanner import ICAPScanner, ICAPScanResult
from meds.policy.version_store import PolicyVersionStore


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_promotion(
    name="test-app-v1.0.0",
    app_name="test-app",
    namespace="default",
    version="v1.0.0",
    source_env="development",
    target_env="staging",
    add_policies=None,
    remove_policies=None,
):
    return Promotion(
        metadata={"id": "test-001", "name": name},
        spec=PromotionSpec(
            application=ApplicationRef(name=app_name, namespace=namespace),
            source_environment=source_env,
            target_environment=target_env,
            version=version,
            policy_migration=PolicyMigration(
                add_policies=add_policies or [],
                remove_policies=remove_policies or [],
            ),
        ),
    )


def make_env(name="staging", env_type="staging", max_risk=60, policies=None):
    return Environment(
        name=name,
        type=env_type,
        max_risk_score=max_risk,
        policies=policies or ["pod-security-baseline"],
        cluster=f"{name}-cluster",
        policy_mode="audit" if env_type == "staging" else "enforce",
        approval_threshold=0.75,
    )


def mock_icap_clean():
    scanner = MagicMock(spec=ICAPScanner)
    scanner.scan.return_value = ICAPScanResult(
        threat_found=False,
        threat_type=None,
        coverage_score=95,
        low_coverage_warning=False,
        scanning_mode="block",
    )
    return scanner


def mock_icap_threat():
    scanner = MagicMock(spec=ICAPScanner)
    scanner.scan.return_value = ICAPScanResult(
        threat_found=True,
        threat_type="MALWARE.Test.EICAR",
        coverage_score=80,
        low_coverage_warning=False,
        scanning_mode="block",
    )
    return scanner


# ── State machine tests ────────────────────────────────────────────────────────

class TestStateMachine:
    def test_dev_to_staging_allowed(self):
        ok, err = validate_transition("development", "staging")
        assert ok is True
        assert err == ""

    def test_staging_to_prod_allowed(self):
        ok, err = validate_transition("staging", "production")
        assert ok is True
        assert err == ""

    def test_dev_to_prod_blocked(self):
        ok, err = validate_transition("development", "production")
        assert ok is False
        assert "Stage-skipping blocked" in err
        assert "staging" in err

    def test_prod_to_staging_blocked(self):
        ok, err = validate_transition("production", "staging")
        assert ok is False
        assert "Backward promotion blocked" in err

    def test_same_env_blocked(self):
        ok, err = validate_transition("staging", "staging")
        assert ok is False
        assert "same environment" in err

    def test_unknown_env_returns_error(self):
        ok, err = validate_transition("qa", "production")
        assert ok is False


# ── Full pipeline tests ────────────────────────────────────────────────────────

class TestFullPipeline:
    def _make_controller(self, icap_scanner=None, tmp_path=None):
        audit = AuditLogger(data_dir=str(tmp_path or "/tmp/meds-test-audit"))
        version_store = PolicyVersionStore(data_dir=str(tmp_path or "/tmp/meds-test-versions"))
        return PromotionController(
            icap_scanner=icap_scanner or mock_icap_clean(),
            audit_logger=audit,
            version_store=version_store,
        )

    @patch("meds.controllers.promotion_controller.POLICY_ENGINE_URL", "")
    def test_dev_to_staging_patch_version_approved(self, tmp_path):
        """Patch version with clean ICAP should auto-approve dev→staging."""
        ctrl = self._make_controller(tmp_path=tmp_path)
        promo = make_promotion(version="v1.0.1", source_env="development", target_env="staging")
        source_env = make_env("development", "development", max_risk=80)
        target_env = make_env("staging", "staging", max_risk=60)

        result = ctrl.process_promotion(promo, source_env, target_env)

        assert result["decision"] in ("APPROVED", "PENDING_APPROVAL")
        assert result["phase"] != "FAILED"
        assert result["risk_assessment"] is not None
        assert result["risk_assessment"]["total_score"] <= 60 or result["decision"] == "PENDING_APPROVAL"

    @patch("meds.controllers.promotion_controller.POLICY_ENGINE_URL", "")
    def test_alpha_version_to_prod_rejected(self, tmp_path):
        """Alpha version to production must be rejected (risk too high)."""
        ctrl = self._make_controller(tmp_path=tmp_path)
        promo = make_promotion(version="v2.0.0-alpha.1", source_env="staging", target_env="production")
        source_env = make_env("staging", "staging", max_risk=60)
        target_env = make_env("production", "production", max_risk=40)

        result = ctrl.process_promotion(promo, source_env, target_env)

        assert result["decision"] == "REJECTED"
        assert result["phase"] == "FAILED"

    @patch("meds.controllers.promotion_controller.POLICY_ENGINE_URL", "")
    def test_icap_threat_blocks_promotion(self, tmp_path):
        """ICAP threat detection must block promotion immediately."""
        ctrl = self._make_controller(icap_scanner=mock_icap_threat(), tmp_path=tmp_path)
        promo = make_promotion(version="v1.0.1", source_env="development", target_env="staging")
        source_env = make_env("development", "development", max_risk=80)
        target_env = make_env("staging", "staging", max_risk=60)

        result = ctrl.process_promotion(promo, source_env, target_env)

        assert result["decision"] == "REJECTED"
        assert result["phase"] == "FAILED"
        assert "ICAP threat" in result["message"]

    @patch("meds.controllers.promotion_controller.POLICY_ENGINE_URL", "")
    def test_backward_promotion_rejected_by_state_machine(self, tmp_path):
        """Backward promotion (prod→staging) must be blocked by state machine, not risk scorer."""
        ctrl = self._make_controller(tmp_path=tmp_path)
        promo = make_promotion(version="v1.0.0", source_env="production", target_env="staging")
        source_env = make_env("production", "production", max_risk=40)
        target_env = make_env("staging", "staging", max_risk=60)

        result = ctrl.process_promotion(promo, source_env, target_env)

        assert result["decision"] == "REJECTED"
        assert result["phase"] == "FAILED"
        assert "Backward promotion blocked" in result["message"]

    @patch("meds.controllers.promotion_controller.POLICY_ENGINE_URL", "")
    def test_stage_skipping_rejected(self, tmp_path):
        """Dev→Prod skip must be blocked."""
        ctrl = self._make_controller(tmp_path=tmp_path)
        promo = make_promotion(version="v1.0.1", source_env="development", target_env="production")
        source_env = make_env("development", "development", max_risk=80)
        target_env = make_env("production", "production", max_risk=40)

        result = ctrl.process_promotion(promo, source_env, target_env)

        assert result["decision"] == "REJECTED"
        assert "Stage-skipping blocked" in result["message"]

    @patch("meds.controllers.promotion_controller.POLICY_ENGINE_URL", "")
    def test_rollback_succeeds(self, tmp_path):
        """Rollback should set phase to ROLLED_BACK."""
        ctrl = self._make_controller(tmp_path=tmp_path)
        promo = make_promotion(version="v1.0.0")
        promo.status.rollback_version_id = "ver-abc123"
        target_env = make_env("staging", "staging")

        result = ctrl.execute_rollback(promo, target_env, "ver-abc123", reason="test", actor="test-runner")

        assert promo.status.phase == "ROLLED_BACK"
        assert "ver-abc123" in promo.status.message


# ── Audit log integrity tests ──────────────────────────────────────────────────

class TestAuditLogIntegrity:
    def test_hash_chain_valid_after_multiple_events(self, tmp_path):
        from meds.audit.log import AuditLogger
        logger = AuditLogger(data_dir=str(tmp_path))
        for i in range(5):
            logger.log(f"event_{i}", details={"seq": i}, promotion_id=f"pid-{i}")
        result = logger.verify_chain()
        assert result["valid"] is True
        assert result["events_checked"] == 5

    def test_hash_chain_detects_tampering(self, tmp_path):
        import json
        from meds.audit.log import AuditLogger
        logger = AuditLogger(data_dir=str(tmp_path))
        logger.log("event_a", details={"x": 1})
        logger.log("event_b", details={"x": 2})

        # Tamper with the log file
        log_file = tmp_path / "audit_log.jsonl"
        lines = log_file.read_text().strip().split("\n")
        first = json.loads(lines[0])
        first["details"]["x"] = 999  # tamper
        lines[0] = json.dumps(first)
        log_file.write_text("\n".join(lines) + "\n")

        # Reload a fresh logger to read the tampered file
        logger2 = AuditLogger(data_dir=str(tmp_path))
        result = logger2.verify_chain()
        assert result["valid"] is False


# ── USLO engine tests ──────────────────────────────────────────────────────────

class TestUSLOEngine:
    def test_staging_audit_mode_allows_violations(self):
        from meds.policy.uslo_engine import PolicyEvolutionTracker
        tracker = PolicyEvolutionTracker()
        assert tracker.get_effective_mode("staging") == "audit"

    def test_production_enforce_mode(self):
        from meds.policy.uslo_engine import PolicyEvolutionTracker
        tracker = PolicyEvolutionTracker()
        assert tracker.get_effective_mode("production") == "enforce"

    def test_development_enforce_mode(self):
        from meds.policy.uslo_engine import PolicyEvolutionTracker
        tracker = PolicyEvolutionTracker()
        assert tracker.get_effective_mode("development") == "enforce"
