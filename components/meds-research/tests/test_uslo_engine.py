import types
import pytest
from meds.policy.uslo_engine import PolicyEvolutionTracker


def make_promotion(add_policies):
    spec = types.SimpleNamespace(
        policy_migration=types.SimpleNamespace(
            add_policies=add_policies,
            remove_policies=[],
        )
    )
    return types.SimpleNamespace(spec=spec)


def make_env(env_type):
    return types.SimpleNamespace(type=env_type)


@pytest.fixture
def tracker():
    return PolicyEvolutionTracker()


def test_production_env_audit_mode(tracker):
    promotion = make_promotion(["network-segmentation"])
    target = make_env("production")
    plan = tracker.plan_migration(promotion, make_env("staging"), target)
    assert len(plan["changes"]) == 1
    change = plan["changes"][0]
    assert change["mode"] == "audit"
    assert change["grace_period"] == "48h"


def test_staging_env_audit_mode(tracker):
    promotion = make_promotion(["pod-security-standards"])
    target = make_env("staging")
    plan = tracker.plan_migration(promotion, make_env("development"), target)
    change = plan["changes"][0]
    assert change["mode"] == "audit"
    assert change["grace_period"] == "8h"


def test_dev_env_enforce_mode(tracker):
    promotion = make_promotion(["audit-logging"])
    target = make_env("development")
    plan = tracker.plan_migration(promotion, make_env("development"), target)
    change = plan["changes"][0]
    assert change["mode"] == "enforce"
    assert change["grace_period"] == "0h"


def test_policy_not_in_catalog(tracker):
    promotion = make_promotion(["unknown-policy-xyz"])
    plan = tracker.plan_migration(promotion, make_env("development"), make_env("production"))
    change = plan["changes"][0]
    assert "error" in change


def test_policy_in_catalog_has_severity(tracker):
    promotion = make_promotion(["rbac-least-privilege"])
    plan = tracker.plan_migration(promotion, make_env("staging"), make_env("production"))
    change = plan["changes"][0]
    assert "severity" in change
    assert "error" not in change


def test_zero_policies_no_compliance_impact(tracker):
    promotion = make_promotion([])
    plan = tracker.plan_migration(promotion, make_env("development"), make_env("staging"))
    assert plan["compliance_impact"].startswith("NONE")


def test_one_policy_low_compliance_impact(tracker):
    promotion = make_promotion(["audit-logging"])
    plan = tracker.plan_migration(promotion, make_env("development"), make_env("staging"))
    assert plan["compliance_impact"].startswith("LOW")


def test_three_policies_medium_compliance_impact(tracker):
    promotion = make_promotion(["audit-logging", "rbac-least-privilege", "secrets-encryption"])
    plan = tracker.plan_migration(promotion, make_env("staging"), make_env("production"))
    assert plan["compliance_impact"].startswith("MEDIUM")


def test_five_policies_high_compliance_impact(tracker):
    promotion = make_promotion([
        "audit-logging", "rbac-least-privilege", "secrets-encryption",
        "network-segmentation", "pod-security-standards",
    ])
    plan = tracker.plan_migration(promotion, make_env("staging"), make_env("production"))
    assert plan["compliance_impact"].startswith("HIGH")


def test_plan_has_required_keys(tracker):
    promotion = make_promotion([])
    plan = tracker.plan_migration(promotion, make_env("development"), make_env("staging"))
    assert "changes" in plan
    assert "compliance_impact" in plan
    assert "missing_required_policies" in plan
