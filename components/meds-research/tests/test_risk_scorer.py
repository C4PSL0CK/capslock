import pytest
from meds.validation.risk_scorer import RiskScorer


@pytest.fixture
def scorer():
    return RiskScorer()


# --- Individual factor tests ---

def test_alpha_version_config_score(scorer):
    factor = scorer._assess_config_complexity("v1.0-alpha")
    assert factor.score == 90


def test_beta_version_config_score(scorer):
    factor = scorer._assess_config_complexity("v1.0-beta")
    assert factor.score == 70


def test_rc_version_config_score(scorer):
    factor = scorer._assess_config_complexity("v1.0-rc1")
    assert factor.score == 60


def test_major_version_config_score(scorer):
    factor = scorer._assess_config_complexity("v2.0.0")
    assert factor.score == 70


def test_minor_version_config_score(scorer):
    factor = scorer._assess_config_complexity("v1.2.0")
    assert factor.score == 40


def test_stable_patch_low_config_score(scorer):
    factor = scorer._assess_config_complexity("v1.2.3")
    assert factor.score == 20


def test_zero_policy_changes(scorer):
    factor = scorer._assess_policy_changes([], [])
    assert factor.score == 0


def test_two_policy_changes_low(scorer):
    factor = scorer._assess_policy_changes(["a"], ["b"])
    assert factor.score == 30


def test_four_policy_changes_medium(scorer):
    factor = scorer._assess_policy_changes(["a", "b"], ["c", "d"])
    assert factor.score == 60


def test_five_policy_changes_high(scorer):
    factor = scorer._assess_policy_changes(["a", "b", "c", "d", "e"], [])
    assert factor.score == 90


def test_dev_to_staging_environment_score(scorer):
    factor = scorer._assess_environment_transition("development", "staging")
    assert factor.score == 20


def test_staging_to_prod_environment_score(scorer):
    factor = scorer._assess_environment_transition("staging", "production")
    assert factor.score == 30


def test_dev_to_prod_skip_very_high(scorer):
    factor = scorer._assess_environment_transition("development", "production")
    assert factor.score == 90


def test_alpha_version_delta_high(scorer):
    factor = scorer._assess_version_delta("v1.0-alpha")
    assert factor.score == 80


def test_stable_version_delta_low(scorer):
    factor = scorer._assess_version_delta("v1.2.3")
    assert factor.score == 30


# --- Combined scoring tests ---

def test_score_below_max_approved(scorer):
    result = scorer.calculate_risk_score(
        version="v1.2.3",
        source_environment="development",
        target_environment="staging",
        add_policies=[],
        remove_policies=[],
        max_allowed_score=60,
    )
    assert result["total_score"] < 60
    assert result["recommendation"].startswith("APPROVED")


def test_score_above_max_rejected(scorer):
    result = scorer.calculate_risk_score(
        version="v2.0.0-alpha",
        source_environment="development",
        target_environment="production",
        add_policies=["a", "b", "c", "d", "e"],
        remove_policies=[],
        max_allowed_score=40,
    )
    assert result["total_score"] > 40
    assert result["recommendation"].startswith("REJECTED")


def test_weights_sum_to_one(scorer):
    result = scorer.calculate_risk_score(
        version="v1.0.0",
        source_environment="development",
        target_environment="staging",
        add_policies=[],
        remove_policies=[],
        max_allowed_score=60,
    )
    total_weight = sum(f["weight"] for f in result["factors"])
    assert abs(total_weight - 1.0) < 1e-9


def test_result_contains_required_keys(scorer):
    result = scorer.calculate_risk_score(
        version="v1.0.0",
        source_environment="development",
        target_environment="staging",
        add_policies=[],
        remove_policies=[],
        max_allowed_score=60,
    )
    assert "total_score" in result
    assert "max_allowed" in result
    assert "factors" in result
    assert "recommendation" in result
    assert len(result["factors"]) == 4
