"""
Risk Scoring Validation — PP2 Scenarios
========================================
Tests exact computed scores across 10 real-world deployment scenarios,
boundary conditions for each recommendation tier, and per-factor dominance.

Weights: config=0.20, policy=0.25, version_delta=0.15, env_transition=0.10,
         icap_coverage=0.20, compliance_posture=0.10
Default scores when not provided: icap_coverage=60, compliance_posture=50
"""
import pytest
from meds.validation.risk_scorer import RiskScorer


@pytest.fixture
def scorer():
    return RiskScorer()


def expected(config, policy, version_delta, env_transition,
             icap=60, compliance=50):
    """Compute expected total score using current 6-factor weights."""
    return int(
        config       * 0.20 +
        policy       * 0.25 +
        version_delta * 0.15 +
        env_transition * 0.10 +
        icap         * 0.20 +
        compliance   * 0.10
    )


# ---------------------------------------------------------------------------
# Scenario 1: Safe patch release to staging
# Typical daily promotion — should always be approved with low risk
# config=15 (patch), policy=0, version_delta=10 (patch), env=15 → total=23
# ---------------------------------------------------------------------------
class TestScenarioSafePatch:
    def test_score(self, scorer):
        result = scorer.calculate_risk_score(
            version="v1.2.3",
            source_environment="development",
            target_environment="staging",
            add_policies=[],
            remove_policies=[],
            max_allowed_score=60,
        )
        assert result["total_score"] == expected(15, 0, 10, 15)  # 23

    def test_approved_low_risk(self, scorer):
        result = scorer.calculate_risk_score(
            version="v1.2.3",
            source_environment="development",
            target_environment="staging",
            add_policies=[],
            remove_policies=[],
            max_allowed_score=60,
        )
        assert "Low risk" in result["recommendation"]


# ---------------------------------------------------------------------------
# Scenario 2: Alpha version skipping staging to production
# Highest-risk deployment possible — must always be rejected
# config=90 (alpha), policy=80 (5 adds), version_delta=80 (alpha), env=100 (blocked) → total=77
# ---------------------------------------------------------------------------
class TestScenarioAlphaToProdSkip:
    def test_score(self, scorer):
        result = scorer.calculate_risk_score(
            version="v0.1-alpha",
            source_environment="development",
            target_environment="production",
            add_policies=["a", "b", "c", "d", "e"],
            remove_policies=[],
            max_allowed_score=40,
        )
        assert result["total_score"] == expected(90, 80, 80, 100)  # 77

    def test_rejected(self, scorer):
        result = scorer.calculate_risk_score(
            version="v0.1-alpha",
            source_environment="development",
            target_environment="production",
            add_policies=["a", "b", "c", "d", "e"],
            remove_policies=[],
            max_allowed_score=40,
        )
        assert result["recommendation"].startswith("REJECTED")

    def test_score_exceeds_max(self, scorer):
        result = scorer.calculate_risk_score(
            version="v0.1-alpha",
            source_environment="development",
            target_environment="production",
            add_policies=["a", "b", "c", "d", "e"],
            remove_policies=[],
            max_allowed_score=40,
        )
        assert result["total_score"] > result["max_allowed"]


# ---------------------------------------------------------------------------
# Scenario 3: Major version release to production
# Standard major release through full pipeline
# config=70 (major), policy=50 (1 add + 1 remove w/ penalty), version_delta=65, env=25 → total=55
# ---------------------------------------------------------------------------
class TestScenarioMajorVersionToProd:
    def test_score(self, scorer):
        result = scorer.calculate_risk_score(
            version="v2.0.0",
            source_environment="staging",
            target_environment="production",
            add_policies=["policy-a"],
            remove_policies=["policy-b"],
            max_allowed_score=60,
        )
        assert result["total_score"] == expected(70, 50, 65, 25)  # 55

    def test_approved_elevated_requires_sign_off(self, scorer):
        result = scorer.calculate_risk_score(
            version="v2.0.0",
            source_environment="staging",
            target_environment="production",
            add_policies=["policy-a"],
            remove_policies=["policy-b"],
            max_allowed_score=60,
        )
        assert "manual sign-off" in result["recommendation"] or "approval required" in result["recommendation"].lower()


# ---------------------------------------------------------------------------
# Scenario 4: RC release to staging — typical pre-production gate
# config=55 (rc), policy=20 (1 add), version_delta=45 (rc), env=15 → total=41
# ---------------------------------------------------------------------------
class TestScenarioRCToStaging:
    def test_score(self, scorer):
        result = scorer.calculate_risk_score(
            version="v1.0-rc1",
            source_environment="development",
            target_environment="staging",
            add_policies=["security-policy"],
            remove_policies=[],
            max_allowed_score=60,
        )
        assert result["total_score"] == expected(55, 20, 45, 15)  # 41

    def test_within_limit(self, scorer):
        result = scorer.calculate_risk_score(
            version="v1.0-rc1",
            source_environment="development",
            target_environment="staging",
            add_policies=["security-policy"],
            remove_policies=[],
            max_allowed_score=60,
        )
        assert result["total_score"] <= result["max_allowed"]


# ---------------------------------------------------------------------------
# Scenario 5: Beta with mass policy churn to production
# High-change release — policy factor dominates (3 adds + 2 removes → 100)
# config=70 (beta), policy=100 (capped), version_delta=65, env=25 → total=68
# ---------------------------------------------------------------------------
class TestScenarioBetaMassChanges:
    def test_score(self, scorer):
        result = scorer.calculate_risk_score(
            version="v1.0-beta",
            source_environment="staging",
            target_environment="production",
            add_policies=["a", "b", "c"],
            remove_policies=["d", "e"],
            max_allowed_score=80,
        )
        assert result["total_score"] == expected(70, 100, 65, 25)  # 68

    def test_elevated_risk_requires_approval(self, scorer):
        result = scorer.calculate_risk_score(
            version="v1.0-beta",
            source_environment="staging",
            target_environment="production",
            add_policies=["a", "b", "c"],
            remove_policies=["d", "e"],
            max_allowed_score=80,
        )
        assert "approval required" in result["recommendation"].lower() or result["total_score"] > result["max_allowed"]


# ---------------------------------------------------------------------------
# Scenario 6: Minor version, no policy changes
# Routine minor release — should score low
# config=35 (minor), policy=0, version_delta=30 (minor), env=15 → total=30
# ---------------------------------------------------------------------------
class TestScenarioMinorVersionNoChanges:
    def test_score(self, scorer):
        result = scorer.calculate_risk_score(
            version="v1.2.0",
            source_environment="development",
            target_environment="staging",
            add_policies=[],
            remove_policies=[],
            max_allowed_score=60,
        )
        assert result["total_score"] == expected(35, 0, 30, 15)  # 30

    def test_approved_low(self, scorer):
        result = scorer.calculate_risk_score(
            version="v1.2.0",
            source_environment="development",
            target_environment="staging",
            add_policies=[],
            remove_policies=[],
            max_allowed_score=60,
        )
        assert "Low risk" in result["recommendation"]


# ---------------------------------------------------------------------------
# Scenario 7: Patch with many policy removals
# Removals carry higher penalty — policy factor still highest weight at 0.25
# config=15, policy=95 (3 removals w/ penalty), version_delta=10, env=25 → total=47
# ---------------------------------------------------------------------------
class TestScenarioPolicyDominated:
    def test_score(self, scorer):
        result = scorer.calculate_risk_score(
            version="v1.2.3",
            source_environment="staging",
            target_environment="production",
            add_policies=[],
            remove_policies=["a", "b", "c"],
            max_allowed_score=60,
        )
        assert result["total_score"] == expected(15, 95, 10, 25)  # 47

    def test_policy_factor_has_highest_weight(self, scorer):
        result = scorer.calculate_risk_score(
            version="v1.2.3",
            source_environment="staging",
            target_environment="production",
            add_policies=[],
            remove_policies=["a", "b", "c"],
            max_allowed_score=60,
        )
        factors = {f["name"]: f for f in result["factors"]}
        policy_weight = factors["policy_changes"]["weight"]
        other_weights = [f["weight"] for f in result["factors"] if f["name"] != "policy_changes"]
        assert all(policy_weight >= w for w in other_weights)


# ---------------------------------------------------------------------------
# Scenario 8: Policy change count → score mapping
# ---------------------------------------------------------------------------
class TestScenarioPolicyChangeBoundaries:
    def test_four_changes_two_removals(self, scorer):
        # 2 adds + 2 removes: base=65, removal_penalty=30 → 95
        factor = scorer._assess_policy_changes(["a", "b"], ["c", "d"])
        assert factor.score == 95

    def test_five_changes_two_removals(self, scorer):
        # 3 adds + 2 removes: base=80, removal_penalty=30 → capped at 100
        factor = scorer._assess_policy_changes(["a", "b", "c"], ["d", "e"])
        assert factor.score == 100

    def test_three_additions_no_removals(self, scorer):
        # 3 adds, 0 removes: base=50, penalty=0 → 50
        factor = scorer._assess_policy_changes(["a", "b", "c"], [])
        assert factor.score == 50


# ---------------------------------------------------------------------------
# Scenario 9: Environment transition boundary conditions
# ---------------------------------------------------------------------------
class TestScenarioEnvironmentBoundaries:
    def test_same_env_is_blocked(self, scorer):
        # Same-environment promotion is explicitly blocked
        factor = scorer._assess_environment_transition("staging", "staging")
        assert factor.score == 100

    def test_skip_staging_is_blocked(self, scorer):
        # Stage-skipping dev → prod is blocked
        factor = scorer._assess_environment_transition("development", "production")
        assert factor.score == 100

    def test_staging_to_prod_higher_than_dev_to_staging(self, scorer):
        dev_to_staging = scorer._assess_environment_transition("development", "staging")
        staging_to_prod = scorer._assess_environment_transition("staging", "production")
        assert staging_to_prod.score > dev_to_staging.score


# ---------------------------------------------------------------------------
# Scenario 10: Recommendation tier boundaries
# ---------------------------------------------------------------------------
class TestRecommendationTiers:
    """Verify all four recommendation tiers trigger at the correct thresholds."""

    def test_rejected_when_score_exceeds_max(self, scorer):
        # score=77 with max=40 → REJECTED
        result = scorer.calculate_risk_score(
            version="v0.1-alpha",
            source_environment="development",
            target_environment="production",
            add_policies=["a", "b", "c", "d", "e"],
            remove_policies=[],
            max_allowed_score=40,
        )
        assert result["recommendation"].startswith("REJECTED")

    def test_elevated_approval_required(self, scorer):
        # score=55, max=70 → 55 > int(70*0.75)=52 → elevated/approval required
        result = scorer.calculate_risk_score(
            version="v2.0.0",
            source_environment="staging",
            target_environment="production",
            add_policies=["a"],
            remove_policies=["b"],
            max_allowed_score=70,
        )
        assert "manual sign-off" in result["recommendation"] or "approval required" in result["recommendation"].lower()

    def test_moderate_risk(self, scorer):
        # score=55, max=75 → int(75*0.5)=37 < 55 <= int(75*0.75)=56 → moderate
        result = scorer.calculate_risk_score(
            version="v2.0.0",
            source_environment="staging",
            target_environment="production",
            add_policies=["a"],
            remove_policies=["b"],
            max_allowed_score=75,
        )
        assert "Moderate risk" in result["recommendation"]

    def test_low_below_50_percent_of_max(self, scorer):
        # score=23, max=60 → 23 < int(60*0.5)=30 → low
        result = scorer.calculate_risk_score(
            version="v1.2.3",
            source_environment="development",
            target_environment="staging",
            add_policies=[],
            remove_policies=[],
            max_allowed_score=60,
        )
        assert "Low risk" in result["recommendation"]


# ---------------------------------------------------------------------------
# Structural integrity
# ---------------------------------------------------------------------------
class TestStructuralIntegrity:
    def test_weights_sum_to_one(self, scorer):
        result = scorer.calculate_risk_score(
            version="v1.0.0",
            source_environment="development",
            target_environment="staging",
            add_policies=[],
            remove_policies=[],
            max_allowed_score=60,
        )
        total = sum(f["weight"] for f in result["factors"])
        assert abs(total - 1.0) < 1e-9

    def test_exactly_six_factors(self, scorer):
        result = scorer.calculate_risk_score(
            version="v1.0.0",
            source_environment="development",
            target_environment="staging",
            add_policies=[],
            remove_policies=[],
            max_allowed_score=60,
        )
        assert len(result["factors"]) == 6

    def test_factor_names_present(self, scorer):
        result = scorer.calculate_risk_score(
            version="v1.0.0",
            source_environment="development",
            target_environment="staging",
            add_policies=[],
            remove_policies=[],
            max_allowed_score=60,
        )
        names = {f["name"] for f in result["factors"]}
        assert names == {
            "config_complexity", "policy_changes", "version_delta",
            "environment_transition", "icap_coverage", "compliance_posture"
        }

    def test_weighted_score_matches_manual_calculation(self, scorer):
        result = scorer.calculate_risk_score(
            version="v1.2.3",
            source_environment="development",
            target_environment="staging",
            add_policies=[],
            remove_policies=[],
            max_allowed_score=60,
        )
        manual = sum(f["score"] * f["weight"] for f in result["factors"])
        assert abs(result["total_score"] - int(manual)) <= 1  # int truncation tolerance

    def test_score_is_non_negative(self, scorer):
        result = scorer.calculate_risk_score(
            version="v1.0.0",
            source_environment="development",
            target_environment="staging",
            add_policies=[],
            remove_policies=[],
            max_allowed_score=60,
        )
        assert result["total_score"] >= 0
