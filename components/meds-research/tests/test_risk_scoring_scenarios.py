"""
Risk Scoring Validation — PP2 Scenarios
========================================
Tests exact computed scores across 10 real-world deployment scenarios,
boundary conditions for each recommendation tier, and per-factor dominance.

Weights: config=0.30, policy=0.40, version_delta=0.20, env_transition=0.10
"""
import pytest
from meds.validation.risk_scorer import RiskScorer


@pytest.fixture
def scorer():
    return RiskScorer()


# ---------------------------------------------------------------------------
# Helper: compute expected score manually so tests are self-documenting
# ---------------------------------------------------------------------------
def expected(config, policy, version_delta, env_transition):
    """Compute expected total score from raw factor scores using published weights."""
    return int(config * 0.30 + policy * 0.40 + version_delta * 0.20 + env_transition * 0.10)


# ---------------------------------------------------------------------------
# Scenario 1: Safe patch release to staging
# Typical daily promotion — should always be approved with low risk
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
        # config=20, policy=0, version_delta=30, env=20
        assert result["total_score"] == expected(20, 0, 30, 20)  # 14

    def test_approved_low_risk(self, scorer):
        result = scorer.calculate_risk_score(
            version="v1.2.3",
            source_environment="development",
            target_environment="staging",
            add_policies=[],
            remove_policies=[],
            max_allowed_score=60,
        )
        assert result["recommendation"] == "APPROVED - Low risk, safe to proceed"


# ---------------------------------------------------------------------------
# Scenario 2: Alpha version skipping staging to production
# Highest-risk deployment possible — must always be rejected
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
        # config=90, policy=90, version_delta=80, env=90 → 88
        assert result["total_score"] == expected(90, 90, 80, 90)  # 88

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
        # config=70, policy=30 (2 changes), version_delta=30, env=30
        assert result["total_score"] == expected(70, 30, 30, 30)  # 42

    def test_approved_with_monitor(self, scorer):
        result = scorer.calculate_risk_score(
            version="v2.0.0",
            source_environment="staging",
            target_environment="production",
            add_policies=["policy-a"],
            remove_policies=["policy-b"],
            max_allowed_score=60,
        )
        # 42 > 60*0.6=36 → "monitor closely"
        assert "Moderate risk" in result["recommendation"] or "manual review" in result["recommendation"]


# ---------------------------------------------------------------------------
# Scenario 4: RC release to staging — typical pre-production gate
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
        # config=60, policy=30 (1 change), version_delta=50, env=20
        assert result["total_score"] == expected(60, 30, 50, 20)  # 42

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
# High-change release — policy factor dominates
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
        # config=70, policy=90 (5 changes), version_delta=70, env=30
        assert result["total_score"] == expected(70, 90, 70, 30)  # 74

    def test_elevated_risk_recommendation(self, scorer):
        result = scorer.calculate_risk_score(
            version="v1.0-beta",
            source_environment="staging",
            target_environment="production",
            add_policies=["a", "b", "c"],
            remove_policies=["d", "e"],
            max_allowed_score=80,
        )
        # 74 > 80*0.8=64 → elevated risk
        assert "manual review" in result["recommendation"].lower() or result["total_score"] > result["max_allowed"]


# ---------------------------------------------------------------------------
# Scenario 6: Minor version, no policy changes
# Routine minor release — should score low
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
        # config=40, policy=0, version_delta=30, env=20
        assert result["total_score"] == expected(40, 0, 30, 20)  # 20

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
# Policy changes dominate even for stable version
# ---------------------------------------------------------------------------
class TestScenarioPolicyDominated:
    def test_policy_factor_dominates(self, scorer):
        result = scorer.calculate_risk_score(
            version="v1.2.3",
            source_environment="staging",
            target_environment="production",
            add_policies=[],
            remove_policies=["a", "b", "c"],
            max_allowed_score=60,
        )
        # config=20, policy=60 (3 changes), version_delta=30, env=30
        assert result["total_score"] == expected(20, 60, 30, 30)  # 39

    def test_policy_factor_weight_is_largest(self, scorer):
        result = scorer.calculate_risk_score(
            version="v1.2.3",
            source_environment="staging",
            target_environment="production",
            add_policies=[],
            remove_policies=["a", "b", "c"],
            max_allowed_score=60,
        )
        factors = {f["name"]: f for f in result["factors"]}
        assert factors["policy_changes"]["weight"] == 0.40  # largest weight


# ---------------------------------------------------------------------------
# Scenario 8: Four policy changes — boundary between medium and high
# ---------------------------------------------------------------------------
class TestScenarioFourPolicyChanges:
    def test_four_changes_medium(self, scorer):
        factor = scorer._assess_policy_changes(["a", "b"], ["c", "d"])
        assert factor.score == 60  # 4 changes → medium (60)

    def test_five_changes_high(self, scorer):
        factor = scorer._assess_policy_changes(["a", "b", "c"], ["d", "e"])
        assert factor.score == 90  # 5 changes → high (90)

    def test_three_changes_medium(self, scorer):
        factor = scorer._assess_policy_changes(["a", "b", "c"], [])
        assert factor.score == 60  # 3 changes → medium (60)


# ---------------------------------------------------------------------------
# Scenario 9: Environment transition boundary conditions
# ---------------------------------------------------------------------------
class TestScenarioEnvironmentBoundaries:
    def test_same_env_uses_default(self, scorer):
        factor = scorer._assess_environment_transition("staging", "staging")
        # Not in risk_matrix → default score = 20
        assert factor.score == 20

    def test_skip_staging_highest_risk(self, scorer):
        factor = scorer._assess_environment_transition("development", "production")
        assert factor.score == 90

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
        # score=88 with max=40 → REJECTED
        result = scorer.calculate_risk_score(
            version="v0.1-alpha",
            source_environment="development",
            target_environment="production",
            add_policies=["a", "b", "c", "d", "e"],
            remove_policies=[],
            max_allowed_score=40,
        )
        assert result["recommendation"].startswith("REJECTED")

    def test_elevated_between_80_and_100_percent_of_max(self, scorer):
        # score=42 with max=50 → 42 > 50*0.8=40 → elevated
        result = scorer.calculate_risk_score(
            version="v2.0.0",
            source_environment="staging",
            target_environment="production",
            add_policies=["a"],
            remove_policies=["b"],
            max_allowed_score=50,
        )
        assert "manual review" in result["recommendation"]

    def test_moderate_between_60_and_80_percent_of_max(self, scorer):
        # score=42 with max=65 → 42 > 65*0.6=39, 42 < 65*0.8=52 → moderate
        result = scorer.calculate_risk_score(
            version="v2.0.0",
            source_environment="staging",
            target_environment="production",
            add_policies=["a"],
            remove_policies=["b"],
            max_allowed_score=65,
        )
        assert "Moderate risk" in result["recommendation"]

    def test_low_below_60_percent_of_max(self, scorer):
        # score=14 with max=60 → 14 < 60*0.6=36 → low
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

    def test_exactly_four_factors(self, scorer):
        result = scorer.calculate_risk_score(
            version="v1.0.0",
            source_environment="development",
            target_environment="staging",
            add_policies=[],
            remove_policies=[],
            max_allowed_score=60,
        )
        assert len(result["factors"]) == 4

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
        assert names == {"configuration_complexity", "policy_changes", "version_delta", "environment_transition"}

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
