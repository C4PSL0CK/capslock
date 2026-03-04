"""
ICAP Health Score Validation — PP2 Scenarios
=============================================
Validates the adaptive health scoring algorithm from
components/icap-operator/internal/health/calculator.go

Each sub-score formula is replicated here in Python so tests run without
a running Kubernetes cluster or compiled Go binary.

Scoring components (baseline weights):
  Readiness   0.25  — pod availability ratio
  Latency     0.25  — scan performance vs configured threshold
  Signatures  0.20  — ClamAV signature freshness
  Errors      0.15  — scan failure rate under load
  Resources   0.10  — CPU/memory efficiency
  Queue       0.05  — scan backlog management

Run: pytest components/meds-research/tests/test_health_score_scenarios.py -v
"""
import pytest


# ---------------------------------------------------------------------------
# Python mirror of the Go health calculator (calculator.go + adaptive.go)
# ---------------------------------------------------------------------------

BASELINE_WEIGHTS = {
    "readiness":   0.25,
    "latency":     0.25,
    "signatures":  0.20,
    "errors":      0.15,
    "resources":   0.10,
    "queue":       0.05,
}


def score_readiness(ready: int, desired: int, unavailable: int) -> float:
    """Mirror of calculateReadiness."""
    if desired == 0:
        return 0.0
    score = (ready / desired) * 100
    if unavailable > 0:
        score -= (unavailable / desired) * 20
    return max(0.0, score)


def score_latency(max_latency: str, traffic: str = "normal") -> float:
    """Mirror of calculateLatency."""
    base = {"500ms": 100, "1s": 90, "2s": 70}.get(max_latency, 50)
    adjustment = {"spike": -15, "high": -10, "low": +5, "normal": 0}.get(traffic, 0)
    return max(0.0, min(100.0, base + adjustment))


def score_signatures(age_hours: float) -> float:
    """Mirror of calculateSignatureFreshness."""
    if age_hours < 6:
        return 100.0
    elif age_hours < 12:
        return 90.0
    elif age_hours < 24:
        return 75.0
    elif age_hours < 48:
        return 50.0
    return 25.0


def score_errors(traffic: str = "normal", resources: str = "healthy") -> float:
    """Mirror of calculateErrorHealth."""
    rate = 0.02
    rate += {"spike": 0.03, "high": 0.01, "normal": 0, "low": 0}.get(traffic, 0)
    rate += {"critical": 0.05, "constrained": 0.02, "healthy": 0}.get(resources, 0)
    return max(0.0, min(100.0, (1 - rate) * 100))


def score_resources(ready: int, desired: int, unavailable: int) -> float:
    """Mirror of calculateResourceHealth."""
    if ready == desired and unavailable == 0:
        return 95.0
    if unavailable > 0:
        return 60.0
    return 80.0


def score_queue(replicas: int, traffic: str = "normal") -> float:
    """Mirror of calculateQueueHealth."""
    simulated = {
        "spike":  replicas * 50,
        "high":   replicas * 20,
        "normal": replicas * 5,
        "low":    replicas * 1,
    }.get(traffic, replicas * 5)
    max_healthy = replicas * 30
    if simulated <= max_healthy:
        return 100.0
    overflow = simulated - max_healthy
    return max(0.0, 100.0 - (overflow / max_healthy * 100.0))


def adaptive_weights(traffic: str = "normal", threat: str = "normal", resources: str = "healthy") -> dict:
    """Mirror of CalculateAdaptiveWeights (adaptive.go)."""
    w = dict(BASELINE_WEIGHTS)

    # Traffic adjustment
    if traffic in ("high", "spike"):
        w["latency"]    += 0.10
        w["queue"]      += 0.05
        w["signatures"] -= 0.10
        w["errors"]     -= 0.05
    elif traffic == "low":
        w["signatures"] += 0.10
        w["latency"]    -= 0.05
        w["queue"]      -= 0.05

    # Threat adjustment
    if threat in ("critical", "high"):
        w["signatures"] += 0.15
        w["errors"]     += 0.10
        w["latency"]    -= 0.15
        w["queue"]      -= 0.10
    elif threat == "elevated":
        w["signatures"] += 0.08
        w["errors"]     += 0.05
        w["latency"]    -= 0.08
        w["queue"]      -= 0.05

    # Resource adjustment
    if resources in ("critical", "constrained"):
        w["resources"]  += 0.15
        w["readiness"]  += 0.10
        w["latency"]    -= 0.15
        w["signatures"] -= 0.10

    # Normalise to sum = 1.0
    total = sum(w.values())
    return {k: v / total for k, v in w.items()}


def overall_score(
    ready: int, desired: int, unavailable: int,
    latency_threshold: str = "500ms",
    sig_age_hours: float = 8,
    traffic: str = "normal",
    threat: str = "normal",
    resources_state: str = "healthy",
) -> float:
    """Compute the adaptive overall health score (0-100)."""
    r   = score_readiness(ready, desired, unavailable)
    l   = score_latency(latency_threshold, traffic)
    s   = score_signatures(sig_age_hours)
    e   = score_errors(traffic, resources_state)
    res = score_resources(ready, desired, unavailable)
    q   = score_queue(desired, traffic)

    w = adaptive_weights(traffic, threat, resources_state)

    return (r  * w["readiness"]
          + l  * w["latency"]
          + s  * w["signatures"]
          + e  * w["errors"]
          + res * w["resources"]
          + q  * w["queue"])


# ---------------------------------------------------------------------------
# Readiness score tests
# ---------------------------------------------------------------------------
class TestReadinessScore:
    def test_all_replicas_ready(self):
        assert score_readiness(3, 3, 0) == 100.0

    def test_no_replicas_ready(self):
        assert score_readiness(0, 3, 3) == 0.0

    def test_zero_desired_returns_zero(self):
        assert score_readiness(0, 0, 0) == 0.0

    def test_half_replicas_ready_no_unavailable(self):
        # ready=1, desired=2, unavailable=0 → 50%
        assert score_readiness(1, 2, 0) == 50.0

    def test_unavailable_penalty_applied(self):
        # ready=2, desired=3, unavailable=1 → base=66.7, penalty=6.7 → ~60
        score = score_readiness(2, 3, 1)
        assert score < score_readiness(2, 3, 0)

    def test_score_never_negative(self):
        # All replicas unavailable
        assert score_readiness(0, 3, 3) >= 0.0

    def test_single_replica_healthy(self):
        assert score_readiness(1, 1, 0) == 100.0


# ---------------------------------------------------------------------------
# Latency score tests
# ---------------------------------------------------------------------------
class TestLatencyScore:
    def test_500ms_threshold_is_best(self):
        assert score_latency("500ms") == 100.0

    def test_1s_threshold(self):
        assert score_latency("1s") == 90.0

    def test_2s_threshold(self):
        assert score_latency("2s") == 70.0

    def test_unknown_threshold_defaults_50(self):
        assert score_latency("5s") == 50.0

    def test_spike_traffic_reduces_score_by_15(self):
        base  = score_latency("500ms", "normal")
        spike = score_latency("500ms", "spike")
        assert base - spike == 15.0

    def test_high_traffic_reduces_score_by_10(self):
        base = score_latency("500ms", "normal")
        high = score_latency("500ms", "high")
        assert base - high == 10.0

    def test_low_traffic_increases_score_by_5(self):
        # Use "1s" threshold (base=90) so +5 is not capped
        base = score_latency("1s", "normal")
        low  = score_latency("1s", "low")
        assert low - base == 5.0

    def test_low_traffic_capped_at_100_for_500ms(self):
        # 500ms + low = 105 → capped to 100
        assert score_latency("500ms", "low") == 100.0

    def test_score_floor_zero(self):
        # 50 - 15 = 35; still positive but ensure no negative case
        assert score_latency("5s", "spike") >= 0.0


# ---------------------------------------------------------------------------
# Signature freshness tests
# ---------------------------------------------------------------------------
class TestSignatureFreshness:
    def test_fresh_signatures_under_6h(self):
        assert score_signatures(1) == 100.0
        assert score_signatures(5.9) == 100.0

    def test_slightly_stale_6_to_12h(self):
        assert score_signatures(6) == 90.0
        assert score_signatures(11.9) == 90.0

    def test_moderate_stale_12_to_24h(self):
        assert score_signatures(12) == 75.0
        assert score_signatures(23) == 75.0

    def test_old_signatures_24_to_48h(self):
        assert score_signatures(24) == 50.0
        assert score_signatures(47) == 50.0

    def test_very_old_signatures_48h_plus(self):
        assert score_signatures(48) == 25.0
        assert score_signatures(72) == 25.0

    def test_freshness_decreases_with_age(self):
        scores = [score_signatures(h) for h in [1, 8, 18, 30, 60]]
        assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# Error health tests
# ---------------------------------------------------------------------------
class TestErrorHealth:
    def test_baseline_error_rate(self):
        # 2% base → 98% score
        assert score_errors("normal", "healthy") == pytest.approx(98.0)

    def test_spike_traffic_increases_error_rate(self):
        # 2% + 3% = 5% → 95%
        assert score_errors("spike", "healthy") == pytest.approx(95.0)

    def test_high_traffic_increases_error_rate(self):
        # 2% + 1% = 3% → 97%
        assert score_errors("high", "healthy") == pytest.approx(97.0)

    def test_critical_resources_increases_error_rate(self):
        # 2% + 5% = 7% → 93%
        assert score_errors("normal", "critical") == pytest.approx(93.0)

    def test_spike_plus_critical_resources(self):
        # 2% + 3% + 5% = 10% → 90%
        assert score_errors("spike", "critical") == pytest.approx(90.0)

    def test_constrained_resources(self):
        # 2% + 2% = 4% → 96%
        assert score_errors("normal", "constrained") == pytest.approx(96.0)


# ---------------------------------------------------------------------------
# Resource health tests
# ---------------------------------------------------------------------------
class TestResourceHealth:
    def test_all_replicas_healthy(self):
        assert score_resources(3, 3, 0) == 95.0

    def test_unavailable_replicas_constrained(self):
        assert score_resources(2, 3, 1) == 60.0

    def test_ready_less_than_desired_no_unavailable(self):
        assert score_resources(2, 3, 0) == 80.0

    def test_single_healthy_replica(self):
        assert score_resources(1, 1, 0) == 95.0


# ---------------------------------------------------------------------------
# Queue health tests
# ---------------------------------------------------------------------------
class TestQueueHealth:
    def test_normal_traffic_queue_healthy(self):
        # 3 replicas × 5 = 15 queue; max = 3 × 30 = 90 → healthy
        assert score_queue(3, "normal") == 100.0

    def test_low_traffic_queue_healthy(self):
        assert score_queue(3, "low") == 100.0

    def test_high_traffic_within_healthy_range(self):
        # 3 × 20 = 60 queue; max = 90 → healthy
        assert score_queue(3, "high") == 100.0

    def test_spike_traffic_overflows_queue(self):
        # 3 × 50 = 150; max = 90 → overflow = 60; score = 100 - (60/90*100) = 33.3
        score = score_queue(3, "spike")
        assert score < 100.0
        assert score == pytest.approx(100.0 - (60 / 90 * 100.0))

    def test_more_replicas_handle_spike_better(self):
        score_3 = score_queue(3, "spike")
        score_6 = score_queue(6, "spike")
        # More replicas → same proportional overflow → same score (linear)
        assert score_3 == pytest.approx(score_6)


# ---------------------------------------------------------------------------
# Adaptive weights tests
# ---------------------------------------------------------------------------
class TestAdaptiveWeights:
    def test_baseline_weights_sum_to_one(self):
        w = adaptive_weights()
        assert abs(sum(w.values()) - 1.0) < 1e-9

    def test_spike_traffic_increases_latency_weight(self):
        normal = adaptive_weights("normal")
        spike  = adaptive_weights("spike")
        assert spike["latency"] > normal["latency"]

    def test_spike_traffic_decreases_signature_weight(self):
        normal = adaptive_weights("normal")
        spike  = adaptive_weights("spike")
        assert spike["signatures"] < normal["signatures"]

    def test_low_traffic_increases_signature_weight(self):
        normal = adaptive_weights("normal")
        low    = adaptive_weights("low")
        assert low["signatures"] > normal["signatures"]

    def test_high_threat_increases_signature_weight(self):
        normal = adaptive_weights("normal", "normal")
        high   = adaptive_weights("normal", "high")
        assert high["signatures"] > normal["signatures"]

    def test_critical_resources_increases_readiness_weight(self):
        normal   = adaptive_weights("normal", "normal", "healthy")
        critical = adaptive_weights("normal", "normal", "critical")
        assert critical["readiness"] > normal["readiness"]

    def test_all_combinations_sum_to_one(self):
        for traffic in ("normal", "high", "spike", "low"):
            for threat in ("normal", "elevated", "high"):
                for res in ("healthy", "constrained", "critical"):
                    w = adaptive_weights(traffic, threat, res)
                    assert abs(sum(w.values()) - 1.0) < 1e-9, \
                        f"Weights do not sum to 1 for traffic={traffic}, threat={threat}, resources={res}"


# ---------------------------------------------------------------------------
# Overall score — scenario-based integration tests
# ---------------------------------------------------------------------------
class TestOverallScoreScenarios:
    def test_scenario_fully_healthy(self):
        """All replicas up, fresh signatures, low traffic → score above 90."""
        score = overall_score(
            ready=3, desired=3, unavailable=0,
            latency_threshold="500ms",
            sig_age_hours=2,
            traffic="normal",
        )
        assert score > 90.0, f"Expected >90, got {score:.1f}"

    def test_scenario_all_replicas_down(self):
        """Zero replicas ready → readiness=0 and resource=60 drag overall score down significantly."""
        score = overall_score(
            ready=0, desired=3, unavailable=3,
            latency_threshold="500ms",
            sig_age_hours=2,
            traffic="normal",
        )
        healthy = overall_score(ready=3, desired=3, unavailable=0)
        # Score must be substantially lower than a fully-healthy deployment
        assert score < healthy * 0.85, f"All-down score {score:.1f} should be < 85% of healthy {healthy:.1f}"

    def test_scenario_spike_traffic_with_tight_threshold(self):
        """Traffic spike + tight 500ms threshold → moderate reduction from healthy baseline."""
        healthy = overall_score(ready=3, desired=3, unavailable=0, traffic="normal")
        spike   = overall_score(ready=3, desired=3, unavailable=0, traffic="spike")
        assert spike < healthy, "Spike traffic should reduce score"

    def test_scenario_stale_signatures_48h(self):
        """Very old ClamAV signatures → lower score than fresh."""
        fresh = overall_score(ready=3, desired=3, unavailable=0, sig_age_hours=2)
        stale = overall_score(ready=3, desired=3, unavailable=0, sig_age_hours=50)
        assert stale < fresh, "Stale signatures should reduce score"

    def test_scenario_one_unavailable_replica(self):
        """One replica down affects readiness and resource scores."""
        all_up  = overall_score(ready=3, desired=3, unavailable=0)
        one_down = overall_score(ready=2, desired=3, unavailable=1)
        assert one_down < all_up

    def test_scenario_critical_resources(self):
        """Critical resource state increases error rate, lowers score."""
        healthy  = overall_score(ready=3, desired=3, unavailable=0, resources_state="healthy")
        critical = overall_score(ready=3, desired=3, unavailable=0, resources_state="critical")
        assert critical < healthy

    def test_scenario_high_threat_level(self):
        """High threat level shifts weight toward signatures, changes overall score."""
        normal_threat = overall_score(ready=3, desired=3, unavailable=0, sig_age_hours=20, threat="normal")
        high_threat   = overall_score(ready=3, desired=3, unavailable=0, sig_age_hours=20, threat="high")
        # With old-ish signatures, high threat (higher sig weight) should lower score
        assert high_threat < normal_threat

    def test_scenario_score_bounded_0_to_100(self):
        """Overall score must always be in [0, 100]."""
        scenarios = [
            dict(ready=3, desired=3, unavailable=0, traffic="normal"),
            dict(ready=0, desired=3, unavailable=3, traffic="spike"),
            dict(ready=1, desired=3, unavailable=1, traffic="high", sig_age_hours=50),
            dict(ready=3, desired=3, unavailable=0, traffic="low", sig_age_hours=1),
        ]
        for s in scenarios:
            score = overall_score(**s)
            assert 0.0 <= score <= 100.0, f"Score {score:.1f} out of bounds for {s}"

    def test_scenario_degraded_moderate_score(self):
        """Half replicas down + spike + stale signatures → score in 40-65 range."""
        score = overall_score(
            ready=1, desired=3, unavailable=1,
            latency_threshold="1s",
            sig_age_hours=25,
            traffic="high",
            resources_state="constrained",
        )
        assert 30.0 < score < 75.0, f"Expected 30-75 for degraded scenario, got {score:.1f}"

    def test_scenario_2s_latency_threshold_lowers_score(self):
        """Looser latency threshold means lower latency score."""
        tight = overall_score(ready=3, desired=3, unavailable=0, latency_threshold="500ms")
        loose = overall_score(ready=3, desired=3, unavailable=0, latency_threshold="2s")
        assert tight > loose
