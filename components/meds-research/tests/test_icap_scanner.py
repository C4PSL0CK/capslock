import pytest
from meds.icap.scanner import ICAPScanner


@pytest.fixture
def scanner():
    return ICAPScanner()


def test_determinism_same_input(scanner):
    r1 = scanner.scan("v1.0.0", "myapp")
    r2 = scanner.scan("v1.0.0", "myapp")
    assert r1.threat_found == r2.threat_found
    assert r1.coverage_score == r2.coverage_score
    assert r1.threat_type == r2.threat_type


def test_different_inputs_may_differ(scanner):
    # Just assert types are correct — content is deterministic per input
    r1 = scanner.scan("v1.0.0", "app-a")
    r2 = scanner.scan("v1.0.0", "app-b")
    assert isinstance(r1.coverage_score, int)
    assert isinstance(r2.coverage_score, int)


def test_alpha_coverage_range(scanner):
    for i in range(100):
        result = scanner.scan("v1.0-alpha", f"app-{i}")
        assert 60 <= result.coverage_score <= 79, (
            f"app-{i}: coverage {result.coverage_score} out of alpha range [60, 79]"
        )


def test_beta_coverage_range(scanner):
    for i in range(100):
        result = scanner.scan("v1.0-beta", f"app-{i}")
        assert 70 <= result.coverage_score <= 89, (
            f"app-{i}: coverage {result.coverage_score} out of beta range [70, 89]"
        )


def test_rc_coverage_range(scanner):
    for i in range(100):
        result = scanner.scan("v1.0-rc1", f"app-{i}")
        assert 80 <= result.coverage_score <= 94, (
            f"app-{i}: coverage {result.coverage_score} out of rc range [80, 94]"
        )


def test_stable_coverage_range(scanner):
    for i in range(100):
        result = scanner.scan("v1.2.3", f"app-{i}")
        assert 85 <= result.coverage_score <= 99, (
            f"app-{i}: coverage {result.coverage_score} out of stable range [85, 99]"
        )


def test_alpha_higher_threat_rate_than_stable(scanner):
    alpha_threats = sum(scanner.scan("v1.0-alpha", f"app-{i}").threat_found for i in range(200))
    stable_threats = sum(scanner.scan("v1.2.3", f"app-{i}").threat_found for i in range(200))
    assert alpha_threats > stable_threats


def test_low_coverage_warning_flag(scanner):
    # Find a scan that has low coverage (alpha versions will have some)
    for i in range(200):
        result = scanner.scan("v1.0-alpha", f"app-{i}")
        if result.coverage_score < 75:
            assert result.low_coverage_warning is True
            return
    pytest.skip("No low coverage scan found in 200 alpha iterations")


def test_no_threat_type_when_clean(scanner):
    for i in range(200):
        result = scanner.scan("v1.2.3", f"app-{i}")
        if not result.threat_found:
            assert result.threat_type is None
            return
    pytest.skip("No clean scan found in 200 stable iterations")


def test_threat_type_set_when_threat_found(scanner):
    for i in range(200):
        result = scanner.scan("v1.0-alpha", f"app-{i}")
        if result.threat_found:
            assert result.threat_type is not None
            assert result.threat_type in ["malware", "vulnerability", "suspicious_pattern"]
            return
    pytest.skip("No threat found in 200 alpha iterations")


def test_scan_result_has_required_fields(scanner):
    result = scanner.scan("v1.0.0", "testapp")
    assert hasattr(result, "threat_found")
    assert hasattr(result, "coverage_score")
    assert hasattr(result, "low_coverage_warning")
    assert hasattr(result, "scanned_at")
