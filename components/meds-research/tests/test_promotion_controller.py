import pytest
from unittest.mock import MagicMock, patch

from meds.models.promotion import Promotion, Environment, PromotionSpec, ApplicationRef, PolicyMigration
from meds.icap.scanner import ICAPScanResult
from meds.controllers.promotion_controller import PromotionController


def make_promotion(version, source, target, add_policies=None):
    return Promotion(
        metadata={"name": "test-promotion", "id": "test-id"},
        spec=PromotionSpec(
            application=ApplicationRef(name="myapp", namespace="default"),
            source_environment=source,
            target_environment=target,
            version=version,
            policy_migration=PolicyMigration(add_policies=add_policies or []),
        ),
    )


def make_env(name, env_type, max_risk):
    return Environment(name=name, type=env_type, max_risk_score=max_risk, policies=[])


def clean_icap(coverage_score=90):
    return ICAPScanResult(
        threat_found=False,
        threat_type=None,
        coverage_score=coverage_score,
        low_coverage_warning=coverage_score < 75,
        scanned_at="2025-01-01T00:00:00Z",
    )


def threat_icap():
    return ICAPScanResult(
        threat_found=True,
        threat_type="malware",
        coverage_score=85,
        low_coverage_warning=False,
        scanned_at="2025-01-01T00:00:00Z",
    )


@pytest.fixture
def mock_dependencies():
    """Returns a PromotionController with mocked ICAP scanner, audit logger, and version store."""
    mock_scanner = MagicMock()
    mock_audit = MagicMock()
    mock_store = MagicMock()
    controller = PromotionController(
        icap_scanner=mock_scanner,
        audit_logger=mock_audit,
        version_store=mock_store,
    )
    return controller, mock_scanner, mock_audit, mock_store


def test_approved_case(mock_dependencies):
    controller, mock_scanner, mock_audit, mock_store = mock_dependencies
    mock_scanner.scan.return_value = clean_icap(coverage_score=90)

    promotion = make_promotion("v1.2.3", "development", "staging")
    source = make_env("development", "development", 80)
    target = make_env("staging", "staging", 60)

    result = controller.process_promotion(promotion, source, target)

    assert result["decision"] == "APPROVED"
    assert result["icap_scan"]["threat_found"] is False
    assert result["risk_assessment"] is not None
    assert promotion.status.decision == "APPROVED"


def test_rejected_by_risk_score(mock_dependencies):
    controller, mock_scanner, mock_audit, mock_store = mock_dependencies
    mock_scanner.scan.return_value = clean_icap(coverage_score=90)

    # alpha + dev->prod + 5 policies = score well above 40
    promotion = make_promotion(
        "v2.0.0-alpha", "development", "production",
        add_policies=["a", "b", "c", "d", "e"],
    )
    source = make_env("development", "development", 80)
    target = make_env("production", "production", 40)

    result = controller.process_promotion(promotion, source, target)

    assert result["decision"] == "REJECTED"
    assert result["icap_scan"]["threat_found"] is False
    assert promotion.status.decision == "REJECTED"


def test_rejected_by_icap_threat(mock_dependencies):
    controller, mock_scanner, mock_audit, mock_store = mock_dependencies
    mock_scanner.scan.return_value = threat_icap()

    promotion = make_promotion("v1.2.3", "development", "staging")
    source = make_env("development", "development", 80)
    target = make_env("staging", "staging", 60)

    result = controller.process_promotion(promotion, source, target)

    assert result["decision"] == "REJECTED"
    assert result["icap_scan"]["threat_found"] is True
    assert "threat" in result["message"].lower()
    assert result["risk_assessment"] is None
    assert promotion.status.decision == "REJECTED"


def test_icap_low_coverage_warning_in_message(mock_dependencies):
    controller, mock_scanner, mock_audit, mock_store = mock_dependencies
    mock_scanner.scan.return_value = clean_icap(coverage_score=70)

    promotion = make_promotion("v1.2.3", "development", "staging")
    source = make_env("development", "development", 80)
    target = make_env("staging", "staging", 60)

    result = controller.process_promotion(promotion, source, target)

    assert result["decision"] == "APPROVED"
    assert "coverage" in result["message"].lower()


def test_audit_logger_called_on_approved(mock_dependencies):
    controller, mock_scanner, mock_audit, mock_store = mock_dependencies
    mock_scanner.scan.return_value = clean_icap(coverage_score=90)

    promotion = make_promotion("v1.2.3", "development", "staging")
    controller.process_promotion(
        promotion,
        make_env("development", "development", 80),
        make_env("staging", "staging", 60),
    )

    event_types = [call.args[0] for call in mock_audit.log.call_args_list]
    assert "promotion_approved" in event_types
    assert "promotion_created" in event_types


def test_version_store_called_on_approved(mock_dependencies):
    controller, mock_scanner, mock_audit, mock_store = mock_dependencies
    mock_scanner.scan.return_value = clean_icap(coverage_score=90)

    promotion = make_promotion("v1.2.3", "development", "staging")
    controller.process_promotion(
        promotion,
        make_env("development", "development", 80),
        make_env("staging", "staging", 60),
    )

    mock_store.save_version.assert_called_once()


def test_version_store_not_called_on_rejected(mock_dependencies):
    controller, mock_scanner, mock_audit, mock_store = mock_dependencies
    mock_scanner.scan.return_value = clean_icap(coverage_score=90)

    promotion = make_promotion(
        "v2.0.0-alpha", "development", "production",
        add_policies=["a", "b", "c", "d", "e"],
    )
    controller.process_promotion(
        promotion,
        make_env("development", "development", 80),
        make_env("production", "production", 40),
    )

    mock_store.save_version.assert_not_called()
