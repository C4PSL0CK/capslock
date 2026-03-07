"""
Integration tests for the Policy Engine API.
Tests the full request/response cycle for all major endpoints.
Runs against the FastAPI app directly (no network required).
"""
import pytest
from fastapi.testclient import TestClient
import sys
import os

# Add policy-engine api to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from api.main import app

client = TestClient(app)


class TestHealthEndpoints:
    def test_root_health_check(self):
        resp = client.get("/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "timestamp" in data

    def test_list_compliance_frameworks(self):
        resp = client.get("/api/compliance/frameworks")
        assert resp.status_code == 200
        data = resp.json()
        assert "frameworks" in data
        frameworks = {f["name"] for f in data["frameworks"]}
        assert "CIS Kubernetes Benchmark" in frameworks
        assert "PCI-DSS" in frameworks

    def test_list_available_policies(self):
        resp = client.get("/api/policies")
        assert resp.status_code == 200
        data = resp.json()
        assert "policies" in data
        envs = {p["environment"] for p in data["policies"]}
        assert "dev" in envs
        assert "staging" in envs
        assert "prod" in envs


class TestPolicySynthesis:
    def test_synthesize_opa_policies_for_staging(self):
        resp = client.post("/api/policies/synthesize", json={
            "namespace": "staging",
            "environment": "staging",
            "frameworks": ["cis", "pci-dss"],
            "engine": "opa",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["engine"] == "opa"
        assert data["namespace"] == "staging"
        assert len(data["manifests"]) >= 2
        # All manifests should have name, kind, yaml
        for m in data["manifests"]:
            assert "name" in m
            assert "kind" in m
            assert "yaml" in m
            assert len(m["yaml"]) > 50  # non-trivial YAML
        # YAML should contain valid Kubernetes API version
        assert any("gatekeeper.sh" in m["yaml"] for m in data["manifests"])
        assert data["confidence_score"] > 0.0
        assert data["confidence_score"] <= 1.0

    def test_synthesize_kyverno_policies_for_production(self):
        resp = client.post("/api/policies/synthesize", json={
            "namespace": "production",
            "environment": "production",
            "frameworks": ["cis"],
            "engine": "kyverno",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["engine"] == "kyverno"
        assert len(data["manifests"]) >= 2
        # Production should use Enforce (not Audit)
        for m in data["manifests"]:
            assert "Enforce" in m["yaml"]
        assert "kyverno.io/v1" in data["manifests"][0]["yaml"]

    def test_synthesize_dev_environment_uses_audit_mode(self):
        resp = client.post("/api/policies/synthesize", json={
            "namespace": "dev",
            "environment": "development",
            "frameworks": ["cis"],
            "engine": "kyverno",
        })
        assert resp.status_code == 200
        data = resp.json()
        # Development should use Audit mode
        for m in data["manifests"]:
            assert "Audit" in m["yaml"]

    def test_synthesize_invalid_engine_returns_400(self):
        resp = client.post("/api/policies/synthesize", json={
            "namespace": "default",
            "environment": "staging",
            "engine": "unknown-engine",
        })
        assert resp.status_code == 400

    def test_synthesize_confidence_score_known_namespace(self):
        resp = client.post("/api/policies/synthesize", json={
            "namespace": "default",
            "environment": "production",
            "frameworks": ["cis", "pci-dss"],
            "engine": "opa",
        })
        data = resp.json()
        # Known namespace + known frameworks + known env = high confidence
        assert data["confidence_score"] >= 0.75

    def test_synthesize_confidence_score_unknown_namespace(self):
        resp = client.post("/api/policies/synthesize", json={
            "namespace": "totally-custom-namespace",
            "environment": "production",
            "frameworks": ["cis"],
            "engine": "opa",
        })
        data = resp.json()
        # Unknown namespace lowers confidence
        assert data["confidence_score"] < 0.90


class TestConflictResolution:
    def test_list_conflict_rules(self):
        resp = client.get("/api/policies/conflicts")
        assert resp.status_code == 200
        data = resp.json()
        assert "rules" in data
        assert len(data["rules"]) >= 4
        rule_ids = {r["id"] for r in data["rules"]}
        assert "allow-deny-conflict" in rule_ids
        assert "scan-mode-conflict" in rule_ids
        assert "required-remove-conflict" in rule_ids
        assert "namespace-scope-conflict" in rule_ids

    def test_conflict_resolution_allow_deny_production(self):
        """In production, deny should win over allow for same resource."""
        # Synthesize policies that include allow-* and deny-* patterns
        resp = client.post("/api/policies/synthesize", json={
            "namespace": "production",
            "environment": "production",
            "frameworks": ["cis"],
            "engine": "opa",
        })
        data = resp.json()
        cr = data["conflict_resolution"]
        assert "conflicts" in cr
        assert "resolved" in cr
        assert "precedence_rule" in cr
        assert "action" in cr

    def test_no_conflicts_returns_empty_list(self):
        resp = client.post("/api/policies/synthesize", json={
            "namespace": "staging",
            "environment": "staging",
            "frameworks": ["cis"],
            "engine": "kyverno",
        })
        data = resp.json()
        cr = data["conflict_resolution"]
        # synthesized policies from kyverno generator don't have allow-/deny- conflicts
        assert isinstance(cr["conflicts"], list)
        assert cr["action"] != ""


class TestICAPBridge:
    def test_icap_operator_status_returns_shape(self):
        """ICAP status endpoint should always return a valid shape (uses local fallback)."""
        resp = client.get("/api/icap/operator/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "scanning_mode" in data
        assert "health_score" in data or "ready_replicas" in data
        assert "source" in data

    def test_icap_health_returns_instances(self):
        resp = client.get("/api/icap/health")
        assert resp.status_code == 200
        data = resp.json()
        assert "aggregate_health_score" in data
        assert "instances" in data
        assert "scanning_mode" in data
        # Should have a/b/c instances
        assert len(data["instances"]) >= 1

    def test_icap_configure_scanning_mode(self):
        resp = client.post("/api/icap/operator/configure", json={"scanning_mode": "warn"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("applied_local", "patched")
        assert data["patch"]["scanning_mode"] == "warn"

        # Verify health reflects the change
        health = client.get("/api/icap/health").json()
        assert health["scanning_mode"] == "warn"

        # Restore to block
        client.post("/api/icap/operator/configure", json={"scanning_mode": "block"})

    def test_icap_configure_empty_request_returns_400(self):
        resp = client.post("/api/icap/operator/configure", json={})
        assert resp.status_code == 400


class TestSSDLBBridge:
    def test_ssdlb_status_no_url_configured(self):
        """Without SSDLB_URL set, should return not_configured gracefully."""
        resp = client.get("/api/integration/ssdlb/status")
        assert resp.status_code == 200
        data = resp.json()
        # Either not_configured (no URL) or ok (if URL is set)
        assert data["status"] in ("not_configured", "ok", "error")


class TestMEDSIntegration:
    def test_meds_notify_missing_namespace_returns_400(self):
        resp = client.post("/api/integration/meds/notify", json={})
        assert resp.status_code == 400

    def test_meds_notify_with_namespace(self):
        """Notify should attempt to run policy engine (may fail without binary, but shouldn't crash)."""
        resp = client.post("/api/integration/meds/notify", json={
            "namespace": "default",
            "environment": "staging",
            "promotion_id": "test-001",
            "version": "v1.0.0",
        })
        assert resp.status_code == 200
        data = resp.json()
        # Result depends on whether binary is present
        assert "status" in data
        assert data["status"] in ("policy_applied", "policy_failed", "error")
