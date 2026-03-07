"""Unit tests for SSDLB controller logic."""
import pytest
import time
import os
import json
import tempfile
from unittest.mock import patch, MagicMock

# Make main importable without starting FastAPI
os.environ.setdefault("PROMETHEUS_URL", "http://localhost:9090")
os.environ.setdefault("POLICY_ENGINE_URL", "")

import sys
sys.path.insert(0, os.path.dirname(__file__))


class TestLoadSaveState:
    def test_load_default_state_when_file_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr("main.STATE_FILE", str(tmp_path / "state.json"))
        from importlib import reload
        import main
        state = main.load_state()
        assert state["mode"] == "single"
        assert state["last_selected"] is None
        assert state["last_switch_ts"] == 0

    def test_save_and_load_roundtrip(self, tmp_path, monkeypatch):
        sf = str(tmp_path / "state.json")
        monkeypatch.setattr("main.STATE_FILE", sf)
        import main
        state = {"mode": "spread", "last_selected": "a", "last_switch_ts": 12345, "spread_since_ts": 12300}
        main.save_state(state)
        loaded = main.load_state()
        assert loaded["mode"] == "spread"
        assert loaded["last_selected"] == "a"
        assert loaded["last_switch_ts"] == 12345

    def test_load_handles_corrupt_state(self, tmp_path, monkeypatch):
        sf = str(tmp_path / "state.json")
        monkeypatch.setattr("main.STATE_FILE", sf)
        with open(sf, "w") as f:
            f.write("not valid json{{{")
        import main
        state = main.load_state()
        assert state["mode"] == "single"  # falls back to default


class TestServiceRegistry:
    def test_register_valid_version(self):
        from fastapi.testclient import TestClient
        import main
        client = TestClient(main.app)
        resp = client.post("/register/d", json={"version": "d", "weight": 2})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "registered"
        # Cleanup
        if "d" in main._service_registry:
            del main._service_registry["d"]

    def test_register_invalid_version(self):
        from fastapi.testclient import TestClient
        import main
        client = TestClient(main.app)
        resp = client.post("/register/../../etc", json={"version": "../../etc"})
        assert resp.status_code == 200
        assert "error" in resp.json()

    def test_deregister_version(self):
        from fastapi.testclient import TestClient
        import main
        main._service_registry["test-v"] = {"version": "test-v", "registered_at": None, "healthy": True, "weight": 1}
        client = TestClient(main.app)
        resp = client.delete("/register/test-v")
        assert resp.status_code == 200
        assert resp.json()["status"] == "deregistered"
        assert "test-v" not in main._service_registry

    def test_get_registry(self):
        from fastapi.testclient import TestClient
        import main
        client = TestClient(main.app)
        resp = client.get("/registry")
        assert resp.status_code == 200
        data = resp.json()
        assert "registry" in data
        assert "a" in data["registry"]


class TestQueueDepth:
    def test_queue_depth_prometheus_unreachable(self):
        """Falls back gracefully when Prometheus is unreachable."""
        import main
        with patch("main.query_prometheus", side_effect=Exception("connection refused")):
            with patch("main.get_total_rate", return_value=0.0):
                result = main.get_queue_depth()
        assert result["total_queue_depth"] == 0.0
        assert result["high_queue_detected"] is False

    def test_queue_depth_high_queue_detected(self):
        """Detects high queue when depth > 10."""
        import main
        with patch("main.query_prometheus", return_value=[
            {"metric": {"version": "a"}, "value": [0, "6.0"]},
            {"metric": {"version": "b"}, "value": [0, "5.0"]},
        ]):
            result = main.get_queue_depth()
        assert result["total_queue_depth"] > 10.0
        assert result["high_queue_detected"] is True


class TestTrendDetection:
    def test_rising_trend_detected_when_growth_above_threshold(self):
        import main
        with patch("main.get_total_rate", side_effect=lambda w: 1.2 if w == "1m" else 1.0):
            rising, short, medium = main.detect_rising_trend()
        assert rising is True

    def test_no_rising_trend_when_stable(self):
        import main
        with patch("main.get_total_rate", side_effect=lambda w: 1.0 if w == "1m" else 1.0):
            rising, short, medium = main.detect_rising_trend()
        assert rising is False

    def test_no_trend_when_medium_is_zero(self):
        import main
        with patch("main.get_total_rate", return_value=0.0):
            rising, short, medium = main.detect_rising_trend()
        assert rising is False


class TestDRGeneration:
    def test_generate_dr_for_registered_version(self):
        from fastapi.testclient import TestClient
        import main
        client = TestClient(main.app)
        resp = client.get("/generate-dr/a")
        assert resp.status_code == 200
        data = resp.json()
        assert "yaml" in data
        assert "DestinationRule" in data["yaml"]
        assert "version: a" in data["yaml"]

    def test_generate_dr_unregistered_version(self):
        from fastapi.testclient import TestClient
        import main
        client = TestClient(main.app)
        resp = client.get("/generate-dr/zzz-unknown")
        assert resp.status_code == 200
        assert "error" in resp.json()

    def test_generate_dr_spread(self):
        from fastapi.testclient import TestClient
        import main
        # spread is handled via apply-dr with version="spread" but here test generate
        # register spread temporarily
        main._service_registry["spread"] = {"version": "spread", "registered_at": None, "healthy": True, "weight": 1}
        client = TestClient(main.app)
        resp = client.get("/generate-dr/spread")
        assert resp.status_code == 200
        del main._service_registry["spread"]


class TestComplianceLogging:
    def test_compliance_event_map_populated(self):
        import main
        assert "predictive_spread_entered" in main._COMPLIANCE_EVENT_MAP
        assert "pci_dss" in main._COMPLIANCE_EVENT_MAP["predictive_spread_entered"]
        assert "cis" in main._COMPLIANCE_EVENT_MAP["predictive_spread_entered"]

    def test_log_compliance_event_emits_json(self, capsys):
        import main
        main.log_compliance_event("predictive_spread_entered", short_rate=1.5, medium_rate=1.0)
        captured = capsys.readouterr()
        # Should have logged something with compliance fields
        lines = [l for l in captured.out.split("\n") if l.strip()]
        assert len(lines) > 0
        parsed = json.loads(lines[-1])
        assert parsed["event"] == "predictive_spread_entered"
        assert "compliance_pci_dss" in parsed
