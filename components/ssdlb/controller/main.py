from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any
import subprocess
import os
import requests
import time
import json
import logging
from datetime import datetime, timezone

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logger = logging.getLogger("ssdlb-controller")
logger.setLevel(LOG_LEVEL)

if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setLevel(LOG_LEVEL)
    logger.addHandler(handler)

def log_event(event: str, **fields):
    """
    Structured JSON logging (one line per event).
    Use this for decisions, guardrail triggers, and routing changes.
    """
    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "component": "ssdlb-controller",
        "event": event,
        **fields,
    }
    # Ensure it's always JSON even if some fields are non-serializable
    logger.info(json.dumps(payload, default=str))

# In-memory service registry — replaced by dynamic registration
_service_registry: Dict[str, Dict[str, Any]] = {
    "a": {"version": "a", "registered_at": None, "healthy": True, "weight": 1},
    "b": {"version": "b", "registered_at": None, "healthy": True, "weight": 1},
    "c": {"version": "c", "registered_at": None, "healthy": True, "weight": 1},
}

# PCI-DSS v4.0 and CIS K8s Benchmark v1.9 routing event mappings
_COMPLIANCE_EVENT_MAP = {
    "predictive_spread_entered":  {"pci_dss": ["10.2.1", "10.3.1"], "cis": ["4.2.1"]},
    "recovered_to_single":        {"pci_dss": ["10.2.1"],           "cis": ["4.1.1"]},
    "icap_health_forced_spread":  {"pci_dss": ["10.6.1", "10.3.1"], "cis": ["4.2.1", "4.4.1"]},
    "icap_health_penalty_applied":{"pci_dss": ["10.6.1"],           "cis": ["4.4.1"]},
    "manual_set_version_applied": {"pci_dss": ["10.2.2"],           "cis": ["4.1.1"]},
    "service_registered":         {"pci_dss": ["10.2.2"],           "cis": ["4.1.1"]},
    "service_deregistered":       {"pci_dss": ["10.2.2", "10.3.1"], "cis": ["4.1.1"]},
}

def log_compliance_event(event: str, **fields):
    """
    Structured compliance-aware logging.
    Emits the standard log_event AND appends PCI-DSS/CIS control references.
    """
    compliance = _COMPLIANCE_EVENT_MAP.get(event, {})
    log_event(event, compliance_pci_dss=compliance.get("pci_dss", []),
              compliance_cis=compliance.get("cis", []), **fields)

PROMETHEUS_URL    = os.getenv("PROMETHEUS_URL",    "http://localhost:9090")
POLICY_ENGINE_URL = os.getenv("POLICY_ENGINE_URL", "").rstrip("/")

# Below this aggregate health score the SSDLB forces spread mode regardless
# of traffic trend, because at least one ICAP instance is degraded.
ICAP_HEALTH_SPREAD_THRESHOLD = int(os.getenv("ICAP_HEALTH_SPREAD_THRESHOLD", "70"))
# Per-instance health penalty multiplier: if a version's health is below this,
# its observed rate is artificially inflated so it won't be chosen for single mode.
ICAP_INSTANCE_HEALTHY_FLOOR = int(os.getenv("ICAP_INSTANCE_HEALTHY_FLOOR", "60"))

# Guardrails (tune later)
COOLDOWN_SECONDS = int(os.getenv("COOLDOWN_SECONDS", "60"))
MIN_CHANGE_RATIO = float(os.getenv("MIN_CHANGE_RATIO", "0.20"))  # 20% improvement required


SPREAD_MIN_SECONDS = int(os.getenv("SPREAD_MIN_SECONDS", "60"))          # stay in spread at least this long
RECOVERY_STABLE_SECONDS = int(os.getenv("RECOVERY_STABLE_SECONDS", "120")) # require stable window before collapsing
RECOVERY_GROWTH_RATIO = float(os.getenv("RECOVERY_GROWTH_RATIO", "0.02"))  # spike considered "gone" when growth <= this


MIN_TOTAL_RATE = float(os.getenv("MIN_TOTAL_RATE", "0.05"))  # minimum traffic required
MIN_METRIC_WINDOW_SECONDS = int(os.getenv("MIN_METRIC_WINDOW_SECONDS", "10"))

# Hysteresis thresholds:
# - ENTER should be higher (harder to enter spread)
# - EXIT should be lower (easier to exit spread once stable)
TREND_ENTER_GROWTH_RATIO = float(os.getenv("TREND_ENTER_GROWTH_RATIO", "0.08"))
TREND_EXIT_GROWTH_RATIO  = float(os.getenv("TREND_EXIT_GROWTH_RATIO",  "0.03"))

app = FastAPI()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DR_DIR = os.path.join(BASE_DIR, "dr-files")
STATE_FILE = os.path.join(BASE_DIR, "state.json")

ALLOWED_VERSIONS = {"a", "b", "c"}


def load_state():
    # Default state
    state = {
    "mode": "single",          # "single" or "spread"
    "last_selected": None,     # "a" / "b" / "c" / "spread"
    "last_switch_ts": 0,       # unix timestamp
    "spread_since_ts": 0       # when we entered spread mode
}

    if not os.path.exists(STATE_FILE):
        return state

    try:
        with open(STATE_FILE, "r") as f:
            data = json.load(f)
        # Merge with defaults to avoid missing keys
        state.update({k: data.get(k, state[k]) for k in state.keys()})
    except Exception:
        # If state file is corrupted, fall back safely
        return state

    return state


def save_state(state: dict):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


@app.get("/")
def health():
    return {"status": "controller alive"}


@app.get("/state")
def get_state():
    return load_state()


class ServiceRegistration(BaseModel):
    version: str
    healthy: bool = True
    weight: int = 1  # 1-10, used for weighted routing


@app.post("/register/{version}")
def register_service(version: str, reg: ServiceRegistration):
    """Register a new ICAP service version for dynamic routing."""
    if len(version) > 32 or not version.replace("-", "").isalnum():
        return {"error": "invalid version name"}
    _service_registry[version] = {
        "version": version,
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "healthy": reg.healthy,
        "weight": max(1, min(10, reg.weight)),
    }
    log_compliance_event("service_registered", version=version, weight=reg.weight)
    return {"status": "registered", "version": version, "registry": _service_registry}


@app.delete("/register/{version}")
def deregister_service(version: str):
    """Deregister an ICAP service version."""
    if version not in _service_registry:
        return {"error": "version not found"}
    del _service_registry[version]
    log_compliance_event("service_deregistered", version=version)
    return {"status": "deregistered", "remaining": list(_service_registry.keys())}


@app.get("/registry")
def get_registry():
    """List all registered ICAP service versions."""
    return {"registry": _service_registry, "active_versions": list(_service_registry.keys())}


@app.post("/set-version/{version}")
def set_version(version: str):
    if version not in _service_registry:
        return {"error": "invalid version"}

    path = os.path.join(DR_DIR, f"dr-{version}.yaml")
    if not os.path.exists(path):
        return {"error": "dr file not found", "path": path}

    log_event("manual_set_version_requested", version=version, dr_path=path)

    result = subprocess.run(
        ["kubectl", "apply", "-f", path],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        log_event("manual_set_version_failed", version=version, error=result.stderr)
        return {"error": result.stderr}

    log_compliance_event("manual_set_version_applied", version=version)

    # Update state (manual switch counts as a switch)
    state = load_state()
    state["last_selected"] = version
    state["last_switch_ts"] = int(time.time())
    save_state(state)

    return {"status": "ok", "applied": path}


def get_icap_health() -> dict:
    """
    Fetch ICAP operator health from the policy-engine bridge endpoint.
    Returns an empty dict when the policy-engine is unreachable so callers
    can safely treat missing data as "all healthy".
    """
    if not POLICY_ENGINE_URL:
        return {}
    try:
        r = requests.get(f"{POLICY_ENGINE_URL}/api/icap/health", timeout=3)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        log_event("icap_health_fetch_failed", error=str(exc))
        return {}


@app.get("/icap-health")
def icap_health_endpoint():
    """Expose the current ICAP operator health for the MEDS dashboard."""
    return get_icap_health()


def query_prometheus(query: str):
    r = requests.get(
        f"{PROMETHEUS_URL}/api/v1/query",
        params={"query": query},
        timeout=5
    )
    r.raise_for_status()
    return r.json()["data"]["result"]


def get_request_rates():
    """Raw Istio request rates per ICAP version (a/b/c)."""
    query = (
        'rate(istio_requests_total{'
        'destination_service="icap-service.default.svc.cluster.local",'
        'response_code="200"}[1m])'
    )

    results = query_prometheus(query)
    rates = {}

    for item in results:
        version = item["metric"].get("destination_version")
        value = float(item["value"][1])

        if version in _service_registry:
            rates[version] = rates.get(version, 0) + value

    return rates


def get_health_weighted_rates() -> dict:
    """
    Returns per-version request rates adjusted by ICAP operator health scores.

    Versions whose instance health score falls below ICAP_INSTANCE_HEALTHY_FLOOR
    have their effective rate inflated (making them look busy) so the SSDLB
    avoids routing all traffic there in single mode.
    """
    rates  = get_request_rates()
    health = get_icap_health()
    instances = health.get("instances", {})

    if not instances:
        return rates  # no health data → use raw rates unchanged

    weighted = {}
    for ver, rate in rates.items():
        score = instances.get(ver, {}).get("health_score", 100)
        if score < ICAP_INSTANCE_HEALTHY_FLOOR:
            # Penalise: treat the version as if it is 3× as loaded
            penalty = 3.0 * (ICAP_INSTANCE_HEALTHY_FLOOR - score) / ICAP_INSTANCE_HEALTHY_FLOOR
            weighted[ver] = rate * (1.0 + penalty)
            log_compliance_event(
                "icap_health_penalty_applied",
                version=ver,
                health_score=score,
                raw_rate=rate,
                effective_rate=weighted[ver],
            )
        else:
            weighted[ver] = rate

    return weighted


def get_total_rate(window: str):
    query = (
        f'rate(istio_requests_total{{'
        f'destination_service="icap-service.default.svc.cluster.local",'
        f'response_code="200"}}[{window}])'
    )

    results = query_prometheus(query)

    total = 0.0
    for item in results:
        total += float(item["value"][1])

    return total


def get_queue_depth() -> Dict[str, Any]:
    """
    Query Prometheus for ICAP request queue depth metrics.
    Returns per-version queue depths and aggregate statistics.
    """
    try:
        # Query for pending/queued requests (icap_queue_depth or http connection backlog)
        queue_query = (
            'icap_queue_depth{service="icap-service"}'
        )
        results = query_prometheus(queue_query)
        depths = {}
        for item in results:
            ver = item["metric"].get("version", "unknown")
            depths[ver] = float(item["value"][1])

        if not depths:
            # Fallback: infer queue depth from rate differential
            short = get_total_rate("30s")
            medium = get_total_rate("5m")
            inferred_backlog = max(0.0, short - medium)
            depths = {v: inferred_backlog / max(1, len(_service_registry)) for v in _service_registry}

        total_depth = sum(depths.values())
        max_ver = max(depths, key=depths.get) if depths else None

        return {
            "per_version": depths,
            "total_queue_depth": round(total_depth, 4),
            "max_queue_version": max_ver,
            "high_queue_detected": total_depth > 10.0,
        }
    except Exception as e:
        log_event("queue_depth_fetch_failed", error=str(e))
        return {"per_version": {}, "total_queue_depth": 0.0, "max_queue_version": None, "high_queue_detected": False}


@app.get("/queue-depth")
def queue_depth_endpoint():
    """Return current ICAP request queue depths from Prometheus."""
    return get_queue_depth()


def detect_rising_trend():
    short_rate = get_total_rate("1m")
    medium_rate = get_total_rate("5m")

    if medium_rate == 0:
        return False, short_rate, medium_rate

    growth = (short_rate - medium_rate) / medium_rate

    return growth >= TREND_ENTER_GROWTH_RATIO, short_rate, medium_rate


@app.get("/trend-debug")
def trend_debug():
    short_rate = get_total_rate("1m")
    medium_rate = get_total_rate("5m")

    if medium_rate == 0:
        growth = None
    else:
        growth = (short_rate - medium_rate) / medium_rate

    return {
        "short_rate_1m": short_rate,
        "medium_rate_5m": medium_rate,
        "growth_ratio": growth,
        "enter_threshold": TREND_ENTER_GROWTH_RATIO,
        "exit_threshold": TREND_EXIT_GROWTH_RATIO
    }


@app.get("/generate-dr/{version}")
def generate_destination_rule(version: str, weight: int = 100):
    """Generate Istio DestinationRule YAML dynamically for a given version."""
    if version not in _service_registry:
        return {"error": "version not registered"}

    if version == "spread":
        # Equal-weight spread across all registered versions
        registered = list(_service_registry.keys())
        n = len(registered)
        per_weight = 100 // n
        remainder = 100 - (per_weight * n)
        subsets = []
        for i, v in enumerate(registered):
            w = per_weight + (remainder if i == 0 else 0)
            subsets.append(f"    - labels:\n        version: {v}\n      weight: {w}")
        subsets_yaml = "\n".join(subsets)
        yaml_content = f"""apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: icap-service-dr
  namespace: default
spec:
  host: icap-service.default.svc.cluster.local
  trafficPolicy:
    loadBalancer:
      simple: ROUND_ROBIN
  subsets:
{chr(10).join(f'  - name: v{v}{chr(10)}    labels:{chr(10)}      version: {v}' for v in registered)}
---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: icap-service-vs
  namespace: default
spec:
  hosts:
  - icap-service.default.svc.cluster.local
  http:
  - route:
{subsets_yaml}
"""
    else:
        svc_weight = min(100, max(1, weight))
        yaml_content = f"""apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: icap-service-dr
  namespace: default
spec:
  host: icap-service.default.svc.cluster.local
  subsets:
  - name: v{version}
    labels:
      version: {version}
---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: icap-service-vs
  namespace: default
spec:
  hosts:
  - icap-service.default.svc.cluster.local
  http:
  - route:
    - destination:
        host: icap-service.default.svc.cluster.local
        subset: v{version}
      weight: {svc_weight}
"""

    log_event("dr_generated", version=version, weight=weight)
    return {"version": version, "yaml": yaml_content, "generated_at": datetime.now(timezone.utc).isoformat()}


@app.post("/apply-dr/{version}")
def apply_dynamic_dr(version: str, weight: int = 100):
    """Generate and apply Istio DR dynamically (writes to temp file, then kubectl apply)."""
    import tempfile
    gen = generate_destination_rule(version, weight)
    if "error" in gen:
        return gen

    yaml_content = gen["yaml"]
    log_event("apply_dynamic_dr", version=version, yaml_length=len(yaml_content))

    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            tmp_path = f.name

        result = subprocess.run(
            ["kubectl", "apply", "-f", tmp_path],
            capture_output=True, text=True
        )
        os.unlink(tmp_path)

        if result.returncode != 0:
            log_event("apply_dynamic_dr_failed", version=version, error=result.stderr)
            return {"error": result.stderr, "yaml": yaml_content}

        log_event("apply_dynamic_dr_success", version=version)
        return {"status": "ok", "applied_version": version, "kubectl": result.stdout}
    except Exception as e:
        log_event("apply_dynamic_dr_error", version=version, error=str(e))
        return {"error": str(e)}


def apply_version(version: str):
    dr_path = os.path.join(DR_DIR, f"dr-{version}.yaml")
    return subprocess.run(
        ["kubectl", "apply", "-f", dr_path],
        capture_output=True,
        text=True
    )


@app.post("/auto-route")
def auto_route():
    state = load_state()
    now = int(time.time())
    log_event("auto_route_called", state=state, now=now)
   
    # Observation window
    if state["last_switch_ts"] == 0:
        state["last_switch_ts"] = now
        save_state(state)

        log_event(
            "guardrail_initial_warmup",
            required_seconds=MIN_METRIC_WINDOW_SECONDS,
            state=state
        )

        return {
            "status": "warming-up",
            "required_seconds": MIN_METRIC_WINDOW_SECONDS
        }

    if (now - int(state["last_switch_ts"])) < MIN_METRIC_WINDOW_SECONDS:
        elapsed = now - int(state["last_switch_ts"])

        log_event(
            "guardrail_warming_up",
            seconds_elapsed=elapsed,
            required_seconds=MIN_METRIC_WINDOW_SECONDS,
            state=state
        )

        return {
            "status": "warming-up",
            "seconds_elapsed": elapsed,
            "required_seconds": MIN_METRIC_WINDOW_SECONDS
        }

    # Cooldown
    if state["last_selected"] and (now - int(state["last_switch_ts"])) < COOLDOWN_SECONDS:
        remaining = COOLDOWN_SECONDS - (now - int(state["last_switch_ts"]))

        log_event(
            "guardrail_cooldown",
            seconds_remaining=remaining,
            last_selected=state.get("last_selected"),
            state=state
        )

        return {
            "status": "cooldown",
            "last_selected": state["last_selected"],
            "seconds_remaining": remaining
        }

    # Check ICAP operator health — force spread if aggregate score is degraded
    icap_health = get_icap_health()
    agg_score   = icap_health.get("aggregate_health_score", 100)
    if icap_health and agg_score < ICAP_HEALTH_SPREAD_THRESHOLD and state.get("mode") != "spread":
        result = subprocess.run(
            ["kubectl", "apply", "-f", os.path.join(DR_DIR, "dr-spread.yaml")],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            state["mode"]           = "spread"
            state["last_selected"]  = "spread"
            state["last_switch_ts"] = now
            state["spread_since_ts"] = now
            save_state(state)
            log_compliance_event(
                "icap_health_forced_spread",
                aggregate_health_score=agg_score,
                threshold=ICAP_HEALTH_SPREAD_THRESHOLD,
            )
            return {
                "status":                  "icap-health-spread",
                "aggregate_health_score":  agg_score,
                "threshold":               ICAP_HEALTH_SPREAD_THRESHOLD,
            }

    # Query health-weighted rates
    try:
        rates = get_health_weighted_rates()
    except Exception as e:
        return {"status": "no-metrics", "reason": str(e)}

    try:
        rising, short_rate, medium_rate = detect_rising_trend()
    except Exception:
        rising = False
        short_rate = 0.0
        medium_rate = 0.0

    # ------------------------
    # SPREAD MODE RECOVERY LOGIC
    # ------------------------
    if state.get("mode") == "spread":
        spread_since = int(state.get("spread_since_ts") or now)

        if (now - spread_since) < SPREAD_MIN_SECONDS:
            return {
                "status": "spread-hold",
                "seconds_in_spread": now - spread_since,
                "min_seconds": SPREAD_MIN_SECONDS
            }

        log_event(
            "spread_continue",
            short_rate=short_rate,
            medium_rate=medium_rate,
            exit_threshold=TREND_EXIT_GROWTH_RATIO,
            state=state
        )


        if rising:
            return {
                "status": "spread-continue",
                "short_rate": short_rate,
                "medium_rate": medium_rate
            }

        if medium_rate <= 0:
            return {
                "status": "spread-continue",
                "reason": "medium_rate_zero"
            }

        growth_ratio = (short_rate - medium_rate) / medium_rate

        if growth_ratio > TREND_EXIT_GROWTH_RATIO:
            return {
                "status": "spread-continue",
                "growth_ratio": growth_ratio,
                "exit_threshold": TREND_EXIT_GROWTH_RATIO,
                "short_rate": short_rate,
                "medium_rate": medium_rate
            }

        # Collapse back to single — pick the healthiest (lowest effective load) version
        if not rates:
            return {"status": "no-metrics", "reason": "empty rates"}

        selected = min(rates, key=rates.get)  # lowest effective rate = least loaded + healthiest
        result = apply_version(selected)

        if result.returncode != 0:
            return {"status": "error", "kubectl": result.stderr}

        state["mode"] = "single"
        state["last_selected"] = selected
        state["last_switch_ts"] = now
        state["spread_since_ts"] = 0
        save_state(state)

        log_compliance_event(
            "recovered_to_single",
            selected=selected,
            rates=rates,
            exit_threshold=TREND_EXIT_GROWTH_RATIO,
            state=state
        )

        return {
            "status": "recovered-to-single",
            "selected": selected,
            "rates": rates
        }

    # ------------------------
    # PREDICTIVE SPREAD ENTRY
    # ------------------------
    if rising:
        result = subprocess.run(
            ["kubectl", "apply", "-f", os.path.join(DR_DIR, "dr-spread.yaml")],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return {"status": "error", "kubectl": result.stderr}

        state["mode"] = "spread"
        state["last_selected"] = "spread"
        state["last_switch_ts"] = now
        state["spread_since_ts"] = now
        save_state(state)

        log_compliance_event(
            "predictive_spread_entered",
            short_rate=short_rate,
            medium_rate=medium_rate,
            enter_threshold=TREND_ENTER_GROWTH_RATIO if "TREND_ENTER_GROWTH_RATIO" in globals() else None,
            state_before=state,
        )

        return {
            "status": "predictive-spread",
            "short_rate": short_rate,
            "medium_rate": medium_rate
        }

    # ------------------------
    # NORMAL SINGLE MODE LOGIC
    # ------------------------
    if not rates:
        return {"status": "no-metrics", "reason": "empty rates"}

    total_rate = sum(rates.values())
    if total_rate < MIN_TOTAL_RATE:
        log_event(
            "guardrail_low_traffic",
            total_rate=total_rate,
            threshold=MIN_TOTAL_RATE,
            rates=rates,
            state=state
        )
        return {
            "status": "low-traffic",
            "total_rate": total_rate,
            "threshold": MIN_TOTAL_RATE
        }

    selected = min(rates, key=rates.get)

    last = state["last_selected"]
    if last in rates and last != selected:
        last_rate = rates[last]
        sel_rate = rates[selected]

        if last_rate > 0:
            improvement_ratio = (last_rate - sel_rate) / last_rate
        else:
            improvement_ratio = 1.0

        if improvement_ratio < MIN_CHANGE_RATIO:
 
           log_event(
               "no_switch_min_change",
               last_selected=last,
               candidate=selected,
               improvement_ratio=improvement_ratio,
               threshold=MIN_CHANGE_RATIO,
               rates=rates,
               state=state
           )

           return {
                "status": "no-switch",
                "reason": "min-change-threshold",
                "rates": rates,
                "last_selected": last,
                "candidate": selected,
                "improvement_ratio": improvement_ratio
            }

    result = apply_version(selected)
    if result.returncode != 0:
        return {"status": "error", "kubectl": result.stderr}

    state["mode"] = "single"
    state["last_selected"] = selected
    state["last_switch_ts"] = now
    save_state(state)

    return {
        "status": "ok",
        "rates": rates,
        "selected": selected
    }
