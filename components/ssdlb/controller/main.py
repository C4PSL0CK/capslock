from fastapi import FastAPI
import subprocess
import os
import requests
import time
import json

PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://localhost:9090")

# Guardrails (tune later)
COOLDOWN_SECONDS = int(os.getenv("COOLDOWN_SECONDS", "60"))
MIN_CHANGE_RATIO = float(os.getenv("MIN_CHANGE_RATIO", "0.20"))  # 20% improvement required

MIN_TOTAL_RATE = float(os.getenv("MIN_TOTAL_RATE", "0.05"))  # minimum traffic required
MIN_METRIC_WINDOW_SECONDS = int(os.getenv("MIN_METRIC_WINDOW_SECONDS", "120"))

TREND_GROWTH_RATIO = float(os.getenv("TREND_GROWTH_RATIO", "0.30"))  # 30% spike triggers spread

app = FastAPI()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DR_DIR = os.path.join(BASE_DIR, "dr-files")
STATE_FILE = os.path.join(BASE_DIR, "state.json")

ALLOWED_VERSIONS = {"a", "b", "c"}


def load_state():
    # Default state
    state = {"last_selected": None, "last_switch_ts": 0}

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


@app.post("/set-version/{version}")
def set_version(version: str):
    if version not in ALLOWED_VERSIONS:
        return {"error": "invalid version"}

    path = os.path.join(DR_DIR, f"dr-{version}.yaml")
    if not os.path.exists(path):
        return {"error": "dr file not found", "path": path}

    result = subprocess.run(
        ["kubectl", "apply", "-f", path],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        return {"error": result.stderr}

    # Update state (manual switch counts as a switch)
    state = load_state()
    state["last_selected"] = version
    state["last_switch_ts"] = int(time.time())
    save_state(state)

    return {"status": "ok", "applied": path}


def query_prometheus(query: str):
    r = requests.get(
        f"{PROMETHEUS_URL}/api/v1/query",
        params={"query": query},
        timeout=5
    )
    r.raise_for_status()
    return r.json()["data"]["result"]


def get_request_rates():
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

        if version in ALLOWED_VERSIONS:
            rates[version] = rates.get(version, 0) + value

    return rates


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


def detect_rising_trend():
    short_rate = get_total_rate("1m")
    medium_rate = get_total_rate("5m")

    if medium_rate == 0:
        return False, short_rate, medium_rate

    growth = (short_rate - medium_rate) / medium_rate

    return growth > TREND_GROWTH_RATIO, short_rate, medium_rate


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
        "threshold": TREND_GROWTH_RATIO
    }


def apply_version(version: str):
    dr_path = os.path.join(DR_DIR, f"dr-{version}.yaml")
    return subprocess.run(
        ["kubectl", "apply", "-f", dr_path],
        capture_output=True,
        text=True
    )


@app.post("/auto-route")
def auto_route():
    # 1) Load persisted state
    state = load_state()
    now = int(time.time())

    # Observation window guardrail
    if state["last_switch_ts"] == 0:
        state["last_switch_ts"] = now
        save_state(state)
        return {"status": "warming-up", "required_seconds": MIN_METRIC_WINDOW_SECONDS}

    if (now - int(state["last_switch_ts"])) < MIN_METRIC_WINDOW_SECONDS:
        return {
            "status": "warming-up",
            "seconds_elapsed": now - int(state["last_switch_ts"]),
            "required_seconds": MIN_METRIC_WINDOW_SECONDS
        }

    # Cooldown guardrail
    if state["last_selected"] and (now - int(state["last_switch_ts"])) < COOLDOWN_SECONDS:
        remaining = COOLDOWN_SECONDS - (now - int(state["last_switch_ts"]))
        return {
            "status": "cooldown",
            "last_selected": state["last_selected"],
            "seconds_remaining": remaining
        }

    # Query metrics safely
    try:
        rates = get_request_rates()
    except Exception as e:
        return {"status": "no-metrics", "reason": str(e)}

    if not rates:
        return {"status": "no-metrics", "reason": "empty rates"}

    # Traffic presence guardrail
    total_rate = sum(rates.values())
    if total_rate < MIN_TOTAL_RATE:
        return {
            "status": "low-traffic",
            "total_rate": total_rate,
            "threshold": MIN_TOTAL_RATE
        }

    # Predictive Trend Detection
    rising, short_rate, medium_rate = detect_rising_trend()

    if rising:
        result = subprocess.run(
            ["kubectl", "apply", "-f", os.path.join(DR_DIR, "dr-spread.yaml")],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return {"status": "error", "kubectl": result.stderr}

        state["last_selected"] = "spread"
        state["last_switch_ts"] = now
        save_state(state)

        return {
            "status": "predictive-spread",
            "short_rate": short_rate,
            "medium_rate": medium_rate,
            "growth_threshold": TREND_GROWTH_RATIO
        }

    # Choose least-loaded version
    selected = min(rates, key=rates.get)

    # Minimum-change threshold
    last = state["last_selected"]
    if last in rates and last != selected:
        last_rate = rates[last]
        sel_rate = rates[selected]

        if last_rate > 0:
            improvement_ratio = (last_rate - sel_rate) / last_rate
        else:
            improvement_ratio = 1.0

        if improvement_ratio < MIN_CHANGE_RATIO:
            return {
                "status": "no-switch",
                "reason": "min-change-threshold",
                "rates": rates,
                "last_selected": last,
                "candidate": selected,
                "improvement_ratio": improvement_ratio
            }

    # Apply routing
    result = apply_version(selected)
    if result.returncode != 0:
        return {"status": "error", "kubectl": result.stderr}

    # Persist state
    state["last_selected"] = selected
    state["last_switch_ts"] = now
    save_state(state)

    return {
        "status": "ok",
        "rates": rates,
        "selected": selected,
        "applied": f"dr-files/dr-{selected}.yaml",
        "cooldown_seconds": COOLDOWN_SECONDS,
        "min_change_ratio": MIN_CHANGE_RATIO
    }
