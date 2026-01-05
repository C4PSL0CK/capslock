from fastapi import FastAPI
import subprocess
import os
import requests

PROMETHEUS_URL = "http://localhost:9090"

app = FastAPI()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DR_DIR = os.path.join(BASE_DIR, "dr-files")


@app.get("/")
def health():
    return {"status": "controller alive"}


@app.post("/set-version/{version}")
def set_version(version: str):
    path = os.path.join(DR_DIR, f"dr-{version}.yaml")

    if not os.path.exists(path):
        return {"error": "invalid version"}

    result = subprocess.run(
        ["kubectl", "apply", "-f", path],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        return {"error": result.stderr}

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

        if version:
            rates[version] = rates.get(version, 0) + value

    return rates


def apply_version(version: str):
    dr_path = os.path.join(DR_DIR, f"dr-{version}.yaml")
    subprocess.run(["kubectl", "apply", "-f", dr_path])


@app.post("/auto-route")
def auto_route():
    rates = get_request_rates()

    if not rates:
        return {"status": "error", "reason": "no metrics"}

    selected = min(rates, key=rates.get)
    apply_version(selected)

    return {
        "status": "ok",
        "rates": rates,
        "selected": selected,
        "applied": f"dr-files/dr-{selected}.yaml"
    }

