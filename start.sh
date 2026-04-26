#!/usr/bin/env bash
# CAPSLock – single-command startup
# Usage: ./start.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
VENV="$ROOT/.venv"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

PIDS=()

# ── API keys ──────────────────────────────────────────────────────────────────
# Load from .env if present (key is never committed to git)
if [[ -f "$ROOT/.env" ]]; then
    set -a; source "$ROOT/.env"; set +a
fi

# ── Kubernetes detection ──────────────────────────────────────────────────────
# Use k3s kubeconfig if KUBECONFIG is not already set
if [[ -z "${KUBECONFIG:-}" && -f /etc/rancher/k3s/k3s.yaml ]]; then
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
fi

# Detect whether a K8s cluster is reachable
K8S_AVAILABLE=false
if [[ -n "${KUBECONFIG:-}" ]] && command -v kubectl &>/dev/null; then
    kubectl get nodes --request-timeout=5s &>/dev/null 2>&1 && K8S_AVAILABLE=true || true
elif command -v k3s &>/dev/null; then
    k3s kubectl get nodes --request-timeout=5s &>/dev/null 2>&1 && K8S_AVAILABLE=true || true
fi

if $K8S_AVAILABLE; then
    echo -e "${GREEN}[k8s] Cluster reachable, icap-operator will be started${NC}"
else
    echo -e "${YELLOW}[k8s] No cluster detected. ICAP config stored locally (run sudo ./setup-k8s.sh to connect)${NC}"
fi

cleanup() {
    echo -e "\n${YELLOW}Stopping all services...${NC}"
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    echo -e "${YELLOW}Done.${NC}"
}
trap cleanup EXIT INT TERM

# ── 1. Virtual environment ────────────────────────────────────────────────────
if [ ! -d "$VENV" ]; then
    echo -e "${BLUE}[1/5] Creating virtual environment...${NC}"
    python3 -m venv "$VENV"
else
    echo -e "${BLUE}[1/5] Using existing virtual environment...${NC}"
fi

PIP="$VENV/bin/pip"
UVICORN="$VENV/bin/uvicorn"

"$PIP" install -q --upgrade pip
"$PIP" install -q -r "$ROOT/components/ssdlb/controller/requirements.txt"
"$PIP" install -q -r "$ROOT/components/policy-engine/api/requirements.txt"
"$PIP" install -q -r "$ROOT/components/meds-research/requirements.txt"

# ── 2. Start icap-operator (if cluster available and binary exists) ──────────
OPERATOR_BIN="$ROOT/components/icap-operator/bin/manager"
if $K8S_AVAILABLE && [[ -f "$OPERATOR_BIN" ]]; then
    echo -e "${BLUE}[2/5] Starting icap-operator...${NC}"
    cd "$ROOT/components/icap-operator"
    "$OPERATOR_BIN" \
        > /tmp/capslock-icap-operator.log 2>&1 &
    PIDS+=($!)
    echo -e "${GREEN}      icap-operator running (PID ${PIDS[-1]})${NC}"
elif $K8S_AVAILABLE && [[ ! -f "$OPERATOR_BIN" ]]; then
    echo -e "${YELLOW}[2/5] Cluster found but operator not built. Run: sudo ./setup-k8s.sh${NC}"
else
    echo -e "${YELLOW}[2/5] Skipping icap-operator (no cluster)${NC}"
fi

# ── Prometheus (port 9090) ────────────────────────────────────────────────────
PROMETHEUS_BIN="${HOME}/.local/bin/prometheus"
if [[ -x "$PROMETHEUS_BIN" ]]; then
    echo -e "${BLUE}[+] Starting Prometheus...${NC}"
    "$PROMETHEUS_BIN" \
        --config.file="$ROOT/prometheus.yml" \
        --storage.tsdb.path="/tmp/capslock-prometheus-data" \
        --web.listen-address="0.0.0.0:9090" \
        --log.level=warn \
        > /tmp/capslock-prometheus.log 2>&1 &
    PIDS+=($!)
fi

# ── 3. Start SSDLB (port 8082) ───────────────────────────────────────────────
echo -e "${BLUE}[3/5] Starting SSDLB controller...${NC}"
cd "$ROOT/components/ssdlb/controller"
POLICY_ENGINE_URL=http://localhost:8001 \
PROMETHEUS_URL=http://localhost:9090 \
ICAP_HEALTH_SPREAD_THRESHOLD=70 \
ICAP_INSTANCE_HEALTHY_FLOOR=60 \
    "$UVICORN" main:app --host 0.0.0.0 --port 8082 --log-level warning \
    > /tmp/capslock-ssdlb.log 2>&1 &
PIDS+=($!)

for i in {1..15}; do
    if curl -sf http://localhost:8082/ > /dev/null 2>&1; then break; fi
    sleep 1
done

# ── 3. Start Policy Engine (port 8001) ───────────────────────────────────────
echo -e "${BLUE}[4/5] Starting Policy Engine...${NC}"
cd "$ROOT/components/policy-engine"
SSDLB_URL=http://localhost:8082 \
ICAP_NAMESPACE=capslock-system \
ICAP_SERVICE_NAME=capslock-icap \
    "$UVICORN" api.main:app --host 0.0.0.0 --port 8001 --log-level warning \
    > /tmp/capslock-policy-engine.log 2>&1 &
PIDS+=($!)

for i in {1..15}; do
    if curl -sf http://localhost:8001/ > /dev/null 2>&1; then break; fi
    sleep 1
done

# ── 4. Start MEDS (port 8000) ────────────────────────────────────────────────
echo -e "${BLUE}[5/5] Starting MEDS...${NC}"
cd "$ROOT/components/meds-research"
POLICY_ENGINE_URL=http://localhost:8001 \
SSDLB_URL=http://localhost:8082 \
ICAP_SERVICE_HOST="" \
ICAP_SERVICE_PORT=1344 \
GROQ_API_KEY="${GROQ_API_KEY:-}" \
    "$UVICORN" meds.api.main:app --host 0.0.0.0 --port 8000 --log-level warning \
    > /tmp/capslock-meds.log 2>&1 &
PIDS+=($!)

for i in {1..15}; do
    if curl -sf http://localhost:8000/api/environments > /dev/null 2>&1; then break; fi
    sleep 1
done

# ── Public tunnel via ngrok ────────────────────────────────────────────────────
TUNNEL_URL=""
NGROK_BIN="${HOME}/.local/bin/ngrok"
if [[ -x "$NGROK_BIN" ]] && "$NGROK_BIN" config check &>/dev/null; then
    echo -e "${BLUE}[+] Starting ngrok tunnel...${NC}"
    "$NGROK_BIN" http 8000 --domain=sleepiest-tautologously-grace.ngrok-free.dev --log=stdout --log-format=json \
        > /tmp/capslock-ngrok.log 2>&1 &
    PIDS+=($!)
    # Wait up to 10s for the public URL
    for i in {1..10}; do
        TUNNEL_URL=$(grep -oP '"url":"https://[^"]+' /tmp/capslock-ngrok.log 2>/dev/null \
            | head -1 | grep -oP 'https://.*' || true)
        [[ -n "$TUNNEL_URL" ]] && break
        sleep 1
    done
fi

# ── Ready ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         CAPSLock is running                  ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  CAPSLOCK         →  http://localhost:8000   ║${NC}"
echo -e "${GREEN}║  Policy Engine    →  http://localhost:8001   ║${NC}"
echo -e "${GREEN}║  SSDLB controller →  http://localhost:8082   ║${NC}"
echo -e "${GREEN}║  Prometheus       →  http://localhost:9090   ║${NC}"
if [[ -n "$TUNNEL_URL" ]]; then
echo -e "${GREEN}║  Public URL       →  ${TUNNEL_URL}  ║${NC}"
fi
echo -e "${GREEN}╠══════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Logs: /tmp/capslock-*.log                   ║${NC}"
echo -e "${GREEN}║  Press Ctrl+C to stop                        ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""

# Keep alive until Ctrl+C — ignore individual process exits so set -e
# does not fire when the icap-operator or any child exits on its own.
while true; do sleep 5; done
