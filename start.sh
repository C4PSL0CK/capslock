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
    echo -e "${BLUE}[1/4] Creating virtual environment...${NC}"
    python3 -m venv "$VENV"
else
    echo -e "${BLUE}[1/4] Using existing virtual environment...${NC}"
fi

PIP="$VENV/bin/pip"
UVICORN="$VENV/bin/uvicorn"

"$PIP" install -q --upgrade pip
"$PIP" install -q -r "$ROOT/components/ssdlb/controller/requirements.txt"
"$PIP" install -q -r "$ROOT/components/policy-engine/api/requirements.txt"
"$PIP" install -q -r "$ROOT/components/meds-research/requirements.txt"

# ── 2. Start SSDLB (port 8082) ───────────────────────────────────────────────
echo -e "${BLUE}[2/4] Starting SSDLB controller...${NC}"
cd "$ROOT/components/ssdlb/controller"
POLICY_ENGINE_URL=http://localhost:8001 \
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
echo -e "${BLUE}[3/4] Starting Policy Engine...${NC}"
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
echo -e "${BLUE}[4/4] Starting MEDS...${NC}"
cd "$ROOT/components/meds-research"
POLICY_ENGINE_URL=http://localhost:8001 \
ICAP_SERVICE_HOST="" \
ICAP_SERVICE_PORT=1344 \
    "$UVICORN" meds.api.main:app --host 0.0.0.0 --port 8000 --log-level warning \
    > /tmp/capslock-meds.log 2>&1 &
PIDS+=($!)

for i in {1..15}; do
    if curl -sf http://localhost:8000/api/environments > /dev/null 2>&1; then break; fi
    sleep 1
done

# ── Ready ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         CAPSLock is running                  ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  MEDS dashboard   →  http://localhost:8000   ║${NC}"
echo -e "${GREEN}║  Policy Engine    →  http://localhost:8001   ║${NC}"
echo -e "${GREEN}║  SSDLB controller →  http://localhost:8082   ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Logs: /tmp/capslock-*.log                   ║${NC}"
echo -e "${GREEN}║  Press Ctrl+C to stop                        ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""

wait
