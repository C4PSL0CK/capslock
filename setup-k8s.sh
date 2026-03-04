#!/usr/bin/env bash
# CAPSLock — one-time Kubernetes setup
#
# Installs: Go, kubectl, k3s (lightweight K8s, no Docker required)
# Sets up:  ICAPService CRD, capslock-system namespace, ICAPService instance
# Builds:   icap-operator binary (run it separately with: ./start.sh)
#
# Usage:
#   sudo ./setup-k8s.sh          # install everything
#   ./setup-k8s.sh --crd-only    # re-apply CRD/resource into existing cluster

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

step()  { echo -e "${BLUE}▶ $*${NC}"; }
ok()    { echo -e "${GREEN}✓ $*${NC}"; }
warn()  { echo -e "${YELLOW}⚠ $*${NC}"; }

CRD_ONLY=false
[[ "${1:-}" == "--crd-only" ]] && CRD_ONLY=true

# ── Determine kubectl binary ──────────────────────────────────────────────────
KUBECTL="kubectl"
command -v kubectl &>/dev/null || KUBECTL="k3s kubectl"

# ─────────────────────────────────────────────────────────────────────────────
# FULL INSTALL (needs sudo)
# ─────────────────────────────────────────────────────────────────────────────
if ! $CRD_ONLY; then
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Run with sudo for a full install:  sudo $0${NC}"
        echo "Or re-run with --crd-only if a cluster is already running."
        exit 1
    fi

    # ── 1. Go ─────────────────────────────────────────────────────────────────
    GO_VER="1.22.5"
    if ! command -v go &>/dev/null; then
        step "Installing Go ${GO_VER}..."
        curl -fsSL "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz" -o /tmp/go.tar.gz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm /tmp/go.tar.gz
        ln -sf /usr/local/go/bin/go   /usr/local/bin/go
        ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
        ok "Go $(go version)"
    else
        ok "Go already installed: $(go version)"
    fi

    # ── 2. k3s ────────────────────────────────────────────────────────────────
    if ! command -v k3s &>/dev/null; then
        step "Installing k3s (lightweight Kubernetes)..."
        curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--write-kubeconfig-mode=644" sh -
        ok "k3s installed"
    else
        ok "k3s already installed"
    fi

    # Make sure k3s is running
    if ! systemctl is-active --quiet k3s; then
        step "Starting k3s..."
        systemctl start k3s
    fi

    # Wait for the API server to be ready (up to 60s)
    step "Waiting for k3s API server..."
    for i in $(seq 1 30); do
        k3s kubectl get nodes &>/dev/null && break || true
        sleep 2
    done
    k3s kubectl get nodes
    ok "k3s cluster is ready"

    # Expose kubeconfig for regular (non-root) users
    KUBECONF=/etc/rancher/k3s/k3s.yaml
    chmod 644 "$KUBECONF"
    # Write a note so start.sh can pick it up
    REAL_USER="${SUDO_USER:-$USER}"
    PROFILE="/home/${REAL_USER}/.bashrc"
    if ! grep -q "KUBECONFIG" "$PROFILE" 2>/dev/null; then
        echo "export KUBECONFIG=${KUBECONF}" >> "$PROFILE"
        ok "Added KUBECONFIG to ${PROFILE}"
    fi
    export KUBECONFIG="$KUBECONF"
    KUBECTL="k3s kubectl"
fi

# ─────────────────────────────────────────────────────────────────────────────
# CRD + RESOURCE SETUP (runs as normal user with --crd-only, or as root above)
# ─────────────────────────────────────────────────────────────────────────────

# Make sure KUBECONFIG is set for k3s if running as non-root --crd-only
if [[ -f /etc/rancher/k3s/k3s.yaml && -z "${KUBECONFIG:-}" ]]; then
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
fi

# ── 3. Install ICAPService CRD ────────────────────────────────────────────────
step "Installing ICAPService CRD..."
$KUBECTL apply -f "$ROOT/components/icap-operator/config/crd/bases/security.capslock.io_icapservices.yaml"
ok "CRD installed"

# ── 4. Create namespace ───────────────────────────────────────────────────────
step "Creating capslock-system namespace..."
$KUBECTL create namespace capslock-system --dry-run=client -o yaml | $KUBECTL apply -f -
ok "Namespace ready"

# ── 5. Create ICAPService instance ────────────────────────────────────────────
step "Creating ICAPService instance (capslock-icap)..."
cat <<'EOF' | $KUBECTL apply -f -
apiVersion: security.capslock.io/v1alpha1
kind: ICAPService
metadata:
  name: capslock-icap
  namespace: capslock-system
  labels:
    app.kubernetes.io/name: capslock-operator
    app.kubernetes.io/part-of: capslock
spec:
  replicas: 3
  clamavConfig:
    image: "clamav/clamav:latest"
    signatureUpdateInterval: "1h"
  healthThresholds:
    maxLatency: "500ms"
    maxErrorRate: "0.05"
    maxSignatureAge: "24h"
  scalingPolicy:
    minReplicas: 2
    maxReplicas: 10
    targetHealthScore: 80
EOF
ok "ICAPService 'capslock-icap' created in capslock-system"

# ── 6. Build icap-operator binary ─────────────────────────────────────────────
step "Building icap-operator binary..."
cd "$ROOT/components/icap-operator"
export PATH="$PATH:/usr/local/go/bin"
go build -o bin/manager cmd/main.go
ok "Binary: components/icap-operator/bin/manager"
cd "$ROOT"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        Kubernetes cluster ready for CAPSLock                 ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Cluster:     k3s  (kubeconfig: /etc/rancher/k3s/k3s.yaml)  ║${NC}"
echo -e "${GREEN}║  CRD:         security.capslock.io/v1alpha1 ICAPService      ║${NC}"
echo -e "${GREEN}║  Resource:    capslock-icap  (capslock-system namespace)     ║${NC}"
echo -e "${GREEN}║  Operator:    components/icap-operator/bin/manager           ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Next:  source ~/.bashrc && ./start.sh                       ║${NC}"
echo -e "${GREEN}║  Check: kubectl get icapservice -n capslock-system           ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
