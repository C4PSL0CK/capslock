# Policy Engine (EAPE)

**Environment-Aware Policy Engine** | Component 2 of CAPSLOCK | Go + Python bridge

**Project ID:** 25-26J-043 | **Version:** 1.0.0

## Overview

The Policy Engine has two layers:

1. **Go binary** (`cmd/policy-engine`): detects Kubernetes environment types, selects and applies policies via OPA Gatekeeper / Kyverno, resolves conflicts between competing policies.
2. **Python FastAPI bridge** (`api/main.py`): REST API that MEDS and SSDLB call. Manages ICAP operator CRD state, provides integration endpoints, and persists configuration locally when a K8s cluster is unavailable.

## Features

- Automatic environment detection from namespace labels
- Policy conflict detection and resolution (compliance-first, priority, risk-level strategies)
- OPA Gatekeeper and Kyverno integration
- ICAP operator CRD management via Kubernetes client
- Local state persistence: scanning mode and replica config saved to `icap_local_state.json`, surviving cluster unavailability
- Lazy Kubernetes client: only loaded when a cluster is reachable, preventing startup delays
- REST API for MEDS, SSDLB, and CLI automation
- 83.6% test coverage on Go code

## Architecture

```
Environment Detection -> Policy Selection -> Conflict Resolution -> Policy Application
                                                                         |
                                                               ICAP Operator CRD
                                                                    (K8s or local)
```

**7-Step Workflow:**
1. Detect environment from namespace labels
2. Select optimal policy based on environment
3. Detect conflicts (if multiple candidates)
4. Resolve conflicts using configured strategy
5. Apply policy via ICAP Operator
6. Report status to MEDS
7. Verify services via SSDLB

## Quick Start

### Go CLI

```bash
go build -o bin/policy-engine ./cmd/policy-engine

# List policies
./bin/policy-engine list

# Detect environment
./bin/policy-engine detect -n dev-test

# Apply policy
./bin/policy-engine apply -n prod-test

# Start API server
./bin/policy-engine serve --port 8080
```

### Python Bridge (API)

```bash
cd api
pip install fastapi uvicorn httpx kubernetes
uvicorn main:app --port 8081
```

Started automatically by `start.sh`.

## Project Structure

```
policy-engine/
├── cmd/policy-engine/           # Go CLI binary
├── pkg/
│   ├── api/                     # REST API handlers and router
│   ├── conflict/                # Conflict detection and resolution
│   ├── detector/                # Environment detection
│   ├── engine/                  # Policy orchestration
│   ├── integrations/            # OPA/Kyverno format converters
│   ├── mocks/                   # Mock CAPSLock components for testing
│   └── policy/                  # Policy management
├── policies/templates/          # YAML policy definitions
├── api/
│   └── main.py                  # Python FastAPI bridge (ICAP operator + integrations)
├── tests/
│   ├── e2e/                     # End-to-end tests
│   ├── integration/             # API integration tests
│   └── performance/             # Benchmarks
└── docs/                        # Documentation
```

## Python Bridge API Endpoints

### ICAP Operator
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/icap/operator/status` | Full ICAPService CRD status |
| GET | `/api/icap/health` | Compact health summary for SSDLB and dashboard |
| POST | `/api/icap/operator/configure` | Apply scanning mode / replica count to CRD |

**Configuration persistence:** `configure` always saves to `icap_local_state.json` first, then attempts a K8s CRD patch as best-effort. This ensures the UI reflects the correct state even when the cluster is unavailable.

### Integration
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/integration/meds/notify` | Receive deployment notifications from MEDS |
| GET | `/api/integration/icap/policy-status/{namespace}` | Check namespace policy approval |
| GET | `/api/integration/ssdlb/status` | SSDLB load-balancer state |

## Scanning Modes

| Mode | Behaviour |
|------|-----------|
| `block` | Scan and block any detected threat (default) |
| `warn` | Scan and log warning, never block |
| `log-only` | Scan and record, no enforcement |

Mode is persisted locally in `icap_local_state.json` and respected by the MEDS scanner on every deployment.

## Lazy Kubernetes Client

The Python bridge uses a lazy-loaded K8s client:

```python
K8S_AVAILABLE = None  # None = not yet probed

def _ensure_k8s() -> bool:
    # Tries incluster config, then kubeconfig
    # Caches result, only probes once per process lifetime
```

This prevents the API from blocking at startup when no cluster is present, and avoids import-time errors from the `kubernetes` library.

## Conflict Resolution Strategies

| Strategy | Logic |
|----------|-------|
| Compliance-first | Policy with the most compliance framework coverage wins |
| Priority | Explicit priority field on policy metadata |
| Risk-level | Lower risk policy preferred |

## Go Testing

```bash
# All tests
go test ./... -v

# With coverage
go test ./... -cover

# E2E
go test ./tests/e2e/ -v

# Integration
go test ./tests/integration/ -v

# Benchmarks
go test ./tests/performance/ -bench=. -benchmem
```

## Test Coverage (Go)

| Package | Coverage |
|---------|----------|
| conflict | 89.9% |
| detector | 80.0% |
| policy | 83.5% |
| opa | 82.6% |
| mocks | 95.8% |
| **Overall** | **83.6%** |

## Performance (Go)

| Operation | Latency |
|-----------|---------|
| Policy selection | 882 ns/op |
| Conflict detection | 7.2 µs/op |
| Environment detection | 180 ms/op |
| Full workflow | 163 ms/op |

## Integration with Other Components

| Component | Interaction |
|-----------|-------------|
| MEDS | Receives deployment notifications, provides ICAP health, scanning mode |
| SSDLB | Provides aggregate ICAP health for routing decisions |
| ICAP Operator | Patches ICAPService CRD spec; fallback to local state |

## Technologies

- Go 1.21+
- Python 3.11+ / FastAPI
- Kubernetes client-go + `kubernetes` Python client
- OPA Gatekeeper / Kyverno
- YAML policy templates

## Academic Submission

- Student: Kaavya
- Project: 25-26J-043
- Completion: 43/43 tasks (100%)
- Test Coverage: 83.6%
