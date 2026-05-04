# Environment-Aware Policy Engine (EAPE)
## Technical Validation Report — How It Works, Results & Benchmarks

**Component:** EAPE — Component 2 of the CAPSLOCK Security Platform  
**Student ID:** IT22338716  
**Project ID:** 25-26J-043  
**Technology:** Go 1.21 + Python 3.11 (FastAPI bridge)  
**Version:** 1.0.0

---

## 1. Problem Statement

In a Kubernetes-based multi-environment deployment pipeline, the same application traverses development, staging, and production namespaces. Each environment carries fundamentally different security and compliance requirements — yet traditional policy tools apply a single static policy cluster-wide, or require operators to manually label every namespace. This creates two failure modes:

1. **Under-enforcement** — production workloads running under development-grade policies
2. **Over-enforcement** — development velocity blocked by production-level restrictions

EAPE solves this by automatically detecting which environment a Kubernetes namespace belongs to and applying the correct policy without human labelling, while still respecting explicit labels when they are present.

---

## 2. System Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         CAPSLOCK Platform                            │
│                                                                      │
│  ┌─────────────┐    policy gate    ┌────────────────────────────┐   │
│  │    MEDS     │ ────────────────► │  EAPE (this component)     │   │
│  │ Deployment  │ ◄──────────────── │  Port 8000 (Python bridge) │   │
│  │   System    │   compliance score│  Port 8080 (Go API server) │   │
│  └─────────────┘                   └────────────┬───────────────┘   │
│                                                  │                   │
│  ┌─────────────┐    health data    ┌─────────────▼───────────────┐  │
│  │    SSDLB    │ ◄──────────────── │   ICAP Operator CRD Mgmt    │  │
│  │  Load Bal.  │                   │   (scanning mode / replicas)│  │
│  └─────────────┘                   └─────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

EAPE has two layers:

| Layer | Language | Role |
|-------|----------|------|
| **Go binary** (`cmd/policy-engine`) | Go 1.21 | Environment detection, policy selection, compliance validation, conflict resolution |
| **Python bridge** (`api/main.py`) | Python / FastAPI | REST API consumed by MEDS and SSDLB; manages ICAP Operator CRD; persists state locally when K8s is unavailable |

---

## 3. How It Works — The 7-Step Policy Application Workflow

When MEDS promotes a deployment, it calls EAPE with the target namespace. EAPE executes the following pipeline entirely automatically:

```
Namespace name / labels
        │
        ▼
┌─────────────────────┐
│ Step 1: Environment │  Reads K8s namespace labels + infers from name
│       Detection     │  Produces: environment type + confidence score
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Step 2: Policy      │  Scores all loaded policy templates against the
│      Selection      │  environment context. Picks highest-scoring match.
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Step 3: Conflict    │  Compares all candidate policies pairwise across
│      Detection      │  5 conflict dimensions (see §5)
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Step 4: Conflict    │  Applies configured strategy to resolve conflicts
│      Resolution     │  (precedence / security-first / environment-aware)
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Step 5: Compliance  │  Runs CIS Benchmark v1.9 (28 checks) and PCI-DSS
│      Validation     │  v4.0 (16 requirements) against namespace config
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Step 6: Status      │  Reports compliance score + violation details
│      Reporting      │  back to MEDS. Blocks deployment if score < threshold.
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Step 7: Service     │  Verifies ICAP scanning service is healthy via SSDLB
│    Verification     │  before marking policy as applied.
└─────────────────────┘
```

---

## 4. Environment Detection — How Confidence Is Calculated

**Source:** `pkg/detector/environment_detector.go`

The detector uses a **7-factor weighted scoring algorithm** to assign an environment type and a confidence value in [0, 1]:

| Factor | Signal | Weight |
|--------|--------|--------|
| 1 | Primary K8s label present and valid (`environment`, `app.kubernetes.io/environment`, `env`) | +0.60 |
| 2 | Namespace name contains the environment token (`prod`, `staging`, `dev`) | +0.20 |
| 3 | Security-level label present (`security-level`, `security`) | +0.20 |
| 4–5 | Compliance labels (`compliance-pci-dss`, `compliance-cis`) — each +0.10, capped at +0.20 | +0.10 each |
| 6 | Cluster characteristics (node taints, cloud provider hints) via `ClusterDetector` | variable |
| 7 | No labels at all — name-only detection | 0.30 max |

**Example outcomes:**

| Namespace | Labels Present | Detected Environment | Confidence |
|-----------|---------------|---------------------|------------|
| `payment-prod` | `environment=prod`, `compliance-pci-dss=true` | production | 0.95 |
| `staging-test` | none | staging | 0.30 |
| `dev-team-alpha` | `environment=dev`, `security-level=low` | development | 0.80 |
| `default` | none | development (inferred) | 0.60 |

The confidence score is surfaced to MEDS so it can decide whether to require a human override below a threshold (e.g. confidence < 0.5).

---

## 5. Conflict Detection — 5 Dimensions

**Source:** `pkg/conflict/detector.go`

When multiple policy templates are candidates (e.g. a namespace matching both a dev and a prod template), EAPE performs pairwise comparison across five dimensions:

| Conflict Type | Example | Severity |
|---------------|---------|----------|
| `scanning_mode` | Policy A uses `block`; Policy B uses `log-only` | CRITICAL |
| `environment` | Policy A targets `production`; Policy B targets `development` | HIGH |
| `compliance` | Policy A has 2 standards; Policy B has 1 | HIGH |
| `resource_limit` | Policy A max file size 50 MB; Policy B 100 MB | MEDIUM |
| `security_level` | Implied by environment mismatch | LOW |

Each detected conflict receives a unique ID, a severity rating, the conflicting policy pair, and a human-readable description — all persisted to the audit log (F3, see §9).

---

## 6. Conflict Resolution — 3 Strategies

**Source:** `pkg/conflict/resolver.go`

| Strategy | Logic | Use Case |
|----------|-------|----------|
| `precedence` | Environment priority: prod (3) > staging (2) > dev (1) | Default — always deterministic |
| `security-first` | Strictest ICAP scanning mode wins: block (3) > warn (2) > log-only (1) | Zero-tolerance security posture |
| `environment-aware` | Policy whose target environment matches detected environment wins; falls back to precedence | Mixed-environment clusters |

Resolution decisions are recorded as `ConflictResolution` structs and returned in the API response alongside the chosen policy.

---

## 7. Compliance Validation

### CIS Kubernetes Benchmark v1.9

**Source:** `pkg/compliance/cis/` (6 files — validator, 5 section files, scoring, remediation)

28 controls across 5 sections:

| Section | Controls | What Is Checked |
|---------|----------|-----------------|
| 4.1 RBAC | 6 | Service account token automounting, cluster-admin bindings, wildcard permissions |
| 4.2 Pod Security | 8 | Privileged containers, host namespaces, read-only root filesystems, non-root UID, AppArmor |
| 4.3 Network Policies | 4 | Default-deny ingress/egress, namespace isolation |
| 4.4 Secrets Management | 5 | Secrets as env vars, encryption at rest, secret access scope |
| 4.5 Namespace Isolation | 5 | Resource quotas, limit ranges, label governance |

### PCI-DSS v4.0

**Source:** `pkg/compliance/pcidss/` (5 files — validator, requirements, controls, scoring, remediation)

16 requirements across 4 groups:

| Requirement | Area | Controls |
|-------------|------|----------|
| Req 3 | Stored data protection | Encryption, secret management |
| Req 4 | Transmission security | TLS enforcement, network policies |
| Req 6 | Secure systems | Image scanning, vulnerability patching |
| Req 10 | Audit logging | Event logging, tamper detection |

### Compliance Response Format

```json
{
  "overall_compliant": true,
  "overall_score": 0.98,
  "total_violations": 2,
  "cis": {
    "framework": "CIS Kubernetes Benchmark",
    "version": "v1.9",
    "score": 0.96,
    "passed": 26,
    "failed": 2
  },
  "pci_dss": {
    "framework": "PCI-DSS",
    "version": "v4.0",
    "score": 1.00,
    "passed": 16,
    "failed": 0
  }
}
```

Every failed control includes its rule ID, severity, description, and a concrete remediation step — returned to MEDS so the developer is told exactly what to fix.

---

## 8. Policy Templates — Environment Tiers

**Source:** `policies/templates/` (YAML) + `pkg/policy/types.go`

Three environment-specific templates, all inheriting from `base-policy.yaml` (F2 — Policy Inheritance):

| Template | Environment | Enforcement | ICAP Mode | Compliance Frameworks |
|----------|-------------|------------|-----------|----------------------|
| `dev-policy` | development | audit | log-only | CIS |
| `staging-policy` | staging | enforce | warn | CIS, PCI-DSS |
| `prod-policy` | production | strict | block | CIS, PCI-DSS |

**Base policy inheritance** — `base-policy.yaml` defines shared defaults (e.g. minimum file size limits, audit logging enabled). Environment templates deep-merge over the base, ensuring no baseline control is accidentally omitted even when a new template is added.

---

## 9. Advanced Features (F1, F2, F3)

### F1 — Continuous Change Detection

**Source:** `pkg/detector/detector.go` — `Watch()` method

Polls a namespace's environment on a configurable interval. Fires an `onChange` callback when the environment classification shifts (e.g. a namespace is relabelled from `dev` to `prod`). `PolicyEngine.StartWatching()` wires this to automatically re-apply the correct policy without manual intervention.

### F2 — Policy Inheritance

**Source:** `pkg/policy/types.go` — `LoadPolicyTemplateWithBase()`, `mergeTemplates()`, `deepMergeMap()`

Environment templates declare a `base:` field pointing to `base-policy.yaml`. The loader performs a recursive deep-merge: base values apply where the template is silent; template values always win where specified. Files prefixed with `base-` are excluded from the selectable template list.

### F3 — Conflict Audit Persistence

**Source:** `pkg/api/handlers.go` — `writeConflictAuditEntries()`, `HandleConflictAuditLog()`

Every conflict resolution event is appended as a JSONL entry to `/tmp/capslock-conflict-audit.jsonl` (path configurable via `CONFLICT_AUDIT_LOG` env var). The `GET /api/conflict-audit` endpoint streams these entries back to the dashboard, providing a persistent, inspectable audit trail of every policy decision the engine has ever made.

---

## 10. Performance Benchmarks

**Source:** `tests/performance/benchmark_test.go`  
**Run:** `go test ./tests/performance/ -bench=. -benchmem`

| Operation | Benchmark | Result | Notes |
|-----------|-----------|--------|-------|
| Policy selection | `BenchmarkPolicySelection` | **882 ns/op** | Sub-microsecond; negligible on critical path |
| Conflict detection | `BenchmarkConflictDetection` | **7,200 ns/op** | 7.2 µs for pairwise scan of all loaded templates |
| Environment detection | `BenchmarkEnvironmentDetection` | **180 ms/op** | Bounded by Kubernetes API round-trip |
| Full workflow (7 steps) | `BenchmarkPolicyApplication` | **163 ms/op** | Complete end-to-end |
| 3 namespaces sequential | `BenchmarkMultipleNamespaces` | **~490 ms/op** | ~163 ms per namespace |
| Memory per operation | | **~14 KB/op** | Stateless; no accumulation |

**Interpretation:** The compute-intensive steps (selection, conflict detection) are effectively free. End-to-end latency is dominated by the Kubernetes API call during environment detection. In-cluster deployments will see significantly lower latency than the local benchmark figures (~10–30 ms typical in-cluster vs ~180 ms local VM).

---

## 11. Test Coverage

**Run:** `go test ./... -cover`

| Package | Tests | Coverage |
|---------|-------|----------|
| `pkg/mocks` | 12 | **95.8%** |
| `pkg/conflict` | 8 | **89.9%** |
| `pkg/policy` | 10 | **83.5%** |
| `pkg/integrations/opa` | 6 | **82.6%** |
| `pkg/detector` | 9 | **80.0%** |
| **Overall** | **45+** | **83.6%** |

### End-to-End Test Results

| Test | Scenario | Outcome |
|------|----------|---------|
| `TestCompleteWorkflow_Dev` | Apply policy to `dev-test` | PASS — env=dev, policy=dev-policy, confidence≥0.8, status=deployed |
| `TestCompleteWorkflow_Staging` | Apply policy to `staging-test` | PASS — env=staging, policy=staging-policy |
| `TestCompleteWorkflow_Prod` | Apply policy to `prod-test` | PASS — env=prod, policy=prod-policy, healthy services≥1 |
| `TestMultipleNamespaces` | Apply to dev + staging + prod simultaneously | PASS — all 3 succeed, registry has ≥3 entries |
| `TestPolicyRemoval` | Apply then remove policy | PASS — no residual entry in registry |
| `TestErrorHandling` | Non-existent namespace; remove absent policy | PASS — both return errors (no silent failures) |

### Integration Test Results (httptest — no live cluster required)

| Test | Endpoint | Result |
|------|----------|--------|
| `TestHealthEndpoint` | `GET /health` → 200 | PASS |
| `TestDetectEndpoint` | `POST /api/detect` with `dev-test` → 200 | PASS |
| `TestPoliciesListEndpoint` | `GET /api/policies` → 200, non-empty | PASS |
| `TestPolicyGetEndpoint` | `GET /api/policies/get?name=dev-policy` → 200 | PASS |
| `TestConflictResolveEndpoint` | `POST /api/conflicts/resolve` strategy=security-first → 200 | PASS |
| `TestInvalidEndpoint` | `GET /api/invalid` → 404 | PASS |
| `TestMultipleRequests` | `GET /health` × 3 → all 200 | PASS |

---

## 12. Integration with Other CAPSLOCK Components

| Component | Direction | What EAPE Provides |
|-----------|-----------|-------------------|
| **MEDS** (C1) | MEDS → EAPE | Namespace environment detection, policy application, compliance score — MEDS blocks or allows deployment based on result |
| **MEDS** (C1) | EAPE → MEDS | Policy violation webhooks with rule ID, severity, and remediation text |
| **ICAP Operator** (C4) | ICAP → EAPE | `GET /api/integration/icap/policy-status/{namespace}` — ICAP checks if namespace has approved policy before scanning |
| **SSDLB** (C3) | SSDLB → EAPE | `GET /api/icap/health` — aggregate ICAP health score used for routing decisions |

**Deployment-blocked scenario (compliance failure):**
```
1. MEDS promotes image with privileged container to payment-prod
2. EAPE detects: CIS 4.2.1 violation (privileged container)
3. Returns: overall_compliant=false, score=0.62, violation details + remediation
4. MEDS blocks deployment and notifies developer with exact fix required
```

---

## 13. Design Decisions and Justification

| Decision | Rationale |
|----------|-----------|
| **Stateless Go core** | No database dependency; policy templates cached in memory; horizontally scalable |
| **YAML policy templates** | Human-readable, version-controllable, Kubernetes-native format; reviewable by security teams without code knowledge |
| **Confidence scoring over binary detection** | Allows MEDS to decide threshold for human override; more honest about ambiguous namespaces |
| **Lazy Kubernetes client** | API never blocks at startup when no cluster is present; Python bridge probes once and caches result |
| **Local state persistence** | `icap_local_state.json` ensures dashboard reflects correct scanning mode even during cluster outages |
| **mTLS support** | Inter-component calls can be secured with mutual TLS; `CA_CERT_PATH`, `MTLS_CERT_PATH`, `MTLS_KEY_PATH` env vars |
| **Dual interface (REST + CLI)** | REST API for automation; CLI (`./bin/policy-engine detect/apply/list`) for manual operations and debugging |

---

## 14. Running the Engine

```bash
# Build
cd components/policy-engine
go build -o bin/policy-engine ./cmd/policy-engine

# Run all tests
go test ./... -v

# Coverage report
go test ./... -cover

# Benchmarks
go test ./tests/performance/ -bench=. -benchmem

# Start API server
./bin/policy-engine serve --port 8080

# CLI usage
./bin/policy-engine detect -n prod-test
./bin/policy-engine apply  -n prod-test
./bin/policy-engine list
```

---

*Student ID: IT22338716 | Project: 25-26J-043 | Component 2 of CAPSLOCK | Go 83.6% test coverage | 43/43 tasks complete*
