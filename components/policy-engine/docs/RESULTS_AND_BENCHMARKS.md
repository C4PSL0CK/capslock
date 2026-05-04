# EAPE — Results and Benchmarks

**Environment-Aware Policy Engine** | Component 2 of CAPSLOCK | Project 25-26J-043

---

## 1. Test Coverage

Tests are organised into three suites: unit, integration, and end-to-end.

| Package | Coverage |
|---------|----------|
| `pkg/conflict` | 89.9% |
| `pkg/mocks` | 95.8% |
| `pkg/policy` | 83.5% |
| `pkg/integrations/opa` | 82.6% |
| `pkg/detector` | 80.0% |
| **Overall** | **83.6%** |

Run all tests with coverage:

```bash
cd components/policy-engine
go test ./... -cover
```

---

## 2. Performance Benchmarks

Benchmarks are located in `tests/performance/benchmark_test.go` and measure each stage of the 7-step policy application workflow independently.

Run benchmarks:

```bash
go test ./tests/performance/ -bench=. -benchmem
```

### Results

| Benchmark | Operation | ns/op | Allocations |
|-----------|-----------|-------|-------------|
| `BenchmarkPolicySelection` | Select optimal policy for environment | **882 ns/op** | ~14 KB/op |
| `BenchmarkConflictDetection` | Detect conflicts across all loaded templates | **7,200 ns/op** | — |
| `BenchmarkEnvironmentDetection` | Detect environment from namespace labels | **180 ms/op** | — |
| `BenchmarkPolicyApplication` | Full orchestrated workflow (steps 1–7) | **163 ms/op** | — |
| `BenchmarkMultipleNamespaces` | Apply policies to 3 namespaces sequentially | ~490 ms/op | — |

**Key observations:**
- Policy selection and conflict detection are sub-microsecond and sub-10µs respectively — negligible overhead on the critical path.
- Environment detection and the full workflow are bounded by the Kubernetes API call latency (~160–180 ms). In a local cluster this is acceptable; in-cluster latency would be lower.
- Memory allocation of ~14 KB per policy selection operation confirms the stateless, non-accumulating design.

---

## 3. End-to-End Test Results

Suite: `tests/e2e/workflow_test.go`

| Test | Scenario | Expected Outcome | Result |
|------|----------|-----------------|--------|
| `TestCompleteWorkflow_Dev` | Apply policy to `dev-test` namespace | Environment = `dev`, Policy = `dev-policy`, Confidence ≥ 0.8, ≥ 5 workflow steps, Status = `deployed` | PASS |
| `TestCompleteWorkflow_Staging` | Apply policy to `staging-test` namespace | Environment = `staging`, Policy = `staging-policy` | PASS |
| `TestCompleteWorkflow_Prod` | Apply policy to `prod-test` namespace | Environment = `prod`, Policy = `prod-policy`, ≥ 1 healthy service | PASS |
| `TestMultipleNamespaces` | Apply policies to dev, staging, prod simultaneously | All 3 succeed, ≥ 3 entries in applied-policy registry | PASS |
| `TestPolicyRemoval` | Apply then remove policy from `dev-test` | Policy removed from registry, no residual entry | PASS |
| `TestErrorHandling` | Non-existent namespace, remove non-existent policy | Both return errors (no silent failures) | PASS |

---

## 4. Integration Test Results

Suite: `tests/integration/api_test.go` — tests the HTTP layer using `httptest` without a live cluster.

| Test | Endpoint | Expected Status | Result |
|------|----------|----------------|--------|
| `TestHealthEndpoint` | `GET /health` | 200 | PASS |
| `TestDetectEndpoint` | `POST /api/detect` with `dev-test` | 200 | PASS |
| `TestPoliciesListEndpoint` | `GET /api/policies` | 200, non-empty JSON | PASS |
| `TestPolicyGetEndpoint` | `GET /api/policies/get?name=dev-policy` | 200 | PASS |
| `TestPolicySelectEndpoint` | `POST /api/policies/select` | 200 or 400 | PASS |
| `TestConflictDetectEndpoint` | `POST /api/conflicts/detect` | 200 or 400 | PASS |
| `TestConflictResolveEndpoint` | `POST /api/conflicts/resolve` with `security-first` strategy | 200 | PASS |
| `TestInvalidEndpoint` | `GET /api/invalid` | 404 | PASS |
| `TestMultipleRequests` | `GET /health` × 3 | All 200 | PASS |

---

## 5. Functional Verification

### Environment Detection Accuracy

The detector correctly classifies namespaces from name patterns alone:

| Namespace | Detected Environment | Confidence |
|-----------|---------------------|------------|
| `dev-test` | development | 0.95 |
| `staging-test` | staging | 0.95 |
| `prod-test` | production | 0.95 |
| `default` | development | 0.60 |
| `capslock-system` | production | 0.85 |

### Conflict Resolution Strategies

Three strategies tested against a dev-policy vs prod-policy conflict:

| Strategy | Outcome |
|----------|---------|
| `compliance-first` | `prod-policy` wins — broader compliance coverage (CIS + PCI-DSS vs CIS only) |
| `security-first` | `prod-policy` wins — higher security level |
| `environment-aware` | Policy matching target environment wins |

### Policy Application Workflow — Step Completion

Full 7-step workflow verified for all three environment tiers:

```
Step 1: Environment Detection      ✓
Step 2: Policy Selection           ✓
Step 3: Conflict Detection         ✓
Step 4: Conflict Resolution        ✓  (if conflicts found)
Step 5: Policy Application         ✓
Step 6: Status Reporting           ✓
Step 7: Service Verification       ✓
```

---

## 6. Compliance Coverage

| Framework | Controls Validated | Enforced In |
|-----------|--------------------|-------------|
| CIS Kubernetes Benchmark v1.9 | Sections 4.1–4.5 (RBAC, pods, network, secrets, namespaces) | All environments |
| PCI-DSS v4.0 | Requirements 3, 4, 6, 10 | Staging + Production |

### Policy Tier Mapping

| Environment | Policy | Enforcement Mode | ICAP Mode | Compliance |
|-------------|--------|-----------------|-----------|------------|
| Development | `dev-policy` | audit | log-only | CIS |
| Staging | `staging-policy` | enforce | warn | CIS, PCI-DSS |
| Production | `prod-policy` | strict | block | CIS, PCI-DSS |

---

## 7. Scalability

- **Stateless design** — no database required; policy templates cached in memory on startup.
- **Horizontal scaling** — multiple instances can run concurrently with no shared state.
- **Lazy Kubernetes client** — only loaded when a cluster is reachable; startup is never blocked.
- **Local state persistence** — `icap_local_state.json` survives cluster unavailability, keeping the UI consistent.

---

## 8. Novel Contributions

1. **Continuous Change Detection (F1)** — `Detector.Watch()` polls namespace environment on a configurable interval and fires `onChange` callbacks when the environment type shifts, enabling proactive re-application of policies without manual triggers.

2. **Policy Inheritance (F2)** — `base-policy.yaml` defines shared defaults; environment-specific templates declare a `base:` field and deep-merge over the base, eliminating duplication and ensuring baseline controls are never accidentally omitted.

3. **Conflict Audit Persistence (F3)** — every conflict resolution event is appended as a JSONL entry to `/tmp/capslock-conflict-audit.jsonl` and served via `GET /api/conflict-audit`, providing a persistent, inspectable audit trail of all policy decisions.

---

*Student: Kaavya Raigambandarage | Project: 25-26J-043 | Test Coverage: 83.6% | Tasks: 43/43 (100%)*
