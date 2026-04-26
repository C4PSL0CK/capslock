# MEDS — Thesis Source Data File
## Multi-Environment Deployment Security System

**Component:** MEDS — Component 1 of CAPSLOCK  
**Project:** 25-26J-043  
**Technology Stack:** Python 3.11, FastAPI, Pydantic, httpx, Groq (llama-3.3-70b-versatile)  
**Role in Platform:** Orchestration core — every deployment promotion flows through MEDS

---

## 1. Problem Statement

Modern Kubernetes-based CI/CD pipelines promote the same application artifact through multiple environments (development → staging → production). Each environment has fundamentally different security requirements, compliance obligations, and risk tolerance. Existing deployment tools (ArgoCD, FluxCD, Spinnaker) handle the *mechanical* act of deployment but provide no built-in:

- Quantified risk assessment before promotion
- Content scanning enforcement (ICAP/antivirus) tied to deployment decisions
- Policy lifecycle governance across environment tiers
- Tamper-evident audit trails with cryptographic chain integrity
- Automated rollback on SLO degradation
- Natural language interface for operators

MEDS solves this by acting as a **security-enforcement middleware layer** between a developer's promotion request and the GitOps deployment agent. No promotion reaches a target environment without passing through the MEDS pipeline.

---

## 2. Research Context and Motivation

### 2.1 Gap in Existing Tools

| Capability | ArgoCD | Spinnaker | MEDS |
|---|---|---|---|
| Deployment orchestration | ✅ | ✅ | ✅ |
| Risk scoring before deploy | ❌ | Partial | ✅ 6-factor model |
| ICAP content scanning gate | ❌ | ❌ | ✅ RFC 3507 |
| Policy lifecycle enforcement | ❌ | ❌ | ✅ USLO engine |
| Cryptographic audit trail | ❌ | Partial | ✅ SHA-256 chain |
| Stage-skip enforcement | Manual | Manual | ✅ State machine |
| Compliance posture feedback | ❌ | ❌ | ✅ CIS + PCI-DSS |
| NLP operator interface | ❌ | ❌ | ✅ Groq LLM |

### 2.2 Compliance Drivers

The system targets two compliance frameworks:
- **CIS Kubernetes Benchmark v1.9** — industry standard for Kubernetes security hardening
- **PCI-DSS v4.0** — required for any system handling payment card data

In regulated industries, a deployment that introduces a privileged container, removes a network policy, or skips environment gates is a compliance violation. MEDS enforces these as hard blocks, not warnings.

---

## 3. System Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                            MEDS Platform                                     │
│                                                                              │
│   Developer / CI                   FastAPI REST API (:8000)                 │
│        │                                    │                                │
│        │  POST /api/promotions              │                                │
│        └──────────────────────────────────► │                                │
│                                             │                                │
│                              ┌──────────────▼──────────────┐                │
│                              │    PromotionController       │                │
│                              │                              │                │
│                              │  1. State Machine Gate       │                │
│                              │  2. ICAP Hard Gate           │                │
│                              │  3. Compliance Fetch         │                │
│                              │  4. 6-Factor Risk Scoring    │                │
│                              │  5. USLO Policy Planning     │                │
│                              │  6. Decision (APPROVE/REJECT)│                │
│                              │  7. Policy Version Snapshot  │                │
│                              │  8. GitOps Deploy            │                │
│                              └──────────────┬──────────────┘                │
│                                             │                                │
│          ┌──────────────┬──────────────────┼────────────────┐               │
│          ▼              ▼                  ▼                ▼               │
│    ICAPScanner    RiskScorer         AuditLogger      GitOpsOrchestrator    │
│    (3 layers)     (6 factors)        (SHA-256 chain)  (ArgoCD/FluxCD)       │
│          │                                                                   │
│          ▼                                                                   │
│   ┌──────────────────────────────┐                                          │
│   │ Layer 1: RFC 3507 ICAP       │  → ClamAV on port 1344                  │
│   │ Layer 2: Policy-engine gate  │  → EAPE compliance check                │
│   │ Layer 3: Deterministic sim   │  → SHA-256 seeded simulation             │
│   └──────────────────────────────┘                                          │
│                                                                              │
│   External integrations:                                                     │
│   ├── EAPE (Policy Engine)  :8080  — compliance score, namespace policy     │
│   ├── ICAP Operator         :1344  — ClamAV content scanning               │
│   └── SSDLB                 :8082  — health-aware load balancing            │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Module Breakdown

| Module | File | Responsibility |
|---|---|---|
| REST API | `meds/api/main.py` | All HTTP endpoints, in-memory state, inter-component proxy routes |
| Promotion Controller | `meds/controllers/promotion_controller.py` | 8-step orchestration pipeline, decision engine |
| Risk Scorer | `meds/validation/risk_scorer.py` | 6-factor weighted risk model |
| ICAP Scanner | `meds/icap/scanner.py` | 3-layer content scanning with fallback chain |
| USLO Engine | `meds/policy/uslo_engine.py` | Policy lifecycle planning per environment tier |
| Audit Logger | `meds/audit/log.py` | SHA-256 chained tamper-evident event log |
| Policy Version Store | `meds/policy/version_store.py` | Policy snapshots enabling rollback |
| GitOps Orchestrator | `meds/gitops/orchestrator.py` | ArgoCD/FluxCD application manifest generation |
| Policy Catalog | `meds/policy/standards.py` | 16 policy definitions with CIS/PCI-DSS mappings |
| Data Models | `meds/models/promotion.py` | Pydantic models for Promotion, Environment, GitOpsStatus |

---

## 4. The Promotion Lifecycle — 8-Step Pipeline

The core of MEDS is `PromotionController.process_promotion()`. Every promotion request traverses these steps in order:

### Step 1: State Machine Gate
```
Enforced transitions:
  development → staging     ✅ allowed (score: 15)
  staging     → production  ✅ allowed (score: 25)
  development → production  ❌ REJECTED — "Stage-skipping blocked: must pass through staging"
  production  → staging     ❌ REJECTED — "Backward promotion blocked"
  staging     → staging     ❌ REJECTED — "Cannot promote to same environment"
```
This is a hard gate — invalid transitions are rejected before any scanning or scoring occurs.

### Step 2: ICAP Hard Gate
The artifact is scanned via `ICAPScanner.scan()` (3-layer fallback — see Section 6).  
If `threat_found=True`: promotion is **immediately rejected** regardless of risk score.  
Event logged: `icap_threat_detected` + `promotion_rejected`.

### Step 3: Compliance Posture Fetch
Best-effort HTTP call to EAPE (`/api/integration/icap/policy-status/{namespace}`).  
Returns `compliance_score` (0.0–1.0). If EAPE is unreachable, `None` is used (maps to score 50 in risk model — uncertain, not zero).

### Step 4: 6-Factor Risk Scoring
Calls `RiskScorer.calculate_risk_score()`. Full model documented in Section 5.

### Step 5: USLO Policy Planning
Calls `PolicyEvolutionTracker.plan_migration()`. Evaluates all policy additions/removals against the target environment's mode (audit/enforce). Full model documented in Section 7.

### Step 6: Decision
```python
if total_score > max_allowed_score:
    decision = "REJECTED"
elif total_score > int(max_allowed_score * approval_threshold):  # default 0.75
    decision = "PENDING_APPROVAL"   # holds for human sign-off
else:
    decision = "APPROVED"
```

**Environment risk thresholds (max_allowed_score):**

| Environment | Max Risk Score | Approval Threshold | Auto-approve ceiling |
|---|---|---|---|
| development | 80 | 75% (score > 60) | 40 |
| staging | 60 | 75% (score > 45) | 30 |
| production | 40 | 75% (score > 30) | 20 |

### Step 7: Policy Version Snapshot
On `APPROVED`, saves current environment policies to `PolicyVersionStore` with a UUID version ID. This `rollback_version_id` is attached to the promotion status for future rollback.

### Step 8: GitOps Deploy
Calls `GitOpsOrchestrator.deploy()` which generates an ArgoCD `Application` manifest and tracks 6 deployment phases:  
`manifest_generated → diff_calculated → sync_initiated → resources_applied → health_checked → synced`

After successful deploy, MEDS notifies EAPE (`/api/integration/meds/notify`) with namespace, environment, promotion ID, and version.

---

## 5. Risk Scoring Model — 6 Factors

### 5.1 Weights

| Factor | Weight | Signal Source |
|---|---|---|
| `config_complexity` | 0.20 | Version string pattern (alpha/beta/rc/major/minor/patch) |
| `policy_changes` | **0.25** (highest) | Count and direction of policy additions/removals |
| `version_delta` | 0.15 | Semantic versioning distance |
| `environment_transition` | 0.10 | Source → target validity and risk |
| `icap_coverage` | 0.20 | ICAP scan coverage score (0–100) |
| `compliance_posture` | 0.10 | EAPE compliance score (0.0–1.0) |
| **Total** | **1.00** | |

**Formula:**  
`total_score = Σ (factor_score_i × weight_i)` → integer [0–100]

### 5.2 Factor Scoring Tables

**config_complexity (weight 0.20)**

| Version Type | Score | Reasoning |
|---|---|---|
| `*-alpha` | 90 | Very high instability risk |
| `*-beta` | 70 | High instability risk |
| `*-rc*` | 55 | Moderate — known-issue list may still change |
| Major bump (`v2.0.0`) | 70 | Breaking changes possible |
| Minor bump (`v1.2.0`) | 35 | Additive, backwards-compatible |
| Patch (`v1.2.3`) | 15 | Bug fixes only — minimal risk |

**policy_changes (weight 0.25)**

```
base_score = {0 changes: 0, 1 change: 20, 2 changes: 35, n>2: min(90, 35+(n-2)*15)}
removal_penalty = removals × 15   (removals loosen security posture — higher risk)
final_score = min(100, base_score + removal_penalty)
```

Example: 2 additions + 2 removals → base=65, penalty=30 → score=95

**version_delta (weight 0.15)**

| Version Type | Score |
|---|---|
| alpha | 80 |
| beta | 65 |
| rc | 45 |
| major | 65 |
| minor | 30 |
| patch | 10 |

**environment_transition (weight 0.10)**

| Transition | Score |
|---|---|
| development → staging | 15 |
| staging → production | 25 |
| Any other valid | 20 |
| Stage-skip or backward | **100** (blocks) |

**icap_coverage (weight 0.20)**

| Coverage Score | Risk Score | Interpretation |
|---|---|---|
| ≥ 90 | 5 | Excellent coverage |
| ≥ 80 | 20 | Good coverage |
| ≥ 70 | 45 | Moderate — low coverage warning |
| ≥ 60 | 70 | Poor — review scan config |
| < 60 | 90 | Critical gap |
| None | 60 | Unknown — no scan data |

**compliance_posture (weight 0.10)**

| Compliance Score | Risk Score |
|---|---|
| ≥ 90% | 5 |
| ≥ 75% | 25 |
| ≥ 60% | 55 |
| < 60% | 80 |
| None | 50 |

### 5.3 Decision Tiers

| Condition | Decision | Outcome |
|---|---|---|
| score > max_allowed | REJECTED | Blocked, audit event logged |
| score > max × 0.75 | PENDING_APPROVAL | Held for human sign-off |
| score > max × 0.50 | APPROVED | Moderate risk, monitor closely |
| score ≤ max × 0.50 | APPROVED | Low risk, safe to auto-promote |

### 5.4 Validated Scenarios (from test suite)

| Scenario | Version | Source→Target | Policy Changes | Score | Decision |
|---|---|---|---|---|---|
| Safe patch | v1.2.3 | dev→staging | none | **23** | APPROVED (Low risk) |
| Minor release | v1.2.0 | dev→staging | none | **30** | APPROVED (Low risk) |
| RC to staging | v1.0-rc1 | dev→staging | +1 | **41** | APPROVED |
| Major with policy churn | v2.0.0 | staging→prod | +1 -1 | **55** | APPROVED (sign-off required) |
| Beta mass changes | v1.0-beta | staging→prod | +3 -2 | **68** | APPROVED (approval required) |
| Patch + 3 removals | v1.2.3 | staging→prod | -3 | **47** | APPROVED |
| Alpha to prod skip | v0.1-alpha | dev→prod | +5 | **77** | **REJECTED** |

---

## 6. ICAP Scanning — 3-Layer Architecture

The `ICAPScanner` implements a **priority-ordered fallback chain**:

### Layer 1: RFC 3507 ICAP Protocol (Production — Kubernetes)
Connects directly to the ICAP Operator on TCP port 1344.

Protocol flow:
```
MEDS constructs:
  - Synthetic HTTP/1.1 response wrapping the artifact:
    body = "deployment:{app_name}:{version}" (encoded)
  - ICAP RESPMOD request with chunked encoding:
    RESPMOD icap://{host}:1344/avscan ICAP/1.0
    Encapsulated: res-hdr=0, res-body={offset}

ICAP server (ClamAV) responds:
  204 No Content → clean, threat_found=False, coverage_score=95
  200 OK         → check X-Infection-Found header for threat type
                   threat_found=True if header present, coverage_score=90
```

### Layer 2: Policy-Engine Compliance Gate (Docker-Compose / Local)
Calls EAPE's `/api/integration/icap/policy-status/{app_name}`.

Scanning mode (fetched from EAPE `/api/icap/health`, cached 5 seconds) controls outcome:

| Scanning Mode | threat_found | low_coverage_warning |
|---|---|---|
| `block` | True if violations present | score < 75 |
| `warn` | Always False | True if violations OR score < 75 |
| `log-only` | Always False | Always False |

### Layer 3: Deterministic Simulation (Offline / CI)
SHA-256 seeded deterministic simulation — same version+app always produces same result.

| Version Type | Threat Probability | Coverage Range |
|---|---|---|
| alpha | 40% | 60–79 |
| beta | 25% | 70–89 |
| rc | 10% | 80–94 |
| stable | 5% | 85–99 |

The seed ensures tests are reproducible and not flaky.

---

## 7. USLO Engine — Policy Lifecycle Governance

**USLO = Unified Security Lifecycle Orchestration**

### 7.1 Environment Policy Modes

| Environment | Mode | Grace Period | Auto-Escalate |
|---|---|---|---|
| development | **enforce** | 0h | No |
| staging | **audit** | 8h | Yes |
| production | **enforce** | 0h | No |

In **enforce** mode: violations block the promotion.  
In **audit** mode: violations are logged as warnings but promotion proceeds.

Rationale: staging is a pre-production validation gate. Violations at staging are surfaced as warnings with an 8-hour grace period so developers can fix them before reaching production. Production and development have no tolerance — violations must be resolved immediately.

### 7.2 Policy Addition Rules

- Policy not in catalog → `violation=True`, severity=HIGH
- Policy already active → note only, no violation
- CRITICAL severity policy added directly to production → violation (must be staged through staging first)
- Any other addition → applied with grace period, compliance_mappings returned

### 7.3 Policy Removal Rules

- Any removal in **production** → `violation=True`, severity=HIGH, reason: "Policy removal in production requires compliance review"
- Removal in development/staging → no violation, note to monitor compliance posture

### 7.4 Required Policy Check

For staging and production, the USLO checks if any catalog-required policies are missing from the target environment and not being added. Returns warnings (up to 3) for missing required policies.

### 7.5 Compliance Impact Levels

| Condition | compliance_impact | status |
|---|---|---|
| Violations + enforce mode | BLOCKED | violations_blocked |
| Violations + audit mode | WARNING | violations_logged |
| Missing required policies | ADVISORY | missing_policies_warned |
| No changes | NONE | no_policy_changes |
| ≤2 changes, no violations | LOW | policies_applied |
| 3–4 changes | MEDIUM | policies_applied |
| 5+ changes | HIGH | policies_applied |

---

## 8. Policy Catalog

16 policy definitions across 6 categories, mapped to CIS and PCI-DSS controls:

| Policy | Category | Severity | Required For | CIS | PCI-DSS |
|---|---|---|---|---|---|
| `network-segmentation` | Network | critical | production | 5.3.2 | 1.2.1 |
| `network-policy` | Network | critical | staging, prod | 5.3.1 | 1.3.1 |
| `tls-enforcement` | Network | critical | staging, prod | — | 4.2.1 |
| `service-mesh-mtls` | Network | critical | production | — | 4.2.1 |
| `pod-security-standards` | Pod Security | critical | staging, prod | 5.2.1 | 2.2.1 |
| `no-privileged-containers` | Pod Security | critical | production | 5.2.1 | — |
| `read-only-root-fs` | Pod Security | high | production | 5.2.6 | 2.2.1 |
| `no-host-namespaces` | Pod Security | high | staging, prod | 5.2.2 | — |
| `rbac-least-privilege` | Access Control | critical | production | 5.1.1 | 7.1.1 |
| `namespace-isolation` | Access Control | medium | staging, prod | 5.7.1 | — |
| `image-scanning` | Supply Chain | high | staging, prod | 5.2.4 | 6.3.3 |
| `container-registry` | Supply Chain | high | staging, prod | 5.2.4 | — |
| `secrets-encryption` | Encryption | critical | production | — | 3.4.1 |
| `secret-rotation` | Encryption | high | production | — | 8.3.9 |
| `resource-limits` | Resources | medium | all | 5.2.3 | — |
| `audit-logging` | Logging | high | production | — | 10.2.1 |
| `log-forwarding` | Logging | medium | all | — | 10.5.1 |

---

## 9. Audit Log — Cryptographic Chain Integrity

The `AuditLogger` maintains a **SHA-256 linked chain** of audit events stored as JSONL at `data/audit_log.jsonl`.

### Chain Structure

Each event has:
```json
{
  "event_id":     "8-char UUID prefix",
  "timestamp":    "ISO-8601 UTC",
  "event_type":   "promotion_approved | promotion_rejected | icap_threat_detected | ...",
  "promotion_id": "uuid",
  "environment":  "staging",
  "details":      { ... },
  "actor":        "system | operator_name",
  "prev_hash":    "SHA-256 of previous event (genesis for first)",
  "event_hash":   "SHA-256 of this event content (excluding event_hash field)"
}
```

### Hash Computation

```python
content = event.model_dump()
content.pop("event_hash")  # exclude self-reference
digest = sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()
```

`sort_keys=True` ensures deterministic serialization — field order cannot affect the hash.

### Tamper Detection

`verify_chain()` re-reads the full log and for each event:
1. Checks `prev_hash` matches the previous event's `event_hash`
2. Recomputes the event's own hash from its fields and compares to stored `event_hash`

If either check fails → `{valid: False, broken_at: event_id}`.

**Validated in test:** field-level tampering (changing a detail value) is detected even without a chain break, because the hash is computed over all fields.

### Event Types

| Event Type | Trigger |
|---|---|
| `promotion_created` | Every promotion request (approved or rejected) |
| `promotion_approved` | Risk score within threshold + GitOps deploy succeeded |
| `promotion_rejected` | Risk score exceeded OR ICAP threat OR invalid transition |
| `promotion_pending_approval` | Risk score in elevated zone, awaiting human sign-off |
| `icap_threat_detected` | ICAP scan returns threat_found=True |
| `policy_rollback` | Rollback executed |
| `promotion_rollback` | Rollback executed (alias) |

---

## 10. Policy Version Store and Rollback

Every approved promotion snapshots the current environment policies to `data/policy_versions.json`:

```json
{
  "version_id": "a3f9b2c1",
  "environment": "production",
  "policies": ["network-policy", "pod-security-standards", "rbac-least-privilege"],
  "timestamp": "2026-04-21T10:30:00Z",
  "promotion_id": "uuid-of-triggering-promotion",
  "note": "Promotion 'payment-service-v2.0.0' approved"
}
```

Rollback (`execute_rollback()`) restores the snapshotted policy list to the environment, runs a GitOps rollback sync, and logs a `promotion_rollback` audit event.

**SLO-triggered auto-rollback**: The background task `_check_and_rollback_degraded()` runs on a 30-second interval. If a SUCCEEDED promotion's GitOps health degrades to `degraded` and a `rollback_version_id` is set, it executes the rollback automatically.

---

## 11. GitOps Integration

`GitOpsOrchestrator` generates ArgoCD `Application` manifests and tracks deployment phases:

**ArgoCD Application structure (auto-generated):**
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: {app}-{environment}
  namespace: argocd
  labels:
    capslock.io/promotion-id: {uuid}
    capslock.io/environment:  {env}
    capslock.io/version:      {semver}
spec:
  source:
    repoURL: https://github.com/C4PSL0CK/capslock
    targetRevision: {version}
    path: manifests/{env}/{app}
  destination:
    server: https://kubernetes.default.svc
    namespace: {env}
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions: [CreateNamespace=true]
```

6 deployment phases tracked: `manifest_generated → diff_calculated → sync_initiated → resources_applied → health_checked → synced`

---

## 12. NLP Assistant Integration (Groq)

MEDS embeds an AI assistant via `POST /api/nlp/chat` using Groq's `llama-3.3-70b-versatile` model.

**Tool-use loop:**
1. User message + history (last 20 turns) sent to Groq with system prompt
2. Model may invoke one or more tools (first call)
3. Tool results fed back for final response (second call)
4. Reply + optional UI action returned to browser

**Available tools:**
| Tool | Data Source |
|---|---|
| `get_promotions(limit, status_filter)` | `promotions_db` in-memory |
| `get_audit_log(event_type, limit)` | `data/audit_log.jsonl` |
| `get_analytics()` | Aggregate stats from `promotions_db` |
| `get_icap_status()` | EAPE `/api/icap/health` proxy |
| `fill_promotion_form(name, app_name, source_env, target_env, version, namespace)` | UI action |
| `switch_tab(tab)` | UI navigation action |

**Action types returned to UI:**
- `fill_promotion_form` → switches to Dashboard tab and populates form fields
- `switch_tab` → navigates to named tab

Groq also generates plain-English `nlp_reasoning` attached to every promotion's status (via `_generate_promotion_reasoning()`), explaining the risk decision in plain language for non-technical stakeholders.

**Fallback:** if `GROQ_API_KEY` is not set, returns an instructions message (never silently fails).

---

## 13. REST API Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/api/promotions` | Create and evaluate a new promotion |
| GET | `/api/promotions` | List all promotions |
| GET | `/api/promotions/{id}` | Get single promotion |
| POST | `/api/promotions/{id}/approve` | Approve a PENDING_APPROVAL promotion |
| POST | `/api/rollback` | Roll back to a previous policy version |
| GET | `/api/environments` | List environments with policies and thresholds |
| GET | `/api/audit` | Get audit log events (filterable by type) |
| GET | `/api/audit/verify` | Verify SHA-256 chain integrity |
| GET | `/api/analytics` | Aggregate stats (total/approved/rejected/avg risk) |
| GET | `/api/policy-versions` | List policy version snapshots |
| POST | `/api/nlp/chat` | NLP assistant (Groq) |
| GET | `/api/policy-engine/namespaces` | Proxy to EAPE namespace list |
| GET | `/api/policy-engine/policies` | Proxy to EAPE policy list |
| POST | `/api/policy-engine/namespaces/{ns}/apply` | Apply policy to namespace |
| GET | `/api/policy-engine/conflict-audit` | Proxy to EAPE conflict audit log |
| GET | `/api/ssdlb/state` | Proxy to SSDLB state |
| POST | `/api/ssdlb/auto-route` | Trigger SSDLB auto-route decision |
| POST | `/api/ssdlb/set-version/{v}` | Manual SSDLB version override |
| GET | `/metrics` | Prometheus metrics endpoint |
| GET | `/api/system/status` | Health status of all platform components |

---

## 14. Data Models

### Promotion
```python
class Promotion:
    metadata: dict                    # id, name
    spec: PromotionSpec               # see below
    status: PromotionStatus           # phase, risk_score, decision, gitops, ...
```

### PromotionSpec
```python
class PromotionSpec:
    application: ApplicationRef       # name, namespace
    source_environment: str           # development | staging | production
    target_environment: str
    version: str                      # semantic version string
    policy_migration: PolicyMigration # add_policies, remove_policies
```

### PromotionStatus phases
`PENDING → RUNNING → SUCCEEDED | FAILED | PENDING_APPROVAL | ROLLED_BACK`

### Environment
```python
class Environment:
    name: str
    type: str                         # development | staging | production
    max_risk_score: int               # 80 | 60 | 40
    policies: List[str]               # active policy names
    cluster: str                      # logical cluster name
    policy_mode: str                  # audit | enforce
    approval_threshold: float         # default 0.75
```

---

## 15. Test Suite Results

### Test Files
- `tests/test_risk_scorer.py` — 16 unit tests, all factor assessors + weight sum
- `tests/test_risk_scoring_scenarios.py` — 10 scenario classes, 28 tests, exact score validation
- `tests/test_e2e_pipeline.py` — full pipeline tests including state machine, ICAP gate, audit chain
- `tests/test_promotion_controller.py` — controller unit tests
- `tests/test_uslo_engine.py` — USLO policy lifecycle tests
- `tests/test_icap_scanner.py` — ICAP scanner layer tests
- `tests/test_conflict_scenarios.py` — multi-policy conflict scenarios

### Key Test Results

**State machine tests (all pass):**
- `dev → staging` → allowed ✅
- `staging → production` → allowed ✅
- `dev → production` → Stage-skipping blocked ✅
- `production → staging` → Backward promotion blocked ✅
- `staging → staging` → Same environment blocked ✅

**Risk score precision tests (all pass):**
- Safe patch v1.2.3 dev→staging → score=23 ✅
- Minor v1.2.0 dev→staging → score=30 ✅
- RC v1.0-rc1 dev→staging +1 policy → score=41 ✅
- Major v2.0.0 staging→prod +1 -1 → score=55 ✅
- Alpha dev→prod skip +5 policies → score=77 ✅
- Weights sum to exactly 1.0 ✅
- Exactly 6 factors returned ✅
- Weighted sum matches manual calculation ✅

**ICAP gate tests:**
- ICAP threat (`MALWARE.Test.EICAR`) → immediate REJECTED ✅
- Clean scan → proceeds to risk scoring ✅

**Audit chain integrity tests:**
- 5-event chain → valid ✅
- Tampered field → chain invalid, broken_at reported ✅

**USLO mode tests:**
- staging → audit mode ✅
- production → enforce mode ✅
- development → enforce mode ✅

---

## 16. mTLS and Security Posture

All inter-component HTTP calls support mutual TLS via environment variables:

```bash
CA_CERT_PATH=...      # CA certificate for server verification
MTLS_CERT_PATH=...    # Client certificate
MTLS_KEY_PATH=...     # Client private key
```

When set, all `httpx` clients use these for EAPE, ICAP Operator, and SSDLB calls. This enables full mTLS mesh when deployed in Kubernetes with Istio.

---

## 17. Prometheus Observability

MEDS exports metrics at `/metrics` (Prometheus format) via `prometheus-client`.

Metrics tracked in `meds/monitoring/metrics.py` cover promotion counts by decision, risk score distributions, ICAP scan results, and API latency.

---

## 18. Design Decisions and Justification

| Decision | Rationale |
|---|---|
| **Python + FastAPI** | Rapid prototyping; async-first; Pydantic for strict data validation; matches research timeline |
| **In-memory state + JSON persistence** | No database dependency; portable; appropriate for single-instance deployment scope |
| **6-factor risk model** | Captures the full deployment risk surface: code maturity (config+version), security posture (ICAP+compliance), change risk (policy), and environment gate (transition) |
| **policy_changes weighted highest (0.25)** | Policy removals are the most dangerous class of change in regulated environments — loosening security posture in production is the leading cause of compliance failures |
| **SHA-256 chain audit log** | Industry-standard tamper evidence without requiring a database; satisfies PCI-DSS Req 10 (audit log integrity) |
| **ICAP as hard gate, not risk factor only** | A confirmed malware detection must block unconditionally regardless of how low the risk score is — making it a binary gate before the scoring model |
| **3-layer ICAP fallback** | Enables the system to function in all deployment contexts: full Kubernetes cluster (Layer 1), docker-compose with EAPE (Layer 2), and offline/CI (Layer 3) — without code changes |
| **USLO audit mode for staging** | Staging should surface violations without blocking — developers need to see policy issues before they reach production, not be blocked at staging where iteration is expected |
| **Policy version snapshots** | GitOps rollback handles the application artifact; policy version snapshots handle the security posture rollback — these are separate concerns requiring separate mechanisms |
| **Groq NLP assistant** | Reduces operator cognitive load for routine queries and form-filling; free-tier LLM with tool-use makes AI-assistance practical without infrastructure cost |
