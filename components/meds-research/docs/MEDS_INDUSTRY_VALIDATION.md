# Multi-Environment Deployment System (MEDS)
## Technical Validation Report — How It Works, Results & Benchmarks

**Component:** MEDS — Component 1 of the CAPSLOCK Security Platform  
**Student ID:** IT22347626 (Kulatunga)  
**Project ID:** 25-26J-043  
**Technology:** Python 3.11 / FastAPI / Pydantic  
**Version:** 1.0.0

---

## 1. Problem Statement

Promoting software across Kubernetes environments (development → staging → production) carries compounding risk: pre-release versions introduce instability, policy changes alter the security posture, and environments carry different tolerance thresholds. Without a systematic gate, teams either over-block routine changes or under-block high-risk ones.

MEDS solves this with a quantitative, multi-factor risk engine that evaluates every promotion before it reaches its target environment, runs ICAP content scanning as a hard gate, tracks policy lifecycle with per-environment modes, and maintains a tamper-evident audit trail of every decision ever made.

---

## 2. System Architecture

```
                        ┌────────────────────────────────────────────────┐
                        │              MEDS (Port 8000)                  │
                        │                                                │
  Browser  ────────────►│  FastAPI REST API  +  Single-Page Dashboard    │
                        │         (meds/api/main.py)                     │
                        │                  │                             │
                        │    ┌─────────────▼──────────────┐              │
                        │    │   PromotionController       │              │
                        │    │  (8-step pipeline)          │              │
                        │    └──┬────────┬────────┬────────┘              │
                        │       │        │        │                       │
                        │  RiskScorer  USLO    AuditLogger                │
                        │  (6 factors) Engine  (SHA-256 chain)            │
                        │       │        │        │                       │
                        │    ICAPScanner    PolicyVersionStore            │
                        │  (3-layer)        GitOpsOrchestrator            │
                        └───────┼────────────────────────────────────────┘
                                │
               ┌────────────────┼──────────────────┐
               ▼                ▼                  ▼
         ICAP Operator     Policy Engine         SSDLB
         (C4, port 1344)   (C2, EAPE)           (C3)
```

### Key Modules

| Module | File | Role |
|--------|------|------|
| **REST API** | `meds/api/main.py` | All endpoints, in-memory DB, NLP chat, Policy Engine proxy, SSDLB proxy |
| **Promotion Controller** | `meds/controllers/promotion_controller.py` | 8-step promotion pipeline orchestrator |
| **Risk Scorer** | `meds/validation/risk_scorer.py` | 6-factor weighted risk engine |
| **ICAP Scanner** | `meds/icap/scanner.py` | 3-layer scanning with TTL cache |
| **USLO Engine** | `meds/policy/uslo_engine.py` | Policy lifecycle per environment (enforce/audit modes) |
| **Audit Logger** | `meds/audit/log.py` | SHA-256 chained JSONL audit log with tamper detection |
| **Policy Version Store** | `meds/policy/version_store.py` | Per-environment version snapshots for rollback |
| **GitOps Orchestrator** | `meds/gitops/orchestrator.py` | Deploy and rollback via GitOps |
| **NLP Assistant** | `meds/api/main.py` `/api/nlp/chat` | Groq llama-3.3-70b tool-calling chat |

---

## 3. The 8-Step Promotion Pipeline

When a promotion is submitted, `PromotionController.process_promotion()` executes these steps in sequence. Any step can terminate the pipeline early with a REJECTED decision:

```
POST /api/promotions
        │
        ▼
┌──────────────────────────┐
│ Step 1: State Machine    │  Validates transition: dev→staging, staging→prod only.
│         Gate             │  Blocks same-env, backward, and stage-skipping promotions.
└──────────┬───────────────┘
           │ (passes)
           ▼
┌──────────────────────────┐
│ Step 2: ICAP Hard Gate   │  Scans the deployment artifact via 3-layer ICAP.
│                          │  threat_found = True → immediate REJECTED, pipeline stops.
└──────────┬───────────────┘
           │ (clean)
           ▼
┌──────────────────────────┐
│ Step 3: Compliance       │  Fetches compliance score from EAPE (best-effort).
│         Posture Fetch    │  Used as input to the risk scorer.
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│ Step 4: 6-Factor Risk    │  Computes weighted risk score.
│         Scoring          │  score > max_allowed → REJECTED.
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│ Step 5: USLO Policy Plan │  Evaluates policy add/remove changes against
│                          │  environment mode (enforce/audit).
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│ Step 6: Decision         │  APPROVED / PENDING_APPROVAL / REJECTED
│                          │  based on score vs threshold tiers.
└──────────┬───────────────┘
           │ (APPROVED only)
           ▼
┌──────────────────────────┐
│ Step 7: Policy Version   │  Snapshots current environment policies for rollback.
│         Snapshot         │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│ Step 8: GitOps Deploy    │  Deploys via GitOps agent. Notifies EAPE.
│         + EAPE Notify    │  Audit event written. Status set to SUCCEEDED.
└──────────────────────────┘
```

---

## 4. Risk Scoring Engine — 6 Factors

**Source:** `meds/validation/risk_scorer.py`

Total score is a weighted sum of 6 independent factors, each scored 0–100:

```
total_score = int(
    config_complexity  * 0.20 +
    policy_changes     * 0.25 +
    version_delta      * 0.15 +
    environment_trans  * 0.10 +
    icap_coverage      * 0.20 +
    compliance_posture * 0.10
)
```

### Factor Detail

| Factor | Weight | What Is Scored | Example Scores |
|--------|--------|---------------|----------------|
| `config_complexity` | 0.20 | Version maturity from string parse | alpha=90, beta=70, rc=55, major=70, minor=35, patch=15 |
| `policy_changes` | **0.25** | Count of adds + removals; removals carry +15 penalty each | 0 changes=0, 1 add=20, 3 removals=95, 5+ changes=100 (capped) |
| `version_delta` | 0.15 | Semantic versioning risk | alpha=80, beta=65, rc=45, major=65, minor=30, patch=10 |
| `environment_transition` | 0.10 | Validity and direction of the move | dev→staging=15, staging→prod=25, skip/backward=100 (blocked) |
| `icap_coverage` | 0.20 | ICAP scan health score (0–100, inverted to risk) | ≥90=5, ≥80=20, ≥70=45, ≥60=70, <60=90 |
| `compliance_posture` | 0.10 | EAPE compliance score (0.0–1.0, inverted to risk) | ≥90%=5, ≥75%=25, ≥60%=55, <60%=80 |

### Decision Tiers

| Score vs `max_allowed` | Decision | Meaning |
|------------------------|----------|---------|
| `score > max` | **REJECTED** | Hard block |
| `score > max × 0.75` | **PENDING_APPROVAL** | Elevated risk — manual sign-off required |
| `score > max × 0.50` | **APPROVED** — moderate | Monitor closely |
| `score ≤ max × 0.50` | **APPROVED** — low | Safe to auto-promote |

### Environment Risk Thresholds

| Environment | `max_allowed` | Rationale |
|-------------|--------------|-----------|
| Development | 80 | Permissive — most builds pass including beta |
| Staging | 60 | Pre-production gate — RC and below required |
| Production | 40 | Strictest — only stable, low-change builds |

---

## 5. ICAP Scanning — 3-Layer Fallback

**Source:** `meds/icap/scanner.py`

Every promotion is scanned before risk scoring. The scanner tries each layer in order, falling back only if the previous layer is unreachable:

### Layer 1 — RFC 3507 ICAP over Raw TCP (port 1344)

The scanner constructs a real ICAP `RESPMOD` request, wraps the deployment identity (`application:version`) as a synthetic HTTP response body, and sends it to the ClamAV-backed ICAP service deployed by the icap-operator.

| ICAP Status | Meaning | Outcome |
|-------------|---------|---------|
| `204 No Content` | Clean — no modification | `threat_found=False`, `coverage_score=95` |
| `200 OK` | Potentially modified — checks `X-Infection-Found` header | `threat_found=True` if header present |

### Layer 2 — Policy-Engine Compliance Gate

Calls `GET /api/integration/icap/policy-status/{namespace}` on EAPE and filters the result through the active scanning mode (TTL-cached for 5 s to avoid per-scan HTTP overhead):

| Scanning Mode | Behaviour |
|---------------|-----------|
| `block` (default) | Policy violations → `threat_found=True`, promotion blocked |
| `warn` | Violations set `low_coverage_warning`, never block |
| `log-only` | Violations logged only, scan always passes |

### Layer 3 — Deterministic Simulation (offline / CI)

When neither ICAP service nor policy engine is reachable, the scanner uses a seeded SHA-256 hash of `version:app_name` for reproducible results:

| Version Type | Threat Probability | Coverage Range |
|-------------|-------------------|----------------|
| alpha | 40% | 60–79 |
| beta | 25% | 70–89 |
| rc | 10% | 80–94 |
| stable | 5% | 85–99 |

The seed ensures the same version always produces the same scan result, making CI pipelines deterministic.

---

## 6. USLO Engine — Policy Lifecycle

**Source:** `meds/policy/uslo_engine.py`

The Unified Security Lifecycle Orchestration engine tracks policy changes across the promotion and applies environment-specific enforcement modes:

| Environment | Mode | Behaviour |
|-------------|------|-----------|
| Development | **enforce** | Violations hard-block; zero grace period for fast feedback |
| Staging | **audit** | Violations logged as warnings; promotion proceeds; 8 h grace period with auto-escalation |
| Production | **enforce** | Violations hard-block; rollback recommended |

### Rules Enforced

- **CRITICAL policy → production** requires staged rollout through staging first (enforce mode blocks direct addition)
- **Any policy removal in production** is flagged as a HIGH violation requiring compliance review
- **Required-but-missing policies** in staging/production generate advisory warnings
- **Unknown policy names** (not in catalog) are flagged as HIGH violations

---

## 7. Audit Log — SHA-256 Hash Chain

**Source:** `meds/audit/log.py`

Every promotion decision is written as a JSONL event. Events form a cryptographic chain: each entry records the SHA-256 hash of the previous entry (`prev_hash`), and its own hash (`event_hash`) is computed over all fields except itself.

```
Event 1: prev_hash="genesis"  event_hash=sha256(content_1)
Event 2: prev_hash=event_hash_1  event_hash=sha256(content_2)
Event 3: prev_hash=event_hash_2  event_hash=sha256(content_3)
```

`verify_chain()` re-computes every hash and checks the chain link — any field-level tampering or missing event is detected immediately.

### Event Types Logged

| Event Type | When |
|------------|------|
| `promotion_created` | Every promotion attempt |
| `promotion_approved` | Approved decision + GitOps deploy |
| `promotion_rejected` | Rejected by risk score or ICAP |
| `promotion_pending_approval` | Elevated risk — awaiting manual review |
| `icap_threat_detected` | ICAP scan finds a threat |
| `promotion_rollback` | Rollback executed |
| `policy_rollback` | Policy version reverted |

---

## 8. NLP Assistant

**Source:** `meds/api/main.py` — `POST /api/nlp/chat`

Powered by **Groq** (free tier) with `llama-3.3-70b-versatile`. Uses a two-step tool-calling loop:

1. First Groq call — model may invoke tools
2. Tool results are appended to the conversation
3. Second Groq call — model produces the final reply

### Available Tools

| Tool | What it does |
|------|-------------|
| `get_promotions(limit, status_filter)` | Queries live `promotions_db` |
| `get_audit_log(event_type, limit)` | Reads `audit_log.jsonl` with optional filter |
| `get_analytics()` | Returns total, approved, rejected counts and avg risk score |
| `get_icap_status()` | Proxies to EAPE `/api/icap/health` |
| `fill_promotion_form(name, app_name, source_env, target_env, version, namespace)` | Returns a UI action that populates the dashboard form |
| `switch_tab(tab)` | Returns a UI action that navigates the single-page app |

Example queries the model handles correctly:
- *"How many promotions were rejected this week?"* → calls `get_audit_log`
- *"Promote myapp v2.0.0 from staging to production"* → calls `fill_promotion_form`, fills the form
- *"What does a risk score of 75 mean in a staging environment?"* → answers from system prompt knowledge
- *"Show me the ICAP health"* → calls `get_icap_status`

---

## 9. Test Results

Run the full suite with: `cd components/meds-research && pytest tests/ -v`

### Risk Scoring Scenarios — `test_risk_scoring_scenarios.py`

10 named scenarios with exact computed scores and recommendation tier assertions:

| Scenario | Version | Route | Policies | Expected Score | Max | Decision |
|----------|---------|-------|----------|---------------|-----|----------|
| Safe patch to staging | v1.2.3 | dev→staging | none | 23 | 60 | APPROVED — low |
| Alpha skip to prod | v0.1-alpha | dev→prod | 5 adds | 77 | 40 | **REJECTED** |
| Major to prod | v2.0.0 | staging→prod | 1 add + 1 remove | 55 | 60 | APPROVED — elevated, sign-off |
| RC to staging | v1.0-rc1 | dev→staging | 1 add | 41 | 60 | APPROVED |
| Beta mass policy churn | v1.0-beta | staging→prod | 3 adds + 2 removes | 68 | 80 | APPROVED — elevated, sign-off |
| Minor, no policy changes | v1.2.0 | dev→staging | none | 30 | 60 | APPROVED — low |
| Patch + 3 removals | v1.2.3 | staging→prod | 3 removes | 47 | 60 | APPROVED |
| Policy change boundary | — | — | 2 adds + 2 removes | factor=95 | — | — |
| Environment boundaries | — | same-env / skip | — | factor=100 | — | blocked |
| Recommendation tiers | multiple | multiple | multiple | various | various | all tiers verified |

All 10 scenario classes pass. Additional structural tests verify:
- Factor weights sum exactly to 1.0
- Exactly 6 factors returned
- `weighted_score = score × weight` matches manual calculation within integer truncation
- Score is non-negative

### Promotion Controller Tests — `test_promotion_controller.py`

| Test | Scenario | Expected | Result |
|------|----------|----------|--------|
| Invalid transition (same env) | dev→dev | REJECTED | PASS |
| Stage-skipping | dev→prod | REJECTED | PASS |
| ICAP threat hard block | threat_found=True | REJECTED before scoring | PASS |
| Low risk approval | patch, no changes | APPROVED, low | PASS |
| Elevated risk pending | major, many changes | PENDING_APPROVAL | PASS |
| High risk rejection | alpha, max=40 | REJECTED | PASS |
| Rollback execution | SUCCEEDED promotion | ROLLED_BACK | PASS |
| Audit events written | any promotion | event_type in log | PASS |

### E2E Pipeline Tests — `test_e2e_pipeline.py`

End-to-end tests that exercise the full controller pipeline with no mocking:

| Test | Verifies |
|------|---------|
| `test_safe_patch_approved` | Full pipeline, patch version, approved with low risk |
| `test_alpha_to_prod_rejected` | ICAP + risk double-block for unstable to prod |
| `test_policy_removal_in_prod` | USLO raises violation for prod removal |
| `test_audit_chain_integrity` | `verify_chain()` returns valid after N promotions |
| `test_rollback_restores_version` | Version store + GitOps rollback restores prior snapshot |
| `test_pending_approval_flow` | Elevated risk → PENDING → `complete_approval()` → SUCCEEDED |

### ICAP Scanner Tests — `test_icap_scanner.py`

| Test | Scenario |
|------|---------|
| Simulation determinism | Same version always produces same threat/coverage |
| Alpha threat probability | ~40% threat rate across 1000 samples |
| Stable low threat rate | ~5% threat rate across 1000 samples |
| Scanning mode filtering | `warn` mode never sets `threat_found=True` |
| `log-only` mode | Always passes regardless of underlying threat |
| TTL cache | Mode not re-fetched within 5 s window |

### USLO Engine Tests — `test_uslo_engine.py`

| Test | What Is Verified |
|------|-----------------|
| Production policy removal is always a violation | `violation=True`, `severity=HIGH` |
| CRITICAL policy to prod requires staged rollout | `violation=True` in enforce mode |
| Staging audit mode logs but doesn't block | `compliance_impact=WARNING`, not BLOCKED |
| Unknown policy name is flagged HIGH | `violation=True` in any mode |
| No changes → compliance_impact=NONE | Zero-change promotions are clean |
| Required-but-missing policies generate warnings | advisory entries in `warnings` list |

---

## 10. Validation Demo Endpoints

The system exposes interactive demonstration endpoints that exercise the engine in isolation — useful for showing supervisors live results without needing a full Kubernetes cluster:

| Endpoint | What It Shows |
|----------|--------------|
| `POST /api/demo/risk-score` | Submit any version/policies and get the scored breakdown with per-factor reasoning |
| `POST /api/demo/conflicts` | Submit two policy names and see conflict detection + resolution |
| `GET /api/demo/health-scenarios` | 7 pre-computed ICAP health scenarios with adaptive weight adjustments |
| `GET /api/demo/traffic-scenarios` | 8 SSDLB routing scenarios (spread, single, recovery, ICAP-health-spread) |

---

## 11. API Endpoints Summary

### Promotions
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/promotions` | Submit a promotion — runs the full 8-step pipeline |
| `GET` | `/api/promotions` | List all promotions with status, scores, GitOps state |
| `POST` | `/api/promotions/{id}/approve` | Manually approve a PENDING_APPROVAL promotion |
| `POST` | `/api/promotions/{id}/rollback` | Roll back a SUCCEEDED promotion |
| `GET` | `/api/analytics` | Total, approved, rejected counts + average risk score |
| `GET` | `/api/audit` | Audit log with optional `event_type` filter |
| `GET` | `/api/environments/{name}/versions` | Per-environment policy version history |

### ICAP & Policy Engine Proxy
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/icap/status` | Full ICAP CRD status from EAPE |
| `GET` | `/api/icap/health` | Compact health score for SSDLB routing |
| `POST` | `/api/icap/configure` | Set scanning mode / replica count |

### NLP Assistant
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/nlp/chat` | Groq-powered chat with tool calling |

---

## 12. Integration with Other Components

| Component | How MEDS Uses It |
|-----------|-----------------|
| **EAPE** (C2) | Fetches compliance score per namespace before risk scoring; receives policy violation notifications; proxies Policy Engine UI panels |
| **ICAP Operator** (C4) | Layer 1 scanning via RFC 3507 TCP on port 1344; Layer 2 via EAPE bridge |
| **SSDLB** (C3) | Auto-route decisions, manual version overrides, health-aware routing — proxied through `/api/ssdlb/*` |

**Deployment-approved flow:**
```
1. Developer submits POST /api/promotions
2. ICAP scan: clean (coverage=92)
3. EAPE compliance: 0.96
4. Risk score: 18 (patch, no policy changes) → max=40 → APPROVED low risk
5. Policy snapshot saved (rollback point created)
6. GitOps deploy triggered
7. EAPE notified of namespace → environment mapping
8. Audit event chain updated
```

**Deployment-blocked flow (ICAP threat):**
```
1. Developer submits POST /api/promotions with v0.9-alpha
2. ICAP simulation: threat_found=True, threat_type="malware" (40% alpha probability)
3. Pipeline stops immediately — risk scoring does not run
4. REJECTED: "ICAP threat detected: malware"
5. icap_threat_detected + promotion_rejected audit events written
```

---

## 13. Design Decisions and Justification

| Decision | Rationale |
|----------|-----------|
| **Policy changes carry the highest weight (0.25)** | Policy removals directly erode security posture — this is the factor most likely to open vulnerabilities, so it deserves the strongest signal |
| **ICAP as a hard pre-gate before risk scoring** | A threat detection should never be overridden by a low risk score — two independent systems must agree before deployment proceeds |
| **SHA-256 chained audit log** | Provides cryptographic non-repudiation without a database; `verify_chain()` can prove log integrity to auditors |
| **3-layer ICAP fallback** | Ensures the system degrades gracefully: real scanner in prod, compliance gate in dev/docker, simulation in CI — the same API contract throughout |
| **Scanning mode TTL cache (5 s)** | Avoids an HTTP round-trip to EAPE on every scan without allowing stale config to persist; balance between responsiveness and performance |
| **USLO audit mode for staging** | Staging should see real policy violations in the log without blocking delivery — this creates a visible warning trail that operators can act on before production |
| **Groq tool-calling loop (max 2 calls)** | Caps API cost; one call is almost always sufficient, the second resolves any tool results; no infinite loops |
| **mTLS support** | `CA_CERT_PATH`, `MTLS_CERT_PATH`, `MTLS_KEY_PATH` env vars enable secure inter-component communication in production |

---

## 14. Running the System

```bash
# From repo root
bash start.sh

# Or manually
cd components/meds-research
pip install -r requirements.txt
python -m uvicorn meds.api.main:app --reload --port 8000

# Run test suite
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=meds --cov-report=term-missing
```

Dashboard: `http://localhost:8000`

---

*Student ID: IT22347626 | Project: 25-26J-043 | Component 1 of CAPSLOCK | Python / FastAPI | SLIIT 2025/26*
