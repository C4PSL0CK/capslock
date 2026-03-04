# MEDS — Multi-Environment Deployment System

**Component of CAPSLOCK** | Python / FastAPI | Port 8000

## Overview

MEDS is the primary user interface and orchestration layer of CAPSLOCK. It manages software promotions (deployments) across environments, scoring each one for risk, scanning it via ICAP, and providing a full audit trail. It also hosts the NLP-powered AI assistant.

## Features

- **Risk Assessment Engine** — 4-factor weighted scoring (config 30%, policy 40%, version 20%, env 10%)
- **ICAP Scanning Integration** — 3-layer fallback: RFC 3507 TCP, policy-engine compliance gate, deterministic simulation
- **Policy Evolution Tracking** — version history, per-environment rollback
- **Web Dashboard** — 6-tab UI: Dashboard, ICAP Operator, Audit Log, Policy Versions, Validation, Assistant
- **NLP Assistant** — Groq llama-3.3-70b with tool calling for data queries and form automation
- **Validation Demos** — interactive risk calculator, conflict detector, health scenarios, traffic switching
- **Prometheus Metrics** — `/metrics` endpoint for all API operations
- **Performance Optimised** — TTL-cached scanning mode, lazy K8s client, 60s ICAP poll interval

## Quick Start

```bash
# From repo root
bash start.sh

# Or manually
cd components/meds-research
pip install -r requirements.txt
python -m uvicorn meds.api.main:app --reload --port 8000
```

Dashboard: **http://localhost:8000**

## Project Structure

```
meds-research/
├── meds/
│   ├── api/
│   │   └── main.py          # FastAPI app, all endpoints, NLP chat
│   ├── models/
│   │   ├── promotion.py     # Promotion, Environment, PromotionSpec models
│   │   └── requests.py      # Request schemas
│   ├── controllers/
│   │   └── promotion_controller.py  # Orchestrates scan + score + decision
│   ├── validation/
│   │   └── risk_scorer.py   # 4-factor risk scoring engine
│   ├── policy/
│   │   ├── standards.py     # Policy catalog (CIS, PCI-DSS, SOC2, ISO 27001)
│   │   └── version_store.py # Per-environment version history
│   ├── icap/
│   │   └── scanner.py       # 3-layer ICAP scanner with TTL cache
│   ├── audit/
│   │   └── log.py           # JSONL audit log (read + write)
│   └── monitoring/
│       └── metrics.py       # Prometheus metrics
├── static/
│   ├── index.html           # Single-page app (6 tabs)
│   ├── css/styles.css       # Theming, chat bubbles, card layouts
│   └── js/app.js            # All frontend logic, chat UI, form handlers
└── tests/
    ├── test_risk_scoring_scenarios.py    # 10 named scenarios, exact scores
    ├── test_conflict_scenarios.py        # 10 conflict + resolution classes
    └── test_health_score_scenarios.py    # ICAP health score validation
```

## API Endpoints

### Promotions
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/promotions` | Create and evaluate a promotion |
| GET | `/api/promotions` | List all promotions |
| GET | `/api/analytics` | Summary stats (total, approved, rejected, avg risk) |
| GET | `/api/audit` | Audit log with optional `event_type` filter |
| GET | `/api/environments` | List environments with thresholds |
| GET | `/api/policies` | Full policy catalog |
| GET | `/api/environments/{name}/versions` | Policy version history |
| POST | `/api/environments/{name}/rollback` | Rollback to a previous version |

### ICAP Operator (proxied to policy-engine)
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/icap/status` | Full CRD status |
| GET | `/api/icap/health` | Compact health summary |
| POST | `/api/icap/configure` | Apply scanning mode / replica count |

### Validation / Demo
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/demo/risk-score` | Interactive risk score calculator |
| POST | `/api/demo/conflicts` | Policy conflict detection and resolution |
| GET | `/api/demo/health-scenarios` | 7 ICAP health score scenarios |
| GET | `/api/demo/traffic-scenarios` | 8 SSDLB routing decision scenarios |

### NLP Assistant
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/nlp/chat` | Groq-powered chat with tool calling |

## NLP Assistant

Powered by **Groq** (free tier) with `llama-3.3-70b-versatile`.

**Requires:** `GROQ_API_KEY` in `.env` at the repo root.

**Capabilities via tool calling:**
- `get_promotions` — query live promotion data
- `get_audit_log` — search audit events
- `get_analytics` — fetch summary statistics
- `get_icap_status` — read ICAP health
- `fill_promotion_form` — populate the dashboard form from natural language
- `switch_tab` — navigate the UI programmatically

**Example queries:**
- "How many promotions were rejected this week?"
- "Promote myapp v2.0.0 from staging to production"
- "What does a risk score of 75 mean?"
- "Show me the ICAP health status"

## Risk Scoring

```
total_score = int(
    config_score   * 0.30 +
    policy_score   * 0.40 +
    version_score  * 0.20 +
    env_score      * 0.10
)
```

**Decision tiers** (relative to `max_allowed`):
- `> max_allowed` → REJECTED
- `> 80% of max` → APPROVED, elevated risk (requires manual review)
- `> 60% of max` → APPROVED, moderate risk (monitor closely)
- `<= 60% of max` → APPROVED, low risk

## ICAP Scanner (3-Layer Fallback)

1. **RFC 3507 TCP** — direct connection to ICAP service on port 1344
2. **Policy-engine compliance gate** — checks namespace policy approval via REST
3. **Deterministic simulation** — seeded random based on version + app name (threat probability: alpha 40%, beta 25%, rc 10%, stable 5%)

**Performance:** scanning mode is TTL-cached (60s) to avoid HTTP overhead on every scan.

## Environment Risk Thresholds

| Environment | Max Score | Notes |
|-------------|-----------|-------|
| Development | 80 | Permissive — most promotions pass |
| Staging | 60 | Pre-production gate |
| Production | 40 | Strictest — only stable, low-change deployments |

## Validation Test Suite

```bash
cd components/meds-research
pytest tests/ -v
```

| File | Scenarios | What it tests |
|------|-----------|---------------|
| `test_risk_scoring_scenarios.py` | 10 | Exact risk scores, recommendation tiers, factor weights |
| `test_conflict_scenarios.py` | 10 | Policy conflict detection and 3 resolution strategies |
| `test_health_score_scenarios.py` | 10 | ICAP health sub-scores, adaptive weights |

## Dependencies

```
fastapi==0.104.1
uvicorn[standard]==0.24.0
pydantic==2.5.0
httpx==0.25.1
prometheus-client==0.19.0
structlog==23.2.0
groq>=0.9.0
kubernetes==28.1.0
kopf==1.37.1
pytest==7.4.3
```

## Configuration

All thresholds are set in `meds/api/main.py`:

```python
environments_db["development"] = Environment(max_risk_score=80, ...)
environments_db["staging"]     = Environment(max_risk_score=60, ...)
environments_db["production"]  = Environment(max_risk_score=40, ...)
```

Risk factor weights are in `meds/validation/risk_scorer.py`.

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Port 8000 in use | `pkill -f uvicorn` or change port |
| Assistant shows key error | Add `GROQ_API_KEY` to `.env` and restart |
| Scanning mode reverts to block | Fixed — config is now always saved locally before K8s sync |
| Dashboard not updating | Hard refresh: Ctrl+Shift+R |

## Team

- IT22347626 (Kulatunga) — MEDS Component
- Part of CAPSLock Project (25-26J-043)

**Academic:** SLIIT 2025/26
