# CAPSLOCK

**CAPSLock Security Platform** — cloud-native ICAP content inspection with intelligent deployment management, policy enforcement, and AI-assisted operations.

**Project ID:** 25-26J-043

## Overview

CAPSLOCK is a microservices system that secures Kubernetes deployments through a pipeline of content scanning (ICAP), risk-based policy enforcement, adaptive load balancing, and a unified management dashboard. Every software promotion passes through threat detection and risk scoring before reaching production.

## Architecture

```
Developer → CAPSLOCK Dashboard (MEDS)
               ↓
         Risk Scorer + ICAP Scanner
               ↓
         Policy Engine (Go)  ←→  Kubernetes CRDs
               ↓
         SSDLB (traffic routing)
               ↓
         ICAP Operator (ClamAV scanning)
```

## Components

| Component | Language | Role |
|-----------|----------|------|
| [MEDS](components/meds-research/) | Python / FastAPI | Deployment dashboard, risk scoring, NLP assistant |
| [Policy Engine](components/policy-engine/) | Go + Python bridge | Policy conflict resolution, ICAP operator bridge, K8s CRD management |
| [SSDLB](components/ssdlb/) | Go | Adaptive traffic routing, ICAP-health-weighted load balancing |
| [ICAP Operator](components/icap-operator/) | Go / Kubebuilder | Kubernetes operator managing ClamAV ICAP service lifecycle |

## Quick Start

```bash
# 1. Add your Groq API key (free at console.groq.com)
echo "GROQ_API_KEY=gsk_..." > .env

# 2. Start everything
bash start.sh
```

`start.sh` auto-detects k3s/minikube, sources `.env` for secrets, and starts all services.

Dashboard: **http://localhost:8000**

## Dashboard Tabs

| Tab | Purpose |
|-----|---------|
| Dashboard | Create promotions, view recent deployments |
| ICAP Operator | Monitor health, configure scanning mode and replicas |
| Audit Log | Full event history with filtering |
| Policy Versions | Version history and rollback per environment |
| Validation | Interactive risk calculator, conflict detector, health scenarios, traffic demos |
| Assistant | NLP chat powered by Groq llama-3.3-70b |

## Environment Risk Thresholds

| Environment | Max Risk Score | Pipeline Position |
|-------------|---------------|-------------------|
| Development | 80 | Entry point |
| Staging | 60 | Pre-production gate |
| Production | 40 | Strictest gate |

## Risk Score Factors

| Factor | Weight | Description |
|--------|--------|-------------|
| Configuration complexity | 30% | Version maturity (alpha/beta/rc/stable) |
| Policy changes | 40% | Number of policies added or removed |
| Version delta | 20% | Semantic version distance |
| Environment transition | 10% | Risk of the source→target hop |

## Repository Structure

```
capslock/
├── components/
│   ├── meds-research/        # MEDS dashboard + API
│   ├── policy-engine/        # Go policy engine + Python bridge
│   ├── ssdlb/                # Traffic routing service
│   └── icap-operator/        # Kubernetes operator
├── scripts/
│   └── demo_traffic_switching.py  # SSDLB scenario demo
├── manifests/                # Kubernetes manifests and CRDs
├── gitops/                   # Kustomize configs
├── start.sh                  # Single-command startup
└── .env                      # Secrets (gitignored)
```

## Secrets

Create `.env` in the project root (never committed):

```bash
GROQ_API_KEY=gsk_...
```

`start.sh` sources this file automatically.

## Team

| Component | Student ID |
|-----------|-----------|
| ICAP Operator | IT22347626 (Kulatunga) |
| Policy Engine | Kaavya |
| MEDS / Dashboard | IT22347626 |
| SSDLB | - |

**Academic:** SLIIT 2025/26 — Project 25-26J-043
