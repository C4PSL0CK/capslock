# EAPE - Environment-Aware Policy Engine

**Component 2 of the CAPSLock Project**

## 🎯 Overview

EAPE (Environment-Aware Policy Engine) is an intelligent policy orchestrator that automatically detects Kubernetes environment types (dev/staging/prod) and applies appropriate ICAP security policies.

## 🚀 Features (55% Milestone)

### ✅ Critical Components (Target: 100%)
- **Environment Detection Engine (F1)** - Automatic environment classification with confidence scoring
- **Policy Selection Engine (F2)** - Multi-factor intelligent policy selection

### 🔧 Core Features (Target: 55%+)
- Policy template management
- Conflict detection and resolution
- OPA Gatekeeper integration
- Kyverno integration
- REST API
- CLI interface
- Web Dashboard UI

## 📋 Prerequisites

- Go 1.21+
- Kubernetes (K3s/K8s)
- kubectl configured
- OPA Gatekeeper installed
- Kyverno installed

## 🛠️ Installation

bash
# From policy-engine directory
go mod download

# Build
go build -o bin/policy-engine cmd/policy-engine/main.go

# Run
./bin/policy-engine --help


## 🏗️ Project Structure

policy-engine/
├── cmd/policy-engine/      # CLI entry point
├── pkg/
│   ├── detector/           # Environment detection (F1) ⭐
│   ├── policy/             # Policy management & selection (F2) ⭐
│   ├── conflict/           # Conflict resolution
│   ├── integrations/       # OPA/Kyverno
│   ├── api/                # REST API
│   ├── engine/             # Orchestrator
│   └── mocks/              # Mock components
├── policies/templates/     # Policy YAML templates
├── web/dashboard/          # React UI
└── docs/                   # Documentation


## 🔗 Integration with Other Components

- **Component 1 (ICAP Operator):** Receives policy configurations via IcapService CRD
- **Component 3 (MEDS):** Queries service metadata for policy decisions  
- **Component 4 (SSDLB):** Receives environment definitions and reports status

## 🧪 Testing

bash
# Unit tests
go test ./...

# With coverage
go test -cover ./...

# Integration tests
go test -tags=integration ./tests/integration/...


## 👤 Developer

- **Name:** Kaavya Nethsara
- **Email:** it22338716@my.sliit.lk
- **Component:** 2 - EAPE (Environment-Aware Policy Engine)
- **Timeline:** November 26 - December 13, 2025

## 📊 Progress

- [x] Project setup
- [ ] Environment Detection (F1) - 0/5 tasks
- [ ] Policy Selection (F2) - 0/3 tasks
- [ ] Policy Management - 0/4 tasks
- [ ] Conflict Resolution - 0/3 tasks
- [ ] OPA Integration - 0/3 tasks
- [ ] Kyverno Integration - 0/2 tasks
- [ ] REST API - 0/3 tasks
- [ ] CLI - 0/2 tasks
- [ ] Web UI - 0/6 tasks

## 📝 License

Part of the CAPSLock project - SLIIT 2025