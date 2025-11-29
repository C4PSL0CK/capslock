# EAPE - Environment-Aware Policy Engine

**Component of the CAPSLock Project**

## 🎯 Overview

EAPE (Environment-Aware Policy Engine) is an intelligent policy orchestrator that automatically detects Kubernetes environment types (dev/staging/prod) and applies appropriate ICAP security policies.

## 🚀 Features (55% Milestone)

### ✅ Critical Components (Target: 100%)
- **Environment Detection Engine (F1)** - Automatic environment classification with confidence scoring
- **Policy Selection Engine (F2)** - Multi-factor intelligent policy selection

### 🔧 Core Features 
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


## 🏗️ Project Structure
```
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
```

## 🔗 Integration with Other Components

- **Component 1 (ICAP Operator):** Receives policy configurations via IcapService CRD
- **Component 3 (MEDS):** Queries service metadata for policy decisions  
- **Component 4 (SSDLB):** Receives environment definitions and reports status


## 👤 Developer

- **Name:** Kaavya Raigambandarage
- **Email:** it22338716@my.sliit.lk
- **Component:** 2 - EAPE (Environment-Aware Policy Engine)


## 📝 License

Part of the CAPSLock project - SLIIT 2025

## 🎓 Academic Context

This project is part of the Research Project module at SLIIT, focusing on building a distributed security system with multiple integrated components for Kubernetes environments.