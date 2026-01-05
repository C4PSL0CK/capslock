# EAPE Architecture Documentation

## System Overview

The Environment-Aware Policy Engine (EAPE) is Component 2 of the CAPSLock security system. It automatically detects Kubernetes environment types and applies appropriate security policies.

## High-Level Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                     CAPSLock System                         │
├─────────────────────────────────────────────────────────────┤
│  Component 1: Multi-Environment Deployment System           │
│  Component 2: EAPE (Environment-Aware Policy Engine) ◄──    │
│  Component 3: Service Discovery & Load Balancing            │
│  Component 4: Kubernetes ICAP Operator                      │
└─────────────────────────────────────────────────────────────┘
```

## EAPE Component Architecture

### Core Components

1. **Environment Detector** (`pkg/detector`)
   - Analyzes Kubernetes namespace labels
   - Classifies environments (dev/staging/prod)
   - Provides confidence scores

2. **Policy Manager** (`pkg/policy`)
   - Loads and validates policy templates
   - Manages YAML-based policy definitions
   - Supports ICAP, performance, and compliance configs

3. **Policy Selector** (`pkg/policy`)
   - Selects optimal policy based on environment
   - Calculates selection scores
   - Considers compliance requirements

4. **Conflict Detector** (`pkg/conflict`)
   - Identifies conflicts between policies
   - Classifies conflict types and severity
   - Generates conflict reports

5. **Conflict Resolver** (`pkg/conflict`)
   - Resolves policy conflicts using strategies
   - Supports precedence, security-first, environment-aware
   - Provides resolution reasoning

6. **Integration Layer** (`pkg/integrations`)
   - OPA Gatekeeper converter
   - Kyverno ClusterPolicy converter
   - Generates Kubernetes-native resources

7. **Policy Engine** (`pkg/engine`)
   - Orchestrates complete workflow
   - Coordinates all components
   - Manages 7-step policy application

8. **REST API** (`pkg/api`)
   - HTTP endpoints for external access
   - JSON request/response format
   - Health checks and metrics

## Workflow Architecture

### 7-Step Policy Application Workflow
```
1. Environment Detection
   ↓
2. Policy Selection
   ↓
3. Conflict Detection (if multiple candidates)
   ↓
4. Conflict Resolution (if conflicts found)
   ↓
5. Policy Application (via ICAP Operator)
   ↓
6. Status Reporting (to Deployment System)
   ↓
7. Service Verification (via Service Discovery)
```

## Data Flow
```
Kubernetes Namespace
    ↓ (labels)
Environment Detector
    ↓ (environment context)
Policy Selector
    ↓ (selected policy)
Conflict Detector
    ↓ (conflict report)
Conflict Resolver
    ↓ (resolution)
ICAP Operator (Component 1)
    ↓ (status)
Deployment System (Component 4)
```

## Integration Points

### Component 1: ICAP Operator
- **Interface:** MockIcapOperator
- **Methods:** ApplyPolicy(), RemovePolicy(), GetAppliedPolicy()
- **Contract:** Namespace labeling standards

### Component 3: Service Discovery
- **Interface:** MockServiceDiscovery
- **Methods:** GetServices(), GetHealthyServices()
- **Contract:** Service health reporting

### Component 4: Deployment System
- **Interface:** MockDeploymentSystem
- **Methods:** ReportPolicyStatus(), GetEnvironmentMetadata()
- **Contract:** Policy enforcement handoff

## Technology Stack

- **Language:** Go 1.21+
- **Framework:** Standard library (net/http)
- **Kubernetes:** client-go v0.28.x
- **Testing:** Go testing, httptest
- **Dependencies:** YAML parsing (gopkg.in/yaml.v3)

## Directory Structure
```
policy-engine/
├── cmd/
│   └── policy-engine/        # CLI binary
├── pkg/
│   ├── api/                  # REST API
│   ├── conflict/             # Conflict detection/resolution
│   ├── detector/             # Environment detection
│   ├── engine/               # Orchestration
│   ├── integrations/         # OPA/Kyverno converters
│   ├── mocks/                # Mock components
│   └── policy/               # Policy management
├── policies/
│   └── templates/            # YAML policy definitions
├── tests/
│   ├── e2e/                  # End-to-end tests
│   ├── integration/          # API integration tests
│   └── performance/          # Benchmarks
└── docs/                     # Documentation
```

## Design Decisions

### 1. YAML-Based Policy Templates
**Rationale:** Human-readable, version-controllable, Kubernetes-native

### 2. Mock Integration Components
**Rationale:** Enable independent development and testing without full CAPSLock deployment

### 3. Priority-Based Conflict Resolution
**Rationale:** Deterministic resolution with clear precedence rules

### 4. 7-Step Orchestrated Workflow
**Rationale:** Clear separation of concerns, easy to debug and extend

### 5. REST API + CLI
**Rationale:** Dual interface supports both automation and manual operations

## Security Considerations

- No credentials stored in policy templates
- Read-only Kubernetes client (no write operations)
- Input validation on all API endpoints
- Safe YAML parsing with size limits
- Conflict resolution prevents policy bypass

## Performance Characteristics

- Policy Selection: ~882ns/op (sub-microsecond)
- Conflict Detection: ~7.2µs/op
- Environment Detection: ~180ms/op
- Full Workflow: ~163ms/op
- Memory: ~14KB per operation

## Scalability

- Stateless design (no database required)
- Horizontal scaling via multiple instances
- Policy templates cached in memory
- Kubernetes API calls optimized with caching

## Future Enhancements

1. Policy versioning and rollback
2. Audit logging and compliance reporting
3. Real-time policy updates via webhooks
4. Advanced conflict resolution strategies
5. Integration with policy-as-code tools

---

**Version:** 1.0.0  
**Last Updated:** January 2026  
**Author:** Kaavya Raigambandarage