# EAPE - Environment-Aware Policy Engine

**Component 2 of CAPSLock Security System**  
**Project ID:** 25-26J-043  
**Version:** 1.0.0

## Overview

EAPE automatically detects Kubernetes environment types (dev/staging/prod) and applies appropriate security policies through integration with OPA Gatekeeper and Kyverno.

## Features

- ✅ Automatic environment detection from namespace labels
- ✅ Policy selection with conflict resolution
- ✅ OPA Gatekeeper & Kyverno integration
- ✅ REST API for automation
- ✅ CLI for manual operations
- ✅ Mock components for independent testing
- ✅ 83.6% test coverage

## Architecture
```
Environment Detection → Policy Selection → Conflict Resolution → Policy Application
```

**7-Step Workflow:**
1. Detect environment from namespace labels
2. Select optimal policy based on environment
3. Detect conflicts (if multiple candidates)
4. Resolve conflicts using strategy
5. Apply policy via ICAP Operator
6. Report status to Deployment System
7. Verify services via Service Discovery

## Quick Start

### Build
```bash
go build -o bin/policy-engine ./cmd/policy-engine
```

### Run
```bash
# List policies
./bin/policy-engine list

# Detect environment
./bin/policy-engine detect -n dev-test

# Apply policy
./bin/policy-engine apply -n prod-test

# Start API server
./bin/policy-engine serve --port 8080
```

## Project Structure
```
policy-engine/
├── cmd/policy-engine/       # CLI binary
├── pkg/
│   ├── api/                 # REST API (handlers, router)
│   ├── conflict/            # Conflict detection & resolution
│   ├── detector/            # Environment detection
│   ├── engine/              # Policy orchestration
│   ├── integrations/        # OPA/Kyverno converters
│   ├── mocks/               # Mock CAPSLock components
│   └── policy/              # Policy management
├── policies/templates/      # YAML policy definitions
├── tests/
│   ├── e2e/                 # End-to-end tests
│   ├── integration/         # API integration tests
│   └── performance/         # Benchmarks
└── docs/                    # Documentation
```

## Testing
```bash
# All tests
go test ./... -v

# Coverage
go test ./... -cover

# E2E tests
go test ./tests/e2e/ -v

# Integration tests
go test ./tests/integration/ -v

# Benchmarks
go test ./tests/performance/ -bench=. -benchmem
```

## Test Coverage

- **Overall: 83.6%**
- conflict: 89.9%
- detector: 80.0%
- policy: 83.5%
- opa: 82.6%
- mocks: 95.8%

## Performance

- Policy Selection: 882 ns/op
- Conflict Detection: 7.2 µs/op
- Environment Detection: 180 ms/op
- Full Workflow: 163 ms/op

## Integration with CAPSLock Components

- **Component 1 (ICAP Operator):** Policy application interface
- **Component 3 (Service Discovery):** Service health verification
- **Component 4 (Deployment System):** Status reporting

## Technologies

- Go 1.21+
- Kubernetes client-go
- REST API (net/http)
- YAML policy templates

## Academic Submission

- **Student:** Kaavya
- **Project:** 25-26J-043
- **Completion:** 43/43 tasks (100%)
- **Test Coverage:** 83.6%
- **Documentation:** Complete

---

**Last Updated:** January 2026