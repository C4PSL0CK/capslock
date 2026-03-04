# ICAP Operator

**Kubernetes Operator for ClamAV ICAP Services** | Component 1 of CAPSLOCK | Go / Kubebuilder

**Project ID:** 25-26J-043

## Overview

The ICAP Operator manages the full lifecycle of ClamAV-based ICAP (Internet Content Adaptation Protocol) scanning services inside a Kubernetes cluster. It watches a custom `ICAPService` CRD and reconciles the desired state — replicas, scanning mode, ClamAV image version — into running pods and services.

MEDS uses it as the last line of defence before a deployment reaches production: every artifact is streamed through ClamAV via the ICAP protocol (RFC 3507) and either cleared or blocked based on the configured scanning mode.

## Features

- Custom Resource Definition (`ICAPService`) for declarative ICAP configuration
- Automatic reconciliation of replica count and ClamAV image
- Exposes per-instance health scores to SSDLB for traffic-weighted routing
- Configurable scanning modes: `block`, `warn`, `log-only`
- Signature freshness tracking (health degrades after 6h, critical after 48h)
- Integration with Policy Engine for CRD patching via REST

## ICAP Protocol (RFC 3507)

The operator runs ClamAV in ICAP server mode on port **1344**. MEDS scans deployments by:

1. Opening a TCP connection to the ICAP service
2. Sending a synthetic `RESPMOD` request containing the deployment identity
3. Receiving a response: `204 No Content` (clean) or `200 OK` with `X-Infection-Found` header (threat detected)

## Custom Resource: ICAPService

```yaml
apiVersion: capslock.io/v1alpha1
kind: ICAPService
metadata:
  name: capslock-icap
  namespace: capslock-system
spec:
  replicas: 3
  scanningMode: block          # block | warn | log-only
  clamavImage: clamav/clamav:latest
```

**Status fields written by the operator:**
- `readyReplicas` — number of healthy pods
- `healthScore` — aggregate 0-100 health score
- `conditions` — standard Kubernetes condition array

## Health Score Model

The operator reports a per-instance health score (0-100) with adaptive weights:

| Sub-score | Default Weight | Description |
|-----------|---------------|-------------|
| Readiness | 25% | Fraction of desired replicas ready |
| Latency | 25% | Response time against configured threshold |
| Signature freshness | 20% | Age of ClamAV virus database |
| Error rate | 15% | Scan error ratio |
| Resource utilisation | 10% | CPU/memory within limits |
| Queue depth | 5% | Backlog relative to capacity |

Weights shift dynamically under traffic spikes, threat activity, or resource pressure.

## Scanning Modes

| Mode | Behaviour |
|------|-----------|
| `block` | Threat detected → deployment rejected |
| `warn` | Threat detected → logged, deployment continues |
| `log-only` | All scans recorded, no enforcement |

Mode is set via the CRD or the Policy Engine bridge API and persisted locally even when the cluster is unavailable.

## Prerequisites

- Go v1.24+
- Docker 17.03+
- kubectl v1.11.3+
- Kubernetes v1.11.3+ cluster (or k3s / minikube)

## Build and Deploy

```bash
# Build and push image
make docker-build docker-push IMG=<registry>/capslock-operator:tag

# Install CRDs
make install

# Deploy operator
make deploy IMG=<registry>/capslock-operator:tag

# Apply sample ICAPService
kubectl apply -k config/samples/
```

## Local Development (k3s)

`start.sh` in the repo root automatically detects k3s and starts the operator if a cluster is reachable:

```bash
bash start.sh
```

## Uninstall

```bash
kubectl delete -k config/samples/
make uninstall
make undeploy
```

## Integration with Other Components

| Component | Interaction |
|-----------|-------------|
| Policy Engine | Patches `ICAPService` CRD spec via K8s API or local state fallback |
| MEDS | Scans deployments via RFC 3507 TCP (port 1344) or policy-engine health endpoint |
| SSDLB | Reads per-instance health scores for traffic-weighted routing decisions |

## Helm Distribution

```bash
# Generate Helm chart
kubebuilder edit --plugins=helm/v2-alpha

# Install
helm install capslock-operator ./dist/chart/
```

## License

Copyright 2025. Licensed under the Apache License, Version 2.0.
See [LICENSE](http://www.apache.org/licenses/LICENSE-2.0) for details.
