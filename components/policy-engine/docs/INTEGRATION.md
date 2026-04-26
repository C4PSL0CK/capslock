# CAPSLock Component Integration Guide

This document defines the integration contracts between all CAPSLock components.

## Component Overview
```
┌─────────────────────────────────────────────────────────────┐
│                         MEDS Frontend                        │
│          (Multi-Environment Deployment System)               │
└─────────────────────────────────────────────────────────────┘
                    │              │              │
        ┌───────────┘              │              └───────────┐
        │                          │                          │
        ▼                          ▼                          ▼
┌──────────────┐          ┌──────────────┐          ┌──────────────┐
│    EAPE      │◄────────►│     ICAP     │          │    SSDLB     │
│ Policy Engine│          │   Operator   │          │ Load Balance │
└──────────────┘          └──────────────┘          └──────────────┘
```

## 1. MEDS ↔ EAPE Integration

### 1.1 MEDS Calls EAPE

**Use Case:** MEDS initiates deployment and needs policy validation

**Workflow:**
1. MEDS detects new deployment to namespace
2. MEDS calls EAPE to validate compliance before allowing deployment
3. EAPE validates namespace against policies
4. MEDS proceeds or blocks based on compliance result

**API Endpoints:**

#### Get Namespace Environment Detection
```http
GET /api/namespaces/{namespace}/environment
```

**Response:**
```json
{
  "name": "payment-prod",
  "environment": "prod",
  "confidence": 0.95,
  "labels": {
    "environment": "prod",
    "compliance-pci-dss": "true"
  },
  "pod_count": 15
}
```

#### Apply Policy to Namespace
```http
POST /api/namespaces/{namespace}/apply-policy
```

**Response:**
```json
{
  "namespace": "payment-prod",
  "environment": "prod",
  "confidence": 0.95,
  "selected_policy": "prod-policy",
  "conflicts": [],
  "compliance_report": {
    "overall_compliant": true,
    "overall_score": 0.98,
    "total_violations": 2,
    "cis": {
      "framework": "CIS Kubernetes Benchmark",
      "version": "v1.9",
      "score": 0.96,
      "passed": 26,
      "failed": 2
    },
    "pci_dss": {
      "framework": "PCI-DSS",
      "version": "v4.0",
      "score": 1.0,
      "passed": 16,
      "failed": 0
    }
  },
  "steps": [
    {
      "step_number": 1,
      "name": "Environment Detection",
      "status": "completed",
      "duration": 0.15
    },
    {
      "step_number": 5,
      "name": "Compliance Validation",
      "status": "passed",
      "duration": 1.23
    }
  ],
  "success": true
}
```

#### Get Compliance Status
```http
GET /api/namespaces/{namespace}/compliance
```

**Response:**
```json
{
  "timestamp": "2026-03-03T10:30:00Z",
  "namespace": "payment-prod",
  "overall_compliant": true,
  "overall_score": 0.98,
  "total_violations": 2,
  "summary": "Namespace is compliant with 2 minor violations",
  "cis": { "..." },
  "pci_dss": { "..." }
}
```

### 1.2 EAPE Notifies MEDS

**Use Case:** EAPE detects policy violations and notifies MEDS

**Webhook Endpoint (MEDS must implement):**
```http
POST /api/webhooks/eape/policy-violation
```

**EAPE sends:**
```json
{
  "namespace": "payment-prod",
  "violation_type": "compliance_failed",
  "severity": "high",
  "compliance_score": 0.65,
  "violations": [
    {
      "rule_id": "4.2.1",
      "severity": "CRITICAL",
      "description": "Privileged container detected"
    }
  ],
  "timestamp": "2026-03-03T10:30:00Z"
}
```

---

## 2. EAPE ↔ ICAP Integration

### 2.1 ICAP Calls EAPE

**Use Case:** ICAP Operator needs to check if namespace has approved policy before scanning images

**API Endpoint:**
```http
GET /api/integration/icap/policy-status/{namespace}
```

**Response:**
```json
{
  "namespace": "payment-prod",
  "policy_approved": true,
  "compliance_score": 0.98,
  "violations": 2,
  "frameworks": {
    "cis": 0.96,
    "pci_dss": 1.0
  }
}
```

**ICAP Decision Logic:**
```
IF policy_approved == true:
    → Allow image scanning and deployment
ELSE IF compliance_score >= 0.90 AND violations < 5:
    → Allow with warning
ELSE:
    → Block deployment
```

### 2.2 EAPE Calls ICAP

**Use Case:** EAPE needs to verify if images have been scanned

**Webhook Endpoint (ICAP must implement):**
```http
GET /api/icap/scan-status/{namespace}/{image}
```

**ICAP responds:**
```json
{
  "image": "payment-service:v2.3.1",
  "namespace": "payment-prod",
  "scan_status": "clean",
  "vulnerabilities": {
    "critical": 0,
    "high": 2,
    "medium": 5,
    "low": 10
  },
  "malware_detected": false,
  "scanned_at": "2026-03-03T09:15:00Z"
}
```

---

## 3. MEDS ↔ ICAP Integration

### 3.1 MEDS Triggers ICAP Scan

**Use Case:** MEDS promotes image to new environment, triggers ICAP scan

**API Endpoint (ICAP implements):**
```http
POST /api/icap/scan-image
```

**MEDS sends:**
```json
{
  "image": "payment-service:v2.3.1",
  "namespace": "payment-prod",
  "environment": "prod",
  "initiated_by": "meds-promotion-controller"
}
```

### 3.2 ICAP Notifies MEDS

**Use Case:** ICAP completes scan and notifies MEDS

**Webhook Endpoint (MEDS implements):**
```http
POST /api/webhooks/icap/scan-complete
```

**ICAP sends:**
```json
{
  "image": "payment-service:v2.3.1",
  "namespace": "payment-prod",
  "scan_result": "clean",
  "allow_deployment": true
}
```

---

## 4. Integration Flow Examples

### 4.1 Deployment Workflow (Happy Path)
```
1. Developer pushes code
   └─► MEDS detects new version

2. MEDS calls EAPE: GET /api/namespaces/payment-staging/environment
   └─► EAPE returns: environment="staging", confidence=0.92

3. MEDS calls EAPE: POST /api/namespaces/payment-staging/apply-policy
   └─► EAPE validates compliance
   └─► Returns: overall_compliant=true, score=0.95

4. MEDS calls ICAP: POST /api/icap/scan-image
   └─► ICAP scans image
   └─► ICAP notifies MEDS: scan_result="clean"

5. MEDS allows deployment
   └─► Updates SSDLB with new endpoints

6. SSDLB distributes traffic
```

### 4.2 Deployment Blocked (Compliance Failure)
```
1. Developer pushes code with privileged container
   └─► MEDS detects new version

2. MEDS calls EAPE: POST /api/namespaces/payment-prod/apply-policy
   └─► EAPE detects: privileged container (CIS 4.2.1 violation)
   └─► Returns: overall_compliant=false, score=0.62

3. MEDS blocks deployment
   └─► Sends notification to developer
   └─► Provides remediation guidance from EAPE

4. Developer fixes privileged container
   └─► Retry from step 1
```

---

## 5. Component Responsibilities

### EAPE (This Component)
- Environment detection (7-factor algorithm)
- Policy selection
- CIS Kubernetes Benchmark validation (28 checks)
- PCI-DSS validation (16 requirements)
- Conflict resolution
- Policy enforcement recommendations

### MEDS (Component 1)
- Deployment orchestration across environments
- Calling EAPE for policy validation
- Promotion workflow (dev → staging → prod)
- User interface for all components
- Deployment status tracking

### ICAP (Component 4)
- Image malware scanning
- Vulnerability assessment
- Scan result storage
- Integration with external scanners

### SSDLB (Component 3)
- Service discovery
- Load balancing
- Traffic distribution
- Health monitoring

---

## 6. Data Exchange Formats

### Common Headers
All API calls should include:
```http
Content-Type: application/json
X-Component: meds|eape|icap|ssdlb
X-Request-ID: <uuid>
```

### Error Format
Standard error response:
```json
{
  "error": {
    "code": "COMPLIANCE_FAILED",
    "message": "Namespace violates PCI-DSS requirements",
    "details": {
      "violations": 5,
      "critical_violations": 2
    },
    "timestamp": "2026-03-03T10:30:00Z"
  }
}
```

---

## 7. Testing Integration

### EAPE Mock Responses (for MEDS development)

Create test namespace labels:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: test-staging
  labels:
    environment: staging
    compliance-pci-dss: "true"
    tier: staging
```

Test EAPE endpoints:
```bash
# Test environment detection
curl http://localhost:8000/api/namespaces/test-staging/environment

# Test policy application
curl -X POST http://localhost:8000/api/namespaces/test-staging/apply-policy

# Test compliance validation
curl http://localhost:8000/api/namespaces/test-staging/compliance
```

---

## 8. Deployment Configuration

### Environment Variables

**EAPE:**
```bash
EAPE_API_PORT=8000
EAPE_GO_BINARY_PATH=./bin/policy-engine
KUBECONFIG=/path/to/kubeconfig
```

**MEDS:**
```bash
EAPE_API_URL=http://eape-service:8000
ICAP_API_URL=http://icap-service:8080
SSDLB_API_URL=http://ssdlb-service:8081
```

### Service Discovery

Components should be accessible via Kubernetes services:
```yaml
# eape-service
apiVersion: v1
kind: Service
metadata:
  name: eape-service
  namespace: capslock-system
spec:
  selector:
    app: eape
  ports:
  - port: 8000
    targetPort: 8000
```

---

## 9. Monitoring & Observability

### Metrics to Track

**EAPE Metrics:**
- `eape_policy_applications_total` - Total policy applications
- `eape_compliance_validations_total` - Total validations
- `eape_compliance_failures_total` - Failed validations
- `eape_environment_detection_duration_seconds` - Detection latency

**MEDS Should Monitor:**
- EAPE API health (`GET /`)
- Policy application success rate
- Compliance scores over time

---

## 10. Security Considerations

### Authentication
- Component-to-component calls should use service accounts
- API keys or JWT tokens for authentication
- mTLS for production communication

### Authorization
- MEDS has admin access to all EAPE endpoints
- ICAP has read-only access to policy status
- External users have no direct EAPE access (via MEDS only)

### Data Privacy
- Compliance reports may contain sensitive configuration data
- Encrypt data in transit (TLS 1.3)
- Do not log sensitive policy violations in plain text