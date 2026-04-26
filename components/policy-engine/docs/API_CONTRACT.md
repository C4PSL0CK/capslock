# EAPE API Contract for Component Integration

## Base URL
```
Production: http://eape-service.capslock-system:8000
Development: http://localhost:8000
```

## Authentication
- Service Account Tokens (Kubernetes)
- API Keys (for external integrations)

---

## Endpoints

### 1. Health Check
```
GET /
```
**Response:** 200 OK
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2026-03-03T10:30:00Z",
  "k8s_connected": true
}
```

---

### 2. List Namespaces
```
GET /api/namespaces
```
**Response:** 200 OK
```json
[
  {
    "name": "payment-prod",
    "environment": "prod",
    "confidence": 0.95,
    "labels": {},
    "pod_count": 15
  }
]
```

---

### 3. Apply Policy
```
POST /api/namespaces/{namespace}/apply-policy
```
**Response:** 200 OK (even if compliance fails)
```json
{
  "namespace": "payment-prod",
  "success": true,
  "compliance_report": { "..." }
}
```
**Response:** 500 Internal Server Error
```json
{
  "detail": "Policy application failed: ..."
}
```

---

### 4. Get Compliance Status
```
GET /api/namespaces/{namespace}/compliance
```
**Response:** 200 OK
```json
{
  "overall_compliant": true,
  "overall_score": 0.98,
  "total_violations": 2
}
```

---

### 5. MEDS Integration Hook
```
POST /api/integration/meds/notify
```
**Request Body:**
```json
{
  "namespace": "payment-prod",
  "environment": "prod",
  "deployment_id": "deploy-12345"
}
```
**Response:** 200 OK
```json
{
  "status": "policy_applied",
  "compliant": true,
  "compliance_score": 0.98
}
```

---

### 6. ICAP Integration Hook
```
GET /api/integration/icap/policy-status/{namespace}
```
**Response:** 200 OK
```json
{
  "namespace": "payment-prod",
  "policy_approved": true,
  "compliance_score": 0.98,
  "violations": 2
}
```

---

## Error Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Bad Request (invalid namespace) |
| 404 | Namespace Not Found |
| 500 | Internal Server Error |

---

## Rate Limits
- 100 requests/minute per client
- 1000 requests/hour per client

---

## Versioning
- Current Version: `v1`
- API paths include version: `/api/v1/...` (future)
- Breaking changes increment major version