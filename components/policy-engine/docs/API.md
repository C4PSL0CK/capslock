# EAPE REST API Documentation

## Overview

The EAPE REST API provides programmatic access to all policy engine functionality. All endpoints accept and return JSON.

**Base URL:** `http://localhost:8080`  
**Version:** v1  
**Content-Type:** `application/json`

## Endpoints

### Health Check

#### GET /health

Check API server health status.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2026-01-05T20:30:00Z"
}
```

**Status Codes:**
- `200 OK` - Server is healthy

---

### Environment Detection

#### POST /api/detect

Detect environment type for a Kubernetes namespace.

**Request:**
```json
{
  "namespace": "prod-app-1"
}
```

**Response:**
```json
{
  "namespace": "prod-app-1",
  "environment": "prod",
  "confidence": 0.95,
  "indicators": {
    "labels": {
      "env": "production",
      "tier": "prod"
    },
    "annotations": {
      "environment": "production"
    }
  },
  "detected_at": "2026-01-05T20:30:00Z"
}
```

**Status Codes:**
- `200 OK` - Environment detected successfully
- `400 Bad Request` - Invalid namespace
- `404 Not Found` - Namespace not found

---

### Policy Management

#### GET /api/policies

List all available policy templates.

**Response:**
```json
{
  "policies": [
    {
      "name": "dev-policy",
      "version": "1.0",
      "environment": "dev",
      "scanning_mode": "log-only",
      "max_file_size": "100MB",
      "compliance_standards": []
    },
    {
      "name": "prod-policy",
      "version": "1.0",
      "environment": "prod",
      "scanning_mode": "block",
      "max_file_size": "25MB",
      "compliance_standards": ["pci-dss", "cis"]
    }
  ],
  "total": 3
}
```

**Status Codes:**
- `200 OK` - Policies retrieved successfully

---

#### GET /api/policies/get

Get a specific policy template by name.

**Query Parameters:**
- `name` (required) - Policy template name

**Example:** `/api/policies/get?name=prod-policy`

**Response:**
```json
{
  "name": "prod-policy",
  "version": "1.0",
  "environment": "prod",
  "description": "Production environment security policy",
  "icap_config": {
    "scanning_mode": "block",
    "max_file_size": "25MB",
    "allowed_extensions": [".txt", ".json"],
    "blocked_extensions": [".exe", ".sh"]
  },
  "performance_config": {
    "max_concurrent_scans": 10,
    "timeout_seconds": 30
  },
  "compliance_config": {
    "standards": ["pci-dss", "cis"],
    "audit_logging": true,
    "data_retention_days": 90
  }
}
```

**Status Codes:**
- `200 OK` - Policy found
- `400 Bad Request` - Missing name parameter
- `404 Not Found` - Policy not found

---

#### POST /api/policies/select

Select the best policy for given environment context.

**Request:**
```json
{
  "environment": "prod",
  "confidence": 0.95,
  "compliance_requirements": ["pci-dss", "soc2"],
  "risk_tolerance": "low"
}
```

**Response:**
```json
{
  "selected_policy": "prod-policy",
  "score": 0.98,
  "reasoning": "Exact environment match (prod), compliance requirements satisfied, risk tolerance aligned",
  "alternatives": [
    {
      "policy": "staging-policy",
      "score": 0.65,
      "reason": "Environment mismatch"
    }
  ]
}
```

**Status Codes:**
- `200 OK` - Policy selected successfully
- `400 Bad Request` - Invalid request parameters

---

### Conflict Management

#### POST /api/conflicts/detect

Detect conflicts between multiple policies.

**Request:**
```json
{
  "policy_names": ["dev-policy", "prod-policy"],
  "namespace": "test-app"
}
```

**Response:**
```json
{
  "namespace": "test-app",
  "total_conflicts": 3,
  "conflicts": [
    {
      "id": "conflict-1",
      "type": "scanning-mode",
      "severity": "critical",
      "description": "Conflicting scanning modes: log-only vs block",
      "policies": ["dev-policy", "prod-policy"],
      "details": {
        "dev-policy": "log-only",
        "prod-policy": "block"
      }
    },
    {
      "id": "conflict-2",
      "type": "compliance",
      "severity": "high",
      "description": "Differing compliance requirements",
      "policies": ["dev-policy", "prod-policy"],
      "details": {
        "dev-policy": [],
        "prod-policy": ["pci-dss", "soc2"]
      }
    }
  ],
  "generated_at": "2026-01-05T20:30:00Z"
}
```

**Status Codes:**
- `200 OK` - Conflicts detected (even if zero conflicts)
- `400 Bad Request` - Invalid policy names

---

#### POST /api/conflicts/resolve

Resolve conflicts using a specified strategy.

**Request:**
```json
{
  "policy_names": ["dev-policy", "prod-policy"],
  "strategy": "security-first",
  "namespace": "test-app",
  "environment": "prod"
}
```

**Response:**
```json
{
  "namespace": "test-app",
  "total_resolved": 3,
  "final_policy": "prod-policy",
  "strategy": "security-first",
  "resolutions": [
    {
      "conflict_id": "conflict-1",
      "chosen_policy": "prod-policy",
      "rejected_policies": ["dev-policy"],
      "reason": "Chose policy with most secure scanning mode: block",
      "resolved_at": "2026-01-05T20:30:00Z",
      "resolved_by": "system"
    }
  ]
}
```

**Status Codes:**
- `200 OK` - Conflicts resolved successfully
- `400 Bad Request` - Invalid strategy or policies

**Available Strategies:**
- `precedence` - Environment precedence (prod > staging > dev)
- `security-first` - Most secure option
- `environment-aware` - Match detected environment
- `manual` - Require manual intervention

---

## Error Responses

All error responses follow this format:
```json
{
  "error": "Error message description",
  "code": "ERROR_CODE",
  "timestamp": "2026-01-05T20:30:00Z"
}
```

### Common Error Codes

- `INVALID_REQUEST` - Malformed JSON or missing required fields
- `NAMESPACE_NOT_FOUND` - Kubernetes namespace does not exist
- `POLICY_NOT_FOUND` - Policy template does not exist
- `VALIDATION_ERROR` - Request validation failed
- `INTERNAL_ERROR` - Server error

---

## CORS Support

All endpoints support Cross-Origin Resource Sharing (CORS):

**Headers:**
- `Access-Control-Allow-Origin: *`
- `Access-Control-Allow-Methods: GET, POST, OPTIONS`
- `Access-Control-Allow-Headers: Content-Type`

**OPTIONS** requests return `200 OK` with CORS headers.

---

## Rate Limiting

Currently no rate limiting is enforced. Future versions may implement:
- 100 requests/minute per IP
- 1000 requests/hour per IP

---

## Authentication

Current version: **No authentication required**

Future versions will support:
- API key authentication
- JWT token validation
- Kubernetes service account tokens

---

## Examples

### cURL Examples

**Health Check:**
```bash
curl http://localhost:8080/health
```

**Detect Environment:**
```bash
curl -X POST http://localhost:8080/api/detect \
  -H "Content-Type: application/json" \
  -d '{"namespace": "prod-app-1"}'
```

**List Policies:**
```bash
curl http://localhost:8080/api/policies
```

**Get Policy:**
```bash
curl "http://localhost:8080/api/policies/get?name=prod-policy"
```

**Detect Conflicts:**
```bash
curl -X POST http://localhost:8080/api/conflicts/detect \
  -H "Content-Type: application/json" \
  -d '{
    "policy_names": ["dev-policy", "prod-policy"],
    "namespace": "test-app"
  }'
```

**Resolve Conflicts:**
```bash
curl -X POST http://localhost:8080/api/conflicts/resolve \
  -H "Content-Type: application/json" \
  -d '{
    "policy_names": ["dev-policy", "prod-policy"],
    "strategy": "security-first",
    "namespace": "test-app"
  }'
```

### Python Examples
```python
import requests

# Health check
response = requests.get("http://localhost:8080/health")
print(response.json())

# Detect environment
response = requests.post(
    "http://localhost:8080/api/detect",
    json={"namespace": "prod-app-1"}
)
print(response.json())

# List policies
response = requests.get("http://localhost:8080/api/policies")
print(response.json())

# Resolve conflicts
response = requests.post(
    "http://localhost:8080/api/conflicts/resolve",
    json={
        "policy_names": ["dev-policy", "prod-policy"],
        "strategy": "security-first",
        "namespace": "test-app"
    }
)
print(response.json())
```

---

## WebSocket Support

**Not currently implemented.** Future versions may support:
- Real-time policy updates
- Live conflict notifications
- Deployment status streaming

---

## Versioning

API version is included in health check response. Breaking changes will increment major version.

**Current:** v1.0.0

---

**Last Updated:** January 2026  
**Maintainer:** Kaavya Raigambandarage