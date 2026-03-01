# MEDS - Multi-Environment Deployment System

**Component Owner**: IT22347626 (Marlon Kulatunga)  
**Part of**: CAPSLock Platform (Group 25-26J-043)

## Overview

MEDS automates secure Kubernetes deployments with intelligent risk assessment and policy-driven orchestration.

## Features

- **4-Factor Risk Assessment**: Weighted scoring (config 30%, policy 40%, version 20%, environment 10%)
- **USLO Framework**: Automated policy evolution with grace periods (48h/8h/0-2h)
- **Compliance Integration**: CIS Kubernetes, PCI DSS v4.0, SOC 2, ISO 27001
- **Web Dashboard**: Real-time promotion tracking
- **Environment Thresholds**: Dev (80), Staging (60), Production (40)

## Quick Start
```bash
# Navigate to MEDS directory
cd components/meds

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start server
uvicorn meds.api.main:app --reload
```

**Access**: http://localhost:8000

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/environments` | List environments |
| GET | `/api/policies` | Get policy catalog |
| POST | `/api/promotions` | Create promotion |
| GET | `/api/promotions` | List promotions |
| GET | `/api/analytics` | Get metrics |

**API Docs**: http://localhost:8000/docs

## Project Structure
```
meds/
├── meds/
│   ├── models/          # Data models
│   ├── validation/      # Risk assessment engine
│   ├── policy/          # USLO & policy standards
│   ├── controllers/     # Business logic
│   └── api/            # REST API
├── static/
│   ├── css/            # Dashboard styles
│   └── js/             # Frontend logic
└── requirements.txt    # Dependencies
```

## Integration with Other Components

### ICAP Operator Integration
```python
# ICAP sends scan results to MEDS
POST /api/security-scan
{
  "image": "customer-api:v1.2.3",
  "scan_status": "clean",
  "threats_found": 0
}
```

### Policy Engine Integration
```python
# MEDS queries Policy Engine for policies
GET http://policy-engine:9000/api/policies?environment=production
```

### Service Discovery Integration
```python
# MEDS checks service health
GET http://service-discovery:7000/api/health/customer-api?env=production
```

## Testing

### Safe Promotion Example (Approved ✅)
```
Name: customer-api-safe
Source: development → Target: staging
Version: v1.2.3
Policies: 1-2 standard policies
Expected: APPROVED (Risk ~28/60)
```

### Risky Promotion Example (Rejected ❌)
```
Name: payment-api-risky
Source: development → Target: production (SKIPPING STAGING!)
Version: v2.0.0-beta
Policies: 5+ critical policies
Expected: REJECTED (Risk ~75/40)
```

## Configuration

### Risk Factor Weights
Edit `meds/validation/risk_scorer.py`:
```python
self.config_weight = 0.30
self.policy_weight = 0.40
self.version_weight = 0.20
self.environment_weight = 0.10
```

### Environment Thresholds
Edit `meds/api/main.py`:
```python
environments_db["development"] = Environment(max_risk_score=80, ...)
environments_db["staging"] = Environment(max_risk_score=60, ...)
environments_db["production"] = Environment(max_risk_score=40, ...)
```

## Research Contributions

1. **Multi-Factor Risk Assessment**: Novel weighted scoring approach
2. **USLO Framework**: Automated policy evolution with compliance mapping
3. **Environment-Aware Security**: Progressive enforcement across deployment stages

## Contact

- **Student ID**: IT22347626
- **Email**: IT22347626@my.sliit.lk
- **Component**: MEDS (Multi-Environment Deployment System)

## Related Components

- [ICAP Operator](../icap-operator/) - IT22353634
- [Policy Engine](../policy-engine/) - IT22338716
- [Service Discovery](../service-discovery/) - IT22345028

---

**Part of CAPSLock Platform - SLIIT 2025**
