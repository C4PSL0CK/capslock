# MEDS - Multi-Environment Deployment System

## Overview
MEDS automates secure Kubernetes deployments across dev, staging, and production environments using intelligent risk assessment and policy evolution.

## Features
- **Risk Assessment Engine**: 4-factor weighted scoring (config, policy, version, environment)
- **USLO Framework**: Automated policy evolution with grace periods
- **Compliance Integration**: Maps to CIS, PCI DSS, SOC2, ISO27001
- **Web Dashboard**: Real-time promotion tracking and analytics

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start API Server
```bash
python -m uvicorn meds.api.main:app --reload
```

### 3. Open Dashboard
Open browser to: http://localhost:8000

## Architecture
```
User → REST API → Promotion Controller → Risk Assessment + USLO → Decision
```

## Project Structure
```
meds-research/
├── meds/
│   ├── models/          # Data models
│   ├── validation/      # Risk assessment
│   ├── policy/          # USLO engine
│   ├── controllers/     # Promotion logic
│   └── api/            # REST API
├── static/
│   ├── css/            # Styles
│   └── js/             # Frontend logic
└── tests/              # Unit tests
```

## Usage Examples

### Create Safe Promotion (Approved)
```
Name: customer-api-v123
Source: development
Target: staging
Version: v1.2.3
Policies: 1-2 policies
Result: APPROVED (risk ~28/60)
```

### Create Dangerous Promotion (Rejected)
```
Name: payment-prod-beta
Source: development
Target: production (SKIPPING STAGING!)
Version: v2.0.0-beta
Policies: 5+ critical policies
Result: REJECTED (risk ~75/40)
```

## API Endpoints
- `POST /api/promotions` - Create promotion
- `GET /api/promotions` - List promotions
- `GET /api/promotions/{id}` - Get details
- `GET /api/environments` - List environments
- `GET /api/policies` - Get policy catalog
- `GET /api/analytics` - Get metrics

## Research Contributions
1. **Multi-Factor Risk Assessment** - Weighted scoring vs binary pass/fail
2. **USLO Framework** - Automated policy lifecycle with compliance mapping

## Development
```bash
# Run tests
pytest

# Start with auto-reload
python -m uvicorn meds.api.main:app --reload --port 8000
```

## Configuration
Edit `meds/api/main.py` to modify:
- Environment risk thresholds (dev=80, staging=60, prod=40)
- Default policies per environment
- Risk factor weights

## Troubleshooting
- **Port 8000 in use**: `pkill -f uvicorn` or use `--port 8080`
- **Policies not loading**: Check `curl http://localhost:8000/api/policies`
- **Dashboard not showing**: Hard refresh browser (Ctrl+Shift+R)

## Team
- IT22347626 (Kulatunga) - MEDS Component
- Part of CAPSLock Project (25-26J-043)

## License
Academic Research Project - SLIIT 2025
