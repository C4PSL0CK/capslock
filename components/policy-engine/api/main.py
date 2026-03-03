from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import subprocess
import json
from datetime import datetime

app = FastAPI(
    title="EAPE Policy Engine API",
    description="Environment-Aware Policy Engine for CAPSLock - Integrates with MEDS",
    version="1.0.0"
)

# CORS middleware for MEDS integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for MEDS frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# Pydantic Models for MEDS Integration
# ============================================================================

class RuleViolation(BaseModel):
    rule_id: str
    section: str
    title: str
    severity: str
    description: str
    reason: str
    remediation: str
    references: List[str] = []
    affected_resources: List[str] = []

class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

class FrameworkReport(BaseModel):
    framework: str
    version: str
    compatible: bool
    score: float
    total_checks: int
    passed: int
    failed: int
    passed_rules: List[str]
    failed_rules: List[RuleViolation]
    severity_breakdown: SeverityBreakdown
    validated_at: str

class ComplianceReport(BaseModel):
    timestamp: str
    namespace: str
    cis: Optional[FrameworkReport] = None
    pci_dss: Optional[FrameworkReport] = None
    overall_compliant: bool
    overall_score: float
    total_violations: int
    summary: str

class WorkflowStep(BaseModel):
    step_number: int
    name: str
    status: str
    duration: float
    details: str = ""
    error: str = ""

class ApplyPolicyResponse(BaseModel):
    namespace: str
    environment: str
    confidence: float
    selected_policy: str
    conflicts: List[str] = []
    compliance_report: Optional[ComplianceReport] = None
    steps: List[WorkflowStep]
    success: bool
    error: str = ""
    start_time: str
    end_time: str

class NamespaceInfo(BaseModel):
    name: str
    environment: str
    confidence: float
    labels: Dict[str, str]
    pod_count: int

class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str
    k8s_connected: bool

# ============================================================================
# API Endpoints for MEDS Integration
# ============================================================================

@app.get("/", response_model=HealthResponse)
async def health_check():
    """Health check endpoint for MEDS to verify EAPE is running"""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "k8s_connected": True  # TODO: Add actual K8s connectivity check
    }

@app.get("/api/namespaces", response_model=List[NamespaceInfo])
async def list_namespaces():
    """
    List all namespaces with detected environments
    Used by MEDS to show namespace status
    """
    try:
        # Call Go CLI
        result = subprocess.run(
            ["./bin/policy-engine", "detect-json"],
            capture_output=True,
            text=True,
            check=True
        )
        
        namespaces = json.loads(result.stdout)
        return namespaces
    
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to detect namespaces: {e.stderr}"
        )
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to parse namespace data: {str(e)}"
        )

@app.post("/api/namespaces/{namespace}/apply-policy", response_model=ApplyPolicyResponse)
async def apply_policy(namespace: str):
    """
    Apply policy to a namespace with full compliance validation
    Called by MEDS during deployment workflow
    """
    try:
        # Call Go CLI to apply policy
        result = subprocess.run(
            ["./bin/policy-engine", "apply-json", "-n", namespace],
            capture_output=True,
            text=True,
            check=False  # Don't raise on non-zero exit (we handle it)
        )
        
        # Parse result (even if failed, we get JSON)
        apply_result = json.loads(result.stdout)
        
        return apply_result
    
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Policy application failed: {e.stderr}"
        )
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to parse apply result: {str(e)}"
        )

@app.get("/api/namespaces/{namespace}/compliance", response_model=ComplianceReport)
async def get_compliance_status(namespace: str):
    """
    Get compliance validation status for a namespace
    Used by MEDS to display compliance dashboard
    """
    try:
        # Call Go CLI to validate compliance
        result = subprocess.run(
            ["./bin/policy-engine", "validate-compliance", "-n", namespace],
            capture_output=True,
            text=True,
            check=False  # Don't raise on non-zero exit
        )
        
        compliance_report = json.loads(result.stdout)
        return compliance_report
    
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Compliance validation failed: {e.stderr}"
        )
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to parse compliance data: {str(e)}"
        )

@app.get("/api/namespaces/{namespace}/environment")
async def get_environment_detection(namespace: str):
    """
    Get detailed environment detection for a namespace
    Used by MEDS to show confidence scores and detection factors
    """
    try:
        # Get all namespaces and filter
        result = subprocess.run(
            ["./bin/policy-engine", "detect-json"],
            capture_output=True,
            text=True,
            check=True
        )
        
        namespaces = json.loads(result.stdout)
        
        # Find the specific namespace
        for ns in namespaces:
            if ns["name"] == namespace:
                return ns
        
        raise HTTPException(
            status_code=404,
            detail=f"Namespace '{namespace}' not found"
        )
    
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Environment detection failed: {e.stderr}"
        )

# ============================================================================
# Integration Endpoints for Other Components
# ============================================================================

@app.post("/api/integration/meds/notify")
async def meds_notification(data: Dict[str, Any]):
    """
    Receive notifications from MEDS about deployments
    MEDS calls this when a new deployment is promoted
    """
    namespace = data.get("namespace")
    environment = data.get("environment")
    
    if not namespace:
        raise HTTPException(status_code=400, detail="namespace required")
    
    # Trigger policy application
    try:
        result = subprocess.run(
            ["./bin/policy-engine", "apply-json", "-n", namespace],
            capture_output=True,
            text=True,
            check=False
        )
        
        apply_result = json.loads(result.stdout)
        
        return {
            "status": "policy_applied" if apply_result["success"] else "policy_failed",
            "namespace": namespace,
            "compliance_score": apply_result.get("compliance_report", {}).get("overall_score", 0.0),
            "compliant": apply_result.get("compliance_report", {}).get("overall_compliant", False)
        }
    
    except Exception as e:
        return {
            "status": "error",
            "namespace": namespace,
            "error": str(e)
        }

@app.get("/api/integration/icap/policy-status/{namespace}")
async def get_policy_for_icap(namespace: str):
    """
    Get current policy status for ICAP operator
    ICAP calls this to check if namespace has approved policies
    """
    try:
        result = subprocess.run(
            ["./bin/policy-engine", "validate-compliance", "-n", namespace],
            capture_output=True,
            text=True,
            check=False
        )
        
        compliance_report = json.loads(result.stdout)
        
        return {
            "namespace": namespace,
            "policy_approved": compliance_report["overall_compliant"],
            "compliance_score": compliance_report["overall_score"],
            "violations": compliance_report["total_violations"],
            "frameworks": {
                "cis": compliance_report.get("cis", {}).get("score", 0.0),
                "pci_dss": compliance_report.get("pci_dss", {}).get("score", 0.0)
            }
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get policy status: {str(e)}"
        )

# ============================================================================
# Utility Endpoints
# ============================================================================

@app.get("/api/policies")
async def list_available_policies():
    """List all available policy templates"""
    return {
        "policies": [
            {
                "name": "dev-policy",
                "environment": "dev",
                "compliance": ["cis"],
                "enforcement": "audit"
            },
            {
                "name": "staging-policy",
                "environment": "staging",
                "compliance": ["cis", "pci-dss"],
                "enforcement": "enforce"
            },
            {
                "name": "prod-policy",
                "environment": "prod",
                "compliance": ["cis", "pci-dss"],
                "enforcement": "strict"
            }
        ]
    }

@app.get("/api/compliance/frameworks")
async def list_compliance_frameworks():
    """List supported compliance frameworks"""
    return {
        "frameworks": [
            {
                "name": "CIS Kubernetes Benchmark",
                "version": "1.9",
                "total_checks": 28,
                "sections": ["4.1", "4.2", "4.3", "4.4", "4.5"]
            },
            {
                "name": "PCI-DSS",
                "version": "4.0",
                "total_requirements": 16,
                "applicable_to": ["staging", "prod"]
            }
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)