import asyncio
import os

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import subprocess
import json
from datetime import datetime

# URL of the SSDLB controller (set via env var)
SSDLB_URL = os.getenv("SSDLB_URL", "").rstrip("/")

# ICAP Operator CRD settings
ICAP_NAMESPACE   = os.getenv("ICAP_NAMESPACE",   "capslock-system")
ICAP_SERVICE_NAME = os.getenv("ICAP_SERVICE_NAME", "capslock-icap")
ICAP_GROUP       = "security.capslock.io"
ICAP_VERSION     = "v1alpha1"
ICAP_PLURAL      = "icapservices"

# Try to load the Kubernetes client (available only when running in/near a cluster)
try:
    from kubernetes import client as _k8s_client, config as _k8s_config
    try:
        _k8s_config.load_incluster_config()
        K8S_AVAILABLE = True
    except Exception:
        try:
            _k8s_config.load_kube_config()
            K8S_AVAILABLE = True
        except Exception:
            K8S_AVAILABLE = False
except ImportError:
    K8S_AVAILABLE = False

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


@app.get("/api/integration/ssdlb/status")
async def get_ssdlb_status():
    """
    Get current SSDLB load-balancer state and traffic trend.
    Called by MEDS dashboard or policy workflows to check ICAP service health.
    """
    if not SSDLB_URL:
        return {"status": "not_configured", "message": "SSDLB_URL env var not set"}

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            state_resp, trend_resp = await asyncio.gather(
                client.get(f"{SSDLB_URL}/state"),
                client.get(f"{SSDLB_URL}/trend-debug"),
                return_exceptions=True,
            )

        state = state_resp.json() if not isinstance(state_resp, Exception) else {}
        trend = trend_resp.json() if not isinstance(trend_resp, Exception) else {}

        return {
            "status": "ok",
            "lb_state": state,
            "traffic_trend": trend,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}

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

# ============================================================================
# ICAP Operator Bridge  (reads/writes the ICAPService CRD via the K8s API)
# Falls back to structured synthetic data when not running near a cluster.
# ============================================================================

def _get_icap_crd_status() -> Dict[str, Any]:
    """
    Read the live ICAPService CRD status from the Kubernetes API server.
    Returns a structured dict identical in shape to the synthetic fallback
    so callers never need to branch on K8S_AVAILABLE.
    """
    if not K8S_AVAILABLE:
        raise RuntimeError("Kubernetes API not reachable")

    crd_api = _k8s_client.CustomObjectsApi()
    obj = crd_api.get_namespaced_custom_object(
        group=ICAP_GROUP,
        version=ICAP_VERSION,
        namespace=ICAP_NAMESPACE,
        plural=ICAP_PLURAL,
        name=ICAP_SERVICE_NAME,
    )
    spec   = obj.get("spec",   {})
    status = obj.get("status", {})
    return {
        "name":              obj["metadata"]["name"],
        "namespace":         obj["metadata"]["namespace"],
        "ready_replicas":    status.get("readyReplicas",      0),
        "desired_replicas":  spec.get("replicas",             3),
        "health_score":      status.get("currentHealthScore", 0),
        "last_scaling_time": status.get("lastScalingTime",    ""),
        "conditions":        status.get("conditions",         []),
        "scanning_mode":     spec.get("icapConfig", {}).get("scanningMode", "block"),
        "clamav_image":      spec.get("clamavConfig", {}).get("image", "clamav/clamav:latest"),
        "source": "kubernetes",
    }


def _synthetic_icap_status() -> Dict[str, Any]:
    """Structured synthetic status used when no K8s cluster is available."""
    return {
        "name":              ICAP_SERVICE_NAME,
        "namespace":         ICAP_NAMESPACE,
        "ready_replicas":    3,
        "desired_replicas":  3,
        "health_score":      92,
        "last_scaling_time": datetime.utcnow().isoformat(),
        "conditions":        [{"type": "Ready", "status": "True"}],
        "scanning_mode":     "block",
        "clamav_image":      "clamav/clamav:latest",
        "source": "synthetic",
    }


@app.get("/api/icap/operator/status")
async def get_icap_operator_status():
    """
    Return the live ICAPService CRD status from the icap-operator.
    Consumed by MEDS, SSDLB, and the dashboard to show ICAP health.
    """
    try:
        return _get_icap_crd_status()
    except Exception:
        return _synthetic_icap_status()


class IcapConfigureRequest(BaseModel):
    scanning_mode: Optional[str] = None   # log-only | warn | block
    replicas:      Optional[int] = None   # 1–10


@app.post("/api/icap/operator/configure")
async def configure_icap_operator(req: IcapConfigureRequest):
    """
    Patch the ICAPService CRD spec so the icap-operator reconciles the change.
    Accepted by MEDS when a promotion changes the security posture of an environment.
    """
    if not K8S_AVAILABLE:
        return {
            "status": "accepted_synthetic",
            "message": "No K8s cluster reachable — change recorded but not applied",
            "scanning_mode": req.scanning_mode,
            "replicas":      req.replicas,
        }

    patch: Dict[str, Any] = {"spec": {}}
    if req.scanning_mode:
        patch["spec"]["icapConfig"] = {"scanningMode": req.scanning_mode}
    if req.replicas is not None:
        patch["spec"]["replicas"] = req.replicas

    if not patch["spec"]:
        raise HTTPException(status_code=400, detail="No fields to patch")

    try:
        crd_api = _k8s_client.CustomObjectsApi()
        crd_api.patch_namespaced_custom_object(
            group=ICAP_GROUP,
            version=ICAP_VERSION,
            namespace=ICAP_NAMESPACE,
            plural=ICAP_PLURAL,
            name=ICAP_SERVICE_NAME,
            body=patch,
        )
        return {"status": "patched", "patch": patch["spec"]}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/icap/health")
async def get_icap_health():
    """
    Return a compact health summary for the SSDLB to use in routing decisions.
    Shape mirrors what SSDLB expects: top-level health_score + per-instance breakdown.
    """
    try:
        s = _get_icap_crd_status()
    except Exception:
        s = _synthetic_icap_status()

    ready    = s["ready_replicas"]
    desired  = s["desired_replicas"]
    score    = s["health_score"]

    # Synthesise per-instance health (operator tracks aggregate; split evenly with
    # small jitter so SSDLB can weight individual a/b/c DestinationRule subsets)
    import random, hashlib
    instances = {}
    for ver in ("a", "b", "c"):
        seed = int(hashlib.md5(f"{ICAP_SERVICE_NAME}:{ver}:{score}".encode()).hexdigest(), 16)
        jitter = (random.Random(seed).randint(-5, 5))
        instances[ver] = {
            "health_score": max(0, min(100, score + jitter)),
            "ready": ready > 0,
        }

    return {
        "aggregate_health_score": score,
        "ready_replicas":  ready,
        "desired_replicas": desired,
        "all_ready": ready == desired,
        "scanning_mode": s["scanning_mode"],
        "instances": instances,
        "source": s["source"],
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)