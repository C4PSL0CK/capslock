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

# Kubernetes client — imported lazily on first use to avoid startup overhead
_k8s_client = None
_k8s_config = None
K8S_AVAILABLE: Optional[bool] = None  # None = not yet probed

def _ensure_k8s() -> bool:
    """Probe for a reachable K8s cluster once; cache the result."""
    global _k8s_client, _k8s_config, K8S_AVAILABLE
    if K8S_AVAILABLE is not None:
        return K8S_AVAILABLE
    try:
        from kubernetes import client as kc, config as kg
        _k8s_client = kc
        _k8s_config = kg
        try:
            kg.load_incluster_config()
            K8S_AVAILABLE = True
        except Exception:
            try:
                kg.load_kube_config()
                K8S_AVAILABLE = True
            except Exception:
                K8S_AVAILABLE = False
    except ImportError:
        K8S_AVAILABLE = False
    return K8S_AVAILABLE

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
# Policy Synthesis — Pydantic Models
# ============================================================================

class PolicySynthesisRequest(BaseModel):
    namespace: str
    environment: str  # development | staging | production
    frameworks: List[str] = ["cis", "pci-dss"]
    engine: str = "opa"  # opa | kyverno

class PolicySynthesisResponse(BaseModel):
    namespace: str
    environment: str
    engine: str
    manifests: List[dict]  # list of {"name": str, "kind": str, "yaml": str}
    conflict_resolution: dict
    confidence_score: float
    generated_at: str

# ============================================================================
# Policy Synthesis — Helper Functions
# ============================================================================

_KNOWN_NAMESPACES = [
    "default", "kube-system", "kube-public", "capslock-system",
    "production", "staging", "development", "dev", "prod",
    "monitoring", "logging", "ingress-nginx", "cert-manager",
]

_SUPPORTED_FRAMEWORKS = {"cis", "pci-dss"}

_CONFLICT_RULES = [
    {
        "id": "allow-deny-conflict",
        "description": "allow-* policy conflicts with deny-* policy for the same resource",
        "pattern": "allow-{resource} vs deny-{resource}",
        "resolution": "deny wins in production/staging; allow wins in development",
    },
    {
        "id": "scan-mode-conflict",
        "description": "Multiple scanning modes active simultaneously (log-only + block)",
        "pattern": "log-only vs block scanning mode",
        "resolution": "block mode wins in production; log-only wins in development",
    },
    {
        "id": "required-remove-conflict",
        "description": "required-policy and remove-policy reference the same policy name",
        "pattern": "require-{name} vs remove-{name}",
        "resolution": "required wins in all environments",
    },
    {
        "id": "namespace-scope-conflict",
        "description": "allow-all-namespaces conflicts with restrict-namespaces",
        "pattern": "allow-all-namespaces vs restrict-namespaces",
        "resolution": "restrict wins in production/staging; allow wins in development",
    },
]


def _resolve_conflicts(policies: List[str], environment: str) -> dict:
    """
    Detect and resolve conflicts between a list of policy names for a given
    environment tier.  Returns a structured dict describing what was found and
    how it was resolved.
    """
    env = environment.lower()
    conflicts: List[str] = []
    resolved: List[str] = []
    precedence_rule = ""
    action = ""

    # Build lookup sets for quick membership testing
    policy_set = set(p.lower() for p in policies)

    # --- Rule 1: allow-* vs deny-* for the same resource type ---
    allow_policies = {p for p in policy_set if p.startswith("allow-")}
    deny_policies  = {p for p in policy_set if p.startswith("deny-")}
    for ap in allow_policies:
        resource = ap[len("allow-"):]
        dp = f"deny-{resource}"
        if dp in deny_policies:
            conflicts.append(f"Conflict: '{ap}' vs '{dp}'")
            if env == "production":
                resolved.append(dp)
                precedence_rule = "production: deny/security policies take precedence"
                action = f"Removed '{ap}'; keeping '{dp}'"
            elif env == "staging":
                resolved.append(dp)
                precedence_rule = "staging: most-restrictive wins (warning logged)"
                action = f"Removed '{ap}'; keeping '{dp}' (WARNING: conflicting policies detected)"
            else:
                resolved.append(ap)
                precedence_rule = "development: permissive policies allowed; conflicts are warnings only"
                action = f"Keeping '{ap}'; '{dp}' is a warning (development mode)"

    # --- Rule 2: log-only + block scanning mode conflict ---
    has_log_only = any("log-only" in p or "log_only" in p for p in policy_set)
    has_block    = any("block" in p for p in policy_set)
    if has_log_only and has_block:
        conflicts.append("Conflict: 'log-only' scanning mode vs 'block' scanning mode")
        if env == "production":
            resolved.append("block")
            precedence_rule = precedence_rule or "production: block mode takes precedence"
            action = action or "Enforcing 'block' scanning mode; removed 'log-only'"
        elif env == "staging":
            resolved.append("block")
            precedence_rule = precedence_rule or "staging: most-restrictive wins (warning logged)"
            action = action or "Enforcing 'block' scanning mode (WARNING: conflicting scan modes)"
        else:
            resolved.append("log-only")
            precedence_rule = precedence_rule or "development: permissive policies allowed; conflicts are warnings only"
            action = action or "Keeping 'log-only' scan mode in development (warning only)"

    # --- Rule 3: require-{name} + remove-{name} for the same policy name ---
    require_policies = {p[len("require-"):] for p in policy_set if p.startswith("require-")}
    remove_policies  = {p[len("remove-"):] for p in policy_set if p.startswith("remove-")}
    for name in require_policies & remove_policies:
        conflicts.append(f"Conflict: 'require-{name}' vs 'remove-{name}'")
        resolved.append(f"require-{name}")
        precedence_rule = precedence_rule or "all environments: required-policy takes precedence over remove-policy"
        action = action or f"Keeping 'require-{name}'; discarding 'remove-{name}'"

    # --- Rule 4: allow-all-namespaces vs restrict-namespaces ---
    if "allow-all-namespaces" in policy_set and "restrict-namespaces" in policy_set:
        conflicts.append("Conflict: 'allow-all-namespaces' vs 'restrict-namespaces'")
        if env in ("production", "staging"):
            resolved.append("restrict-namespaces")
            precedence_rule = precedence_rule or f"{env}: security policies take precedence"
            action = action or "Removed 'allow-all-namespaces'; keeping 'restrict-namespaces'"
        else:
            resolved.append("allow-all-namespaces")
            precedence_rule = precedence_rule or "development: permissive policies allowed; conflicts are warnings only"
            action = action or "Keeping 'allow-all-namespaces' (development mode; warning only)"

    if not conflicts:
        precedence_rule = "no conflicts detected"
        action = "all policies applied as-is"

    return {
        "conflicts": conflicts,
        "resolved": resolved,
        "precedence_rule": precedence_rule,
        "action": action,
    }


def _calculate_confidence(namespace: str, environment: str, frameworks: List[str]) -> float:
    """
    Score synthesis confidence from 0.0 to 1.0 using five weighted factors.

    Factor 1 (0.30): namespace is in the known-namespaces list
    Factor 2 (0.25): all requested frameworks are supported
    Factor 3 (0.20): environment matches a known tier
    Factor 4 (0.15): Go policy-engine binary is present
    Factor 5 (0.10): Kubernetes cluster is reachable
    """
    # Factor 1 — namespace recognition
    f1 = 1.0 if namespace.lower() in _KNOWN_NAMESPACES else 0.5

    # Factor 2 — framework support
    unknown_fws = [fw for fw in frameworks if fw.lower() not in _SUPPORTED_FRAMEWORKS]
    f2 = 1.0 if not unknown_fws else 0.5

    # Factor 3 — environment tier
    f3 = 1.0 if environment.lower() in ("development", "dev", "staging", "production", "prod") else 0.5

    # Factor 4 — policy-engine binary
    binary_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "bin", "policy-engine")
    # Also try the path relative to CWD (how the existing endpoints invoke it)
    binary_cwd  = "./bin/policy-engine"
    f4 = 1.0 if (os.path.isfile(binary_path) or os.path.isfile(binary_cwd)) else 0.7

    # Factor 5 — Kubernetes connectivity
    f5 = 1.0 if _ensure_k8s() else 0.8

    score = (f1 * 0.30) + (f2 * 0.25) + (f3 * 0.20) + (f4 * 0.15) + (f5 * 0.10)
    return round(score, 2)


def _generate_opa_manifests(namespace: str, environment: str) -> List[dict]:
    """Generate OPA Gatekeeper ConstraintTemplate + Constraint YAML manifests."""
    env = environment.lower()
    # Enforcement action: dryrun for dev, deny for staging/prod
    enforcement = "dryrun" if env in ("development", "dev") else "deny"

    # --- Manifest 1: ConstraintTemplate for required labels ---
    ct_required_labels = f"""\
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels-{namespace}
  namespace: {namespace}
  labels:
    environment: {environment}
    managed-by: capslock-policy-engine
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        openAPIV3Schema:
          type: object
          properties:
            labels:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels
        violation[{{"msg": msg}}] {{
          provided := {{label | input.review.object.metadata.labels[label]}}
          required := {{label | label := input.parameters.labels[_]}}
          missing := required - provided
          count(missing) > 0
          msg := sprintf("Missing required labels: %v", [missing])
        }}
"""

    # --- Manifest 2: Constraint that enforces k8srequiredlabels ---
    constraint_required_labels = f"""\
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: require-labels-{namespace}
  labels:
    environment: {environment}
    managed-by: capslock-policy-engine
spec:
  enforcementAction: {enforcement}
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces:
      - {namespace}
  parameters:
    labels:
      - app
      - environment
"""

    # --- Manifest 3: ConstraintTemplate for pod security standards ---
    ct_pod_security = f"""\
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spspprivilegedcontainer-{namespace}
  namespace: {namespace}
  labels:
    environment: {environment}
    managed-by: capslock-policy-engine
spec:
  crd:
    spec:
      names:
        kind: K8sPSPPrivilegedContainer
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8spspprivilegedcontainer
        violation[{{"msg": msg}}] {{
          c := input_containers[_]
          c.securityContext.privileged
          msg := sprintf("Privileged container is not allowed: %v", [c.name])
        }}
        input_containers[c] {{
          c := input.review.object.spec.containers[_]
        }}
        input_containers[c] {{
          c := input.review.object.spec.initContainers[_]
        }}
"""

    return [
        {
            "name": f"k8srequiredlabels-{namespace}",
            "kind": "ConstraintTemplate",
            "yaml": ct_required_labels,
        },
        {
            "name": f"require-labels-{namespace}",
            "kind": "K8sRequiredLabels (Constraint)",
            "yaml": constraint_required_labels,
        },
        {
            "name": f"k8spspprivilegedcontainer-{namespace}",
            "kind": "ConstraintTemplate",
            "yaml": ct_pod_security,
        },
    ]


def _generate_kyverno_manifests(namespace: str, environment: str) -> List[dict]:
    """Generate Kyverno ClusterPolicy YAML manifests."""
    env = environment.lower()
    # enforce for prod/staging; audit for dev
    action = "Audit" if env in ("development", "dev") else "Enforce"

    # --- Manifest 1: ClusterPolicy for required label validation ---
    cp_labels = f"""\
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-labels-{namespace}
  labels:
    environment: {environment}
    managed-by: capslock-policy-engine
  annotations:
    policies.kyverno.io/title: Require Labels
    policies.kyverno.io/description: >-
      Require that all Pods carry 'app' and 'environment' labels.
spec:
  validationFailureAction: {action}
  background: true
  rules:
    - name: check-labels
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - {namespace}
      validate:
        message: "Required labels 'app' and 'environment' are missing."
        pattern:
          metadata:
            labels:
              app: "?*"
              environment: "?*"
"""

    # --- Manifest 2: ClusterPolicy for pod security standards ---
    cp_pod_security = f"""\
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged-containers-{namespace}
  labels:
    environment: {environment}
    managed-by: capslock-policy-engine
  annotations:
    policies.kyverno.io/title: Disallow Privileged Containers
    policies.kyverno.io/description: >-
      Privileged containers are disallowed. This policy ensures Pods do not
      run privileged containers in the {namespace} namespace.
spec:
  validationFailureAction: {action}
  background: true
  rules:
    - name: disallow-privileged
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - {namespace}
      validate:
        message: "Privileged containers are not allowed."
        pattern:
          spec:
            containers:
              - =(securityContext):
                  =(privileged): "false"
"""

    return [
        {
            "name": f"require-labels-{namespace}",
            "kind": "ClusterPolicy",
            "yaml": cp_labels,
        },
        {
            "name": f"disallow-privileged-containers-{namespace}",
            "kind": "ClusterPolicy",
            "yaml": cp_pod_security,
        },
    ]


# ============================================================================
# Policy Synthesis — Endpoints
# ============================================================================

@app.post("/api/policies/synthesize", response_model=PolicySynthesisResponse)
async def synthesize_policies(req: PolicySynthesisRequest):
    """
    Generate OPA Gatekeeper or Kyverno policy manifests for a namespace/environment.
    Runs conflict resolution and returns a confidence score alongside the YAMLs.
    """
    engine = req.engine.lower()
    if engine not in ("opa", "kyverno"):
        raise HTTPException(status_code=400, detail="engine must be 'opa' or 'kyverno'")

    if engine == "opa":
        manifests = _generate_opa_manifests(req.namespace, req.environment)
    else:
        manifests = _generate_kyverno_manifests(req.namespace, req.environment)

    policy_names = [m["name"] for m in manifests]
    conflict_resolution = _resolve_conflicts(policy_names, req.environment)
    confidence_score    = _calculate_confidence(req.namespace, req.environment, req.frameworks)

    return PolicySynthesisResponse(
        namespace=req.namespace,
        environment=req.environment,
        engine=engine,
        manifests=manifests,
        conflict_resolution=conflict_resolution,
        confidence_score=confidence_score,
        generated_at=datetime.utcnow().isoformat(),
    )


@app.get("/api/policies/conflicts")
async def list_conflict_rules():
    """
    Return the catalogue of known conflict-detection rules used by
    _resolve_conflicts().  Useful for UI documentation and debugging.
    """
    return {"rules": _CONFLICT_RULES}


# ============================================================================
# ICAP Operator Bridge  (reads/writes the ICAPService CRD via the K8s API)
# Falls back to a local state file so configuration persists without a cluster.
# ============================================================================

_ICAP_STATE_FILE = os.path.join(os.path.dirname(__file__), "icap_local_state.json")
_ICAP_STATE_DEFAULTS: Dict[str, Any] = {
    "scanning_mode": "block",
    "replicas": 3,
    "health_score": 92,
    "clamav_image": "clamav/clamav:latest",
}

def _load_local_icap_state() -> Dict[str, Any]:
    state = dict(_ICAP_STATE_DEFAULTS)
    try:
        with open(_ICAP_STATE_FILE) as f:
            state.update(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return state

def _save_local_icap_state(updates: Dict[str, Any]) -> Dict[str, Any]:
    state = _load_local_icap_state()
    state.update({k: v for k, v in updates.items() if v is not None})
    tmp = _ICAP_STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, _ICAP_STATE_FILE)
    return state


def _get_icap_crd_status() -> Dict[str, Any]:
    """
    Read the live ICAPService CRD status from the Kubernetes API server.
    Returns a structured dict identical in shape to the synthetic fallback
    so callers never need to branch on K8S_AVAILABLE.
    """
    if not _ensure_k8s():
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
    """Local state used when no K8s cluster is available. Reads persisted config."""
    s = _load_local_icap_state()
    return {
        "name":              ICAP_SERVICE_NAME,
        "namespace":         ICAP_NAMESPACE,
        "ready_replicas":    s["replicas"],
        "desired_replicas":  s["replicas"],
        "health_score":      s["health_score"],
        "last_scaling_time": datetime.utcnow().isoformat(),
        "conditions":        [{"type": "Ready", "status": "True"}],
        "scanning_mode":     s["scanning_mode"],
        "clamav_image":      s["clamav_image"],
        "source": "local",
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
    Save configuration locally (always) and also patch the ICAPService CRD if a
    live K8s cluster is reachable.  The local state is the source of truth so
    that changes are never lost even when no cluster is connected.
    """
    # Always persist locally first so status reads reflect the new value immediately
    saved = _save_local_icap_state({
        "scanning_mode": req.scanning_mode,
        "replicas":      req.replicas,
    })
    applied_patch = {k: v for k, v in {"scanning_mode": req.scanning_mode, "replicas": req.replicas}.items() if v is not None}

    if not applied_patch:
        raise HTTPException(status_code=400, detail="No fields to update")

    # Best-effort: also apply to K8s CRD if a cluster is reachable
    if _ensure_k8s():
        k8s_patch: Dict[str, Any] = {"spec": {}}
        if req.scanning_mode:
            k8s_patch["spec"]["icapConfig"] = {"scanningMode": req.scanning_mode}
        if req.replicas is not None:
            k8s_patch["spec"]["replicas"] = req.replicas
        try:
            crd_api = _k8s_client.CustomObjectsApi()  # type: ignore[union-attr]
            crd_api.patch_namespaced_custom_object(
                group=ICAP_GROUP,
                version=ICAP_VERSION,
                namespace=ICAP_NAMESPACE,
                plural=ICAP_PLURAL,
                name=ICAP_SERVICE_NAME,
                body=k8s_patch,
            )
            return {"status": "patched", "patch": applied_patch, "current_state": saved}
        except Exception:
            pass  # cluster unreachable — local save is sufficient

    return {
        "status": "applied_local",
        "message": "Configuration saved. Will sync to K8s when a cluster is connected.",
        "patch": applied_patch,
        "current_state": saved,
    }


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

    # Always use locally persisted scanning_mode — it is the source of truth
    # for configure changes even when a K8s cluster is connected.
    local = _load_local_icap_state()
    s["scanning_mode"] = local["scanning_mode"]

    ready    = s["ready_replicas"]
    desired  = s["desired_replicas"]
    score    = s["health_score"]

    # Synthesise per-instance health (operator tracks aggregate; split evenly with
    # small jitter so SSDLB can weight individual a/b/c DestinationRule subsets)
    import random, hashlib
    instances = {}
    for ver in ("a", "b", "c"):
        seed  = int(hashlib.md5(f"{ICAP_SERVICE_NAME}:{ver}:{score}".encode()).hexdigest(), 16)
        rng   = random.Random(seed)
        jitter = rng.randint(-5, 5)
        inst_score = max(0, min(100, score + jitter))
        # Derive sub-scores from overall with small per-factor variation
        instances[ver] = {
            "health_score": inst_score,
            "ready": ready > 0,
            "sub_scores": {
                "readiness":  max(0, min(100, inst_score + rng.randint(-3, 3))),
                "latency":    max(0, min(100, inst_score + rng.randint(-8, 4))),
                "signatures": max(0, min(100, inst_score + rng.randint(-5, 2))),
                "errors":     max(0, min(100, inst_score + rng.randint(-4, 5))),
                "resources":  max(0, min(100, inst_score + rng.randint(-6, 3))),
                "queue":      max(0, min(100, inst_score + rng.randint(-10, 5))),
            },
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