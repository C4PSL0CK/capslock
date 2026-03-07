from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from typing import Dict, List, Optional, Any
import uuid
import time
import os
import json
import httpx

from pydantic import BaseModel
from meds.models.promotion import Promotion, Environment, ApplicationRef, PolicyMigration, PromotionSpec
from meds.models.requests import CreatePromotionRequest, RollbackRequest
from meds.controllers.promotion_controller import PromotionController
from meds.policy.standards import POLICY_CATALOG, get_policies_for_environment
from meds.validation.risk_scorer import RiskScorer
from meds.audit.log import AuditLogger, load_promotions, save_promotions
from meds.policy.version_store import PolicyVersionStore
from meds.monitoring import metrics
from meds.utils.logger import setup_logging, get_logger
from prometheus_client import CONTENT_TYPE_LATEST

POLICY_ENGINE_URL = os.getenv("POLICY_ENGINE_URL", "").rstrip("/")
SSDLB_URL = os.getenv("SSDLB_URL", "http://localhost:8082").rstrip("/")

# Setup logging
setup_logging()
logger = get_logger("meds.api")

app = FastAPI(title="MEDS API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

promotions_db: Dict[str, Promotion] = {}
pending_approvals_db: Dict[str, str] = {}  # promotion_id → promotion_id (set of pending)
environments_db: Dict[str, Environment] = {}

# Initialize environments
environments_db["development"] = Environment(
    name="development", type="development", max_risk_score=80,
    policies=get_policies_for_environment("development"),
    cluster="dev-cluster", policy_mode="enforce", approval_threshold=0.75,
)
environments_db["staging"] = Environment(
    name="staging", type="staging", max_risk_score=60,
    policies=get_policies_for_environment("staging"),
    cluster="staging-cluster", policy_mode="audit", approval_threshold=0.75,
)
environments_db["production"] = Environment(
    name="production", type="production", max_risk_score=40,
    policies=get_policies_for_environment("production"),
    cluster="prod-cluster", policy_mode="enforce", approval_threshold=0.75,
)

# Set environment thresholds in metrics
for env_name, env in environments_db.items():
    metrics.set_environment_threshold(env_name, env.max_risk_score)

# Shared dependencies
audit_logger = AuditLogger()
version_store = PolicyVersionStore()
controller = PromotionController(audit_logger=audit_logger, version_store=version_store)

# Load persisted promotions
_raw = load_promotions()
for pid, pdata in _raw.items():
    try:
        promotions_db[pid] = Promotion(**pdata)
    except Exception:
        pass

logger.info("meds_api_started", environments=list(environments_db.keys()), loaded_promotions=len(promotions_db))


@app.get("/")
async def root():
    try:
        with open("static/index.html", "r") as f:
            return HTMLResponse(content=f.read())
    except Exception:
        return {"message": "MEDS API running. Visit /docs for API documentation"}


@app.get("/metrics")
async def get_metrics():
    """Prometheus metrics endpoint"""
    return Response(content=metrics.get_metrics(), media_type=CONTENT_TYPE_LATEST)


@app.get("/api/system/status")
async def system_status():
    """Live health check across all 4 CAPSLOCK components."""
    components: Dict[str, Any] = {
        "meds": {
            "name": "MEDS", "port": 8000, "status": "ok",
            "description": "Multi-Environment Deployment System",
            "promotions": len(promotions_db),
        },
        "policy_engine": {
            "name": "Policy Engine", "port": 8001, "status": "unknown",
            "description": "Compliance & policy enforcement",
        },
        "ssdlb": {
            "name": "SSDLB", "port": 8082, "status": "unknown",
            "description": "Smart health-aware load balancer",
        },
        "icap_operator": {
            "name": "ICAP Operator", "port": 1344, "status": "unknown",
            "description": "ClamAV content-security scanning",
        },
    }
    async with httpx.AsyncClient() as client:
        if POLICY_ENGINE_URL:
            try:
                await client.get(f"{POLICY_ENGINE_URL}/", timeout=2.0)
                components["policy_engine"]["status"] = "ok"
            except Exception:
                components["policy_engine"]["status"] = "offline"
            try:
                r = await client.get(f"{POLICY_ENGINE_URL}/api/icap/health", timeout=2.0)
                data = r.json()
                components["icap_operator"]["status"] = "ok"
                components["icap_operator"]["health_score"] = data.get("aggregate_health_score", 0)
                components["icap_operator"]["scanning_mode"] = data.get("scanning_mode", "block")
                components["icap_operator"]["ready_replicas"] = data.get("ready_replicas", 0)
            except Exception:
                components["icap_operator"]["status"] = "offline"
        else:
            components["policy_engine"]["status"] = "offline"
            components["icap_operator"]["status"] = "offline"
        if SSDLB_URL:
            try:
                r = await client.get(f"{SSDLB_URL}/state", timeout=2.0)
                state = r.json()
                components["ssdlb"]["status"] = "ok"
                components["ssdlb"]["mode"] = state.get("mode", "single")
                components["ssdlb"]["selected"] = state.get("last_selected", "a")
            except Exception:
                components["ssdlb"]["status"] = "offline"
    return components


# ---------------------------------------------------------------------------
# Demo seed data — injected on first startup when promotions_db is empty
# ---------------------------------------------------------------------------

_DEMO_PROMOTIONS = [
    {
        "name": "payment-service-v2.3.1",
        "application_name": "payment-service",
        "application_namespace": "payments",
        "source_environment": "development",
        "target_environment": "staging",
        "version": "v2.3.1",
        "add_policies": [],
        "remove_policies": [],
    },
    {
        "name": "auth-service-v1.5.2",
        "application_name": "auth-service",
        "application_namespace": "auth",
        "source_environment": "staging",
        "target_environment": "production",
        "version": "v1.5.2",
        "add_policies": [],
        "remove_policies": [],
    },
    {
        "name": "api-gateway-v2.0.0",
        "application_name": "api-gateway",
        "application_namespace": "platform",
        "source_environment": "development",
        "target_environment": "staging",
        "version": "v2.0.0",
        "add_policies": ["network-policy", "resource-limits"],
        "remove_policies": [],
    },
    {
        "name": "data-pipeline-v1.4.0",
        "application_name": "data-pipeline",
        "application_namespace": "analytics",
        "source_environment": "staging",
        "target_environment": "production",
        "version": "v1.4.0",
        "add_policies": [],
        "remove_policies": [],
    },
    {
        "name": "ml-inference-v3.0.0-alpha",
        "application_name": "ml-inference",
        "application_namespace": "mlops",
        "source_environment": "staging",
        "target_environment": "production",
        "version": "v3.0.0-alpha",
        "add_policies": [],
        "remove_policies": [],
    },
    {
        "name": "notification-svc-v1.2.3",
        "application_name": "notification-svc",
        "application_namespace": "messaging",
        "source_environment": "development",
        "target_environment": "staging",
        "version": "v1.2.3",
        "add_policies": [],
        "remove_policies": [],
    },
]


@app.on_event("startup")
async def seed_demo_data():
    """Auto-seed realistic demo data on first startup if the DB is empty."""
    if len(promotions_db) > 0:
        return
    logger.info("seeding_demo_data", count=len(_DEMO_PROMOTIONS))
    for demo in _DEMO_PROMOTIONS:
        try:
            promotion_id = str(uuid.uuid4())[:8]
            promotion = Promotion(
                metadata={"name": demo["name"], "id": promotion_id},
                spec=PromotionSpec(
                    application=ApplicationRef(
                        name=demo["application_name"],
                        namespace=demo["application_namespace"],
                    ),
                    source_environment=demo["source_environment"],
                    target_environment=demo["target_environment"],
                    version=demo["version"],
                    policy_migration=PolicyMigration(
                        add_policies=demo["add_policies"],
                        remove_policies=demo["remove_policies"],
                    ),
                ),
            )
            controller.process_promotion(
                promotion,
                environments_db[demo["source_environment"]],
                environments_db[demo["target_environment"]],
            )
            promotions_db[promotion_id] = promotion
            if promotion.status.decision == "PENDING_APPROVAL":
                pending_approvals_db[promotion_id] = promotion_id
        except Exception as exc:
            logger.warning("seed_promotion_failed", name=demo["name"], error=str(exc))
    save_promotions(promotions_db)
    logger.info("demo_data_seeded", count=len(promotions_db))


@app.get("/api/policies")
async def get_policies():
    start_time = time.time()
    policies = []
    for name, policy in POLICY_CATALOG.items():
        policies.append({
            "name": policy.name,
            "description": policy.description,
            "category": policy.category,
            "severity": policy.severity,
            "required_for": policy.required_for,
            "compliance": {f.value: c for f, c in policy.compliance_mappings.items()}
        })

    duration = time.time() - start_time
    metrics.api_request_duration.labels(method="GET", endpoint="/api/policies", status_code=200).observe(duration)
    logger.info("policies_retrieved", count=len(policies), duration=duration)
    return policies


@app.get("/api/environments")
async def get_environments():
    start_time = time.time()
    result = list(environments_db.values())
    duration = time.time() - start_time
    metrics.api_request_duration.labels(method="GET", endpoint="/api/environments", status_code=200).observe(duration)
    return result


@app.post("/api/promotions")
async def create_promotion(request: CreatePromotionRequest):
    start_time = time.time()

    logger.info("promotion_request_received",
                name=request.name,
                source=request.source_environment,
                target=request.target_environment,
                version=request.version)

    if request.source_environment not in environments_db:
        raise HTTPException(status_code=400, detail="Source environment not found")
    if request.target_environment not in environments_db:
        raise HTTPException(status_code=400, detail="Target environment not found")

    promotion_id = str(uuid.uuid4())[:8]

    promotion = Promotion(
        metadata={"name": request.name, "id": promotion_id},
        spec=PromotionSpec(
            application=ApplicationRef(name=request.application_name, namespace=request.application_namespace),
            source_environment=request.source_environment,
            target_environment=request.target_environment,
            version=request.version,
            policy_migration=PolicyMigration(add_policies=request.add_policies, remove_policies=request.remove_policies)
        )
    )

    policy_eval_start = time.time()
    result = controller.process_promotion(
        promotion,
        environments_db[request.source_environment],
        environments_db[request.target_environment]
    )
    policy_eval_duration = time.time() - policy_eval_start

    promotions_db[promotion_id] = promotion
    if promotion.status.decision == "PENDING_APPROVAL":
        pending_approvals_db[promotion_id] = promotion_id
    save_promotions(promotions_db)

    # Record metrics (risk_assessment is None when ICAP rejects)
    risk_score = result["risk_assessment"]["total_score"] if result["risk_assessment"] else 0
    metrics.record_promotion_request(request.target_environment, result["decision"])
    metrics.record_promotion_decision(result["decision"], request.source_environment, request.target_environment)
    metrics.record_risk_score(risk_score, request.target_environment)
    metrics.record_policy_evaluation_time(policy_eval_duration, len(request.add_policies))
    metrics.set_active_promotions(len(promotions_db))

    for policy in request.add_policies:
        metrics.record_policy_change("add", policy)

    duration = time.time() - start_time
    metrics.api_request_duration.labels(method="POST", endpoint="/api/promotions", status_code=200).observe(duration)

    logger.info("promotion_processed",
                promotion_id=promotion_id,
                decision=result["decision"],
                risk_score=risk_score,
                duration=duration)

    return {
        "id": promotion_id,
        "name": request.name,
        "decision": result["decision"],
        "risk_score": risk_score,
        "max_allowed": result["risk_assessment"]["max_allowed"] if result["risk_assessment"] else None,
        "message": result["message"],
        "risk_assessment": result["risk_assessment"],
        "policy_plan": result["policy_plan"],
        "icap_scan": result["icap_scan"],
    }


@app.get("/api/promotions")
async def get_promotions():
    start_time = time.time()
    result = [
        {
            "id":           p.metadata["id"],
            "name":         p.metadata["name"],
            "application":  p.spec.application.name,
            "source":       p.spec.source_environment,
            "target":       p.spec.target_environment,
            "version":      p.spec.version,
            "decision":     p.status.decision,
            "risk_score":   p.status.risk_score,
            "phase":        p.status.phase,
            "policy_mode":  p.status.policy_mode,
            "cluster":      environments_db.get(p.spec.target_environment, Environment(name="", type="", max_risk_score=0, policies=[])).cluster,
            "gitops":       p.status.gitops.model_dump() if p.status.gitops else None,
            "approval_required": p.status.approval_required,
        }
        for p in promotions_db.values()
    ]
    duration = time.time() - start_time
    metrics.api_request_duration.labels(method="GET", endpoint="/api/promotions", status_code=200).observe(duration)
    return result


@app.get("/api/analytics")
async def get_analytics():
    start_time = time.time()
    total = len(promotions_db)
    approved = sum(1 for p in promotions_db.values() if p.status.decision == "APPROVED")
    avg_risk = sum(p.status.risk_score or 0 for p in promotions_db.values()) / total if total > 0 else 0

    result = {
        "total_promotions": total,
        "approved": approved,
        "rejected": total - approved,
        "average_risk_score": round(avg_risk, 1)
    }
    duration = time.time() - start_time
    metrics.api_request_duration.labels(method="GET", endpoint="/api/analytics", status_code=200).observe(duration)
    return result


@app.get("/api/audit")
async def get_audit(limit: int = 100, event_type: Optional[str] = None):
    events = audit_logger.get_events(limit=limit, event_type=event_type)
    return [e.model_dump() for e in events]


@app.get("/api/environments/{name}/versions")
async def get_environment_versions(name: str):
    if name not in environments_db:
        raise HTTPException(status_code=404, detail="Environment not found")
    versions = version_store.get_versions(name)
    return [v.model_dump() for v in versions]


@app.post("/api/environments/{name}/rollback")
async def rollback_environment(name: str, body: RollbackRequest):
    if name not in environments_db:
        raise HTTPException(status_code=404, detail="Environment not found")
    try:
        rolled_back = version_store.rollback(name, body.version_id, environments_db)
        audit_logger.log(
            "policy_rollback",
            details={"version_id": body.version_id},
            environment=name,
        )
        return rolled_back.model_dump()
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))



@app.get("/api/approvals")
async def list_pending_approvals():
    """List all promotions awaiting human approval."""
    pending = []
    for pid in list(pending_approvals_db.keys()):
        p = promotions_db.get(pid)
        if p and p.status.decision == "PENDING_APPROVAL":
            pending.append({
                "id":          p.metadata["id"],
                "name":        p.metadata["name"],
                "application": p.spec.application.name,
                "source":      p.spec.source_environment,
                "target":      p.spec.target_environment,
                "version":     p.spec.version,
                "risk_score":  p.status.risk_score,
                "message":     p.status.message,
            })
    return pending


@app.post("/api/approvals/{promotion_id}/approve")
async def approve_promotion(promotion_id: str, body: dict = {}):
    """Human approves a PENDING_APPROVAL promotion — triggers GitOps deploy."""
    p = promotions_db.get(promotion_id)
    if not p:
        raise HTTPException(status_code=404, detail="Promotion not found")
    if p.status.decision != "PENDING_APPROVAL":
        raise HTTPException(status_code=400, detail=f"Promotion is not pending approval (current: {p.status.decision})")
    approved_by = body.get("approved_by", "operator")
    target_env  = environments_db.get(p.spec.target_environment)
    if not target_env:
        raise HTTPException(status_code=400, detail="Target environment not found")
    gitops_result = controller.complete_approval(p, target_env, approved_by=approved_by)
    pending_approvals_db.pop(promotion_id, None)
    save_promotions(promotions_db)
    return {"status": "approved", "promotion_id": promotion_id, "gitops": gitops_result}


@app.post("/api/approvals/{promotion_id}/reject")
async def reject_promotion(promotion_id: str, body: dict = {}):
    """Human rejects a PENDING_APPROVAL promotion."""
    p = promotions_db.get(promotion_id)
    if not p:
        raise HTTPException(status_code=404, detail="Promotion not found")
    if p.status.decision != "PENDING_APPROVAL":
        raise HTTPException(status_code=400, detail=f"Promotion is not pending approval (current: {p.status.decision})")
    reason = body.get("reason", "Rejected by operator")
    p.status.phase    = "FAILED"
    p.status.decision = "REJECTED"
    p.status.message  = f"REJECTED — {reason}"
    pending_approvals_db.pop(promotion_id, None)
    audit_logger.log(
        "promotion_rejected",
        details={"reason": reason, "rejected_by": body.get("approved_by", "operator")},
        promotion_id=promotion_id,
        environment=p.spec.target_environment,
        actor=body.get("approved_by", "operator"),
    )
    save_promotions(promotions_db)
    return {"status": "rejected", "promotion_id": promotion_id}


@app.post("/api/promotions/{promotion_id}/rollback")
async def trigger_rollback(promotion_id: str, body: dict = {}):
    """Trigger an automated rollback for a promotion (SLO violation or manual)."""
    p = promotions_db.get(promotion_id)
    if not p:
        raise HTTPException(status_code=404, detail="Promotion not found")
    version_id = body.get("version_id") or p.status.rollback_version_id
    if not version_id:
        raise HTTPException(status_code=400, detail="No rollback version available")
    target_env = environments_db.get(p.spec.target_environment)
    if not target_env:
        raise HTTPException(status_code=400, detail="Target environment not found")
    reason = body.get("reason", "manual")
    actor  = body.get("actor", "operator")
    result = controller.execute_rollback(p, target_env, version_id, reason=reason, actor=actor)
    # Also revert the policy version in the store
    try:
        version_store.rollback(p.spec.target_environment, version_id, environments_db)
        audit_logger.log(
            "policy_rollback",
            details={"version_id": version_id, "reason": reason},
            environment=p.spec.target_environment,
            actor=actor,
        )
    except ValueError:
        pass
    save_promotions(promotions_db)
    return {"status": "rolled_back", "promotion_id": promotion_id, "gitops": result}


@app.get("/api/clusters")
async def get_clusters():
    """Return logical cluster status for each environment."""
    clusters = {}
    for env in environments_db.values():
        c = env.cluster
        if c not in clusters:
            clusters[c] = {
                "cluster":      c,
                "environments": [],
                "promotions":   0,
                "status":       "healthy",
            }
        clusters[c]["environments"].append(env.name)
        clusters[c]["promotions"] += sum(
            1 for p in promotions_db.values()
            if p.spec.target_environment == env.name and p.status.decision == "APPROVED"
        )
    return list(clusters.values())


@app.get("/api/audit/verify")
async def verify_audit_chain():
    """Verify the SHA-256 hash chain integrity of the immutable audit log."""
    return audit_logger.verify_chain()


@app.get("/api/icap/status")
async def get_icap_status():
    """Proxy: ICAP operator full CRD status (from policy-engine)."""
    if not POLICY_ENGINE_URL:
        return {"source": "synthetic", "error": "POLICY_ENGINE_URL not set",
                "name": "capslock-icap", "namespace": "capslock-system",
                "ready_replicas": 3, "desired_replicas": 3, "health_score": 92,
                "scanning_mode": "block", "clamav_image": "clamav/clamav:latest",
                "conditions": [{"type": "Ready", "status": "True"}]}
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            r = await client.get(f"{POLICY_ENGINE_URL}/api/icap/operator/status")
            return r.json()
        except Exception as exc:
            raise HTTPException(status_code=503, detail=str(exc))


@app.get("/api/icap/health")
async def get_icap_health():
    """Proxy: compact ICAP health summary used by SSDLB and the dashboard."""
    if not POLICY_ENGINE_URL:
        return {"aggregate_health_score": 92, "ready_replicas": 3, "desired_replicas": 3,
                "all_ready": True, "scanning_mode": "block", "source": "synthetic",
                "instances": {"a": {"health_score": 94, "ready": True},
                              "b": {"health_score": 91, "ready": True},
                              "c": {"health_score": 90, "ready": True}}}
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            r = await client.get(f"{POLICY_ENGINE_URL}/api/icap/health")
            return r.json()
        except Exception as exc:
            raise HTTPException(status_code=503, detail=str(exc))


@app.post("/api/icap/configure")
async def configure_icap(body: Dict[str, Any]):
    """Proxy: patch the ICAPService CRD spec via the policy-engine bridge."""
    if not POLICY_ENGINE_URL:
        return {"status": "accepted_synthetic",
                "message": "POLICY_ENGINE_URL not set — change not forwarded",
                **body}
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            r = await client.post(
                f"{POLICY_ENGINE_URL}/api/icap/operator/configure", json=body
            )
            return r.json()
        except Exception as exc:
            raise HTTPException(status_code=503, detail=str(exc))


# ---------------------------------------------------------------------------
# Validation / Demo endpoints (PP2)
# ---------------------------------------------------------------------------

@app.post("/api/demo/risk-score")
async def demo_risk_score(body: Dict[str, Any]):
    """Compute a risk score interactively from the Validation tab."""
    scorer = RiskScorer()
    add_policies    = ["p"] * int(body.get("add_policies", 0))
    remove_policies = ["p"] * int(body.get("remove_policies", 0))
    return scorer.calculate_risk_score(
        version             = body.get("version", "v1.0.0"),
        source_environment  = body.get("source_env", "development"),
        target_environment  = body.get("target_env", "staging"),
        add_policies        = add_policies,
        remove_policies     = remove_policies,
        max_allowed_score   = int(body.get("max_allowed_score", 60)),
        icap_coverage_score = body.get("icap_coverage_score"),
        compliance_score    = body.get("compliance_score"),
    )


@app.post("/api/demo/conflicts")
async def demo_conflicts(body: Dict[str, Any]):
    """Detect policy conflicts and optionally resolve between two policies."""
    def _detect(p: dict):
        conflicts = []
        mode     = p.get("enforcement_mode", "permissive")
        risk     = p.get("risk_level", "low")
        stds     = p.get("compliance_standards", [])
        pss      = p.get("pod_security_standard", "baseline")
        network  = p.get("require_network_policies", False)
        limits   = p.get("require_resource_limits", True)
        env      = p.get("target_environment", "development")
        name     = p.get("name", "policy")

        if mode == "strict" and risk == "high":
            conflicts.append({"type": "enforcement", "severity": "MEDIUM",
                "description": "Strict enforcement with high risk may cause service disruptions",
                "remediation": "Use 'audit' mode first or lower the risk level"})
        if "pci-dss" in stds and pss != "restricted":
            conflicts.append({"type": "compliance", "severity": "HIGH",
                "description": "PCI-DSS requires 'restricted' Pod Security Standard",
                "remediation": "Set pod_security_standard to 'restricted'"})
        if any(s in stds for s in ["cis", "pci-dss"]) and not network:
            conflicts.append({"type": "compliance", "severity": "HIGH",
                "description": "CIS / PCI-DSS require network policies to be enabled",
                "remediation": "Enable require_network_policies"})
        if not limits and env == "production":
            conflicts.append({"type": "configuration", "severity": "MEDIUM",
                "description": "Production environment should enforce resource limits",
                "remediation": "Enable require_resource_limits"})
        return conflicts

    def _compliance_score(p: dict) -> float:
        stds = p.get("compliance_standards", [])
        score = len(stds) * 10.0
        if "pci-dss" in stds: score += 20.0
        if "cis"     in stds: score += 15.0
        if p.get("pod_security_standard") == "restricted": score += 10.0
        if p.get("require_network_policies"):               score += 5.0
        if p.get("require_resource_limits", True):          score += 5.0
        return score

    conflicts = _detect(body)
    result: Dict[str, Any] = {"conflicts": conflicts, "count": len(conflicts)}

    # If a second policy is provided, also run resolution
    p2 = body.get("policy2")
    if p2:
        s1, s2 = _compliance_score(body), _compliance_score(p2)
        if s1 > s2:
            result["resolution"] = {"winner": body.get("name", "Policy 1"),
                                    "reason": f"Better compliance coverage ({s1:.0f} vs {s2:.0f})"}
        elif s2 > s1:
            result["resolution"] = {"winner": p2.get("name", "Policy 2"),
                                    "reason": f"Better compliance coverage ({s2:.0f} vs {s1:.0f})"}
        else:
            risk_order = {"low": 1, "medium": 2, "high": 3}
            r1 = risk_order.get(body.get("risk_level", "medium"), 2)
            r2 = risk_order.get(p2.get("risk_level",  "medium"), 2)
            if r1 <= r2:
                result["resolution"] = {"winner": body.get("name", "Policy 1"),
                                        "reason": f"Equal compliance, lower risk ({body.get('risk_level')})"}
            else:
                result["resolution"] = {"winner": p2.get("name", "Policy 2"),
                                        "reason": f"Equal compliance, lower risk ({p2.get('risk_level')})"}
    return result


@app.get("/api/demo/health-scenarios")
async def demo_health_scenarios():
    """Return pre-computed ICAP health score scenarios for the Validation tab."""
    import math

    def _readiness(ready, desired, unavail):
        if desired == 0: return 0.0
        s = (ready / desired) * 100
        if unavail > 0: s -= (unavail / desired) * 20
        return max(0.0, s)

    def _latency(threshold, traffic="normal"):
        base = {"500ms": 100, "1s": 90, "2s": 70}.get(threshold, 50)
        adj  = {"spike": -15, "high": -10, "low": +5, "normal": 0}.get(traffic, 0)
        return max(0.0, min(100.0, base + adj))

    def _sigs(age_h):
        if age_h < 6:  return 100.0
        if age_h < 12: return 90.0
        if age_h < 24: return 75.0
        if age_h < 48: return 50.0
        return 25.0

    def _errors(traffic="normal", res="healthy"):
        rate = 0.02
        rate += {"spike": 0.03, "high": 0.01}.get(traffic, 0)
        rate += {"critical": 0.05, "constrained": 0.02}.get(res, 0)
        return max(0.0, min(100.0, (1 - rate) * 100))

    def _resources(ready, desired, unavail):
        if ready == desired and unavail == 0: return 95.0
        if unavail > 0: return 60.0
        return 80.0

    def _queue(replicas, traffic="normal"):
        q = {"spike": replicas*50, "high": replicas*20, "normal": replicas*5, "low": replicas}.get(traffic, replicas*5)
        mq = replicas * 30
        if q <= mq: return 100.0
        return max(0.0, 100.0 - ((q - mq) / mq * 100.0))

    W = {"readiness": 0.25, "latency": 0.25, "signatures": 0.20, "errors": 0.15, "resources": 0.10, "queue": 0.05}

    def _overall(r, l, s, e, res, q):
        return round(r*W["readiness"] + l*W["latency"] + s*W["signatures"] + e*W["errors"] + res*W["resources"] + q*W["queue"], 1)

    scenarios = [
        {"name": "Fully healthy", "description": "All replicas up, fresh signatures, normal traffic",
         "ready": 3, "desired": 3, "unavail": 0, "latency": "500ms", "sig_age_h": 2, "traffic": "normal", "res": "healthy"},
        {"name": "Traffic spike", "description": "Sudden traffic surge on all instances",
         "ready": 3, "desired": 3, "unavail": 0, "latency": "500ms", "sig_age_h": 2, "traffic": "spike", "res": "healthy"},
        {"name": "One replica down", "description": "1 of 3 replicas unavailable",
         "ready": 2, "desired": 3, "unavail": 1, "latency": "1s", "sig_age_h": 8, "traffic": "normal", "res": "constrained"},
        {"name": "Stale signatures (48h)", "description": "ClamAV signatures not updated for 2 days",
         "ready": 3, "desired": 3, "unavail": 0, "latency": "500ms", "sig_age_h": 50, "traffic": "normal", "res": "healthy"},
        {"name": "High load + tight threshold", "description": "High traffic with aggressive latency threshold",
         "ready": 3, "desired": 3, "unavail": 0, "latency": "500ms", "sig_age_h": 8, "traffic": "high", "res": "healthy"},
        {"name": "Degraded (spike + stale + constrained)", "description": "Multiple stress factors simultaneously",
         "ready": 1, "desired": 3, "unavail": 1, "latency": "1s", "sig_age_h": 25, "traffic": "high", "res": "constrained"},
        {"name": "Total outage", "description": "All replicas unavailable",
         "ready": 0, "desired": 3, "unavail": 3, "latency": "500ms", "sig_age_h": 2, "traffic": "normal", "res": "critical"},
    ]

    results = []
    for s in scenarios:
        r   = _readiness(s["ready"], s["desired"], s["unavail"])
        l   = _latency(s["latency"], s["traffic"])
        sig = _sigs(s["sig_age_h"])
        e   = _errors(s["traffic"], s["res"])
        res = _resources(s["ready"], s["desired"], s["unavail"])
        q   = _queue(s["desired"], s["traffic"])
        overall = _overall(r, l, sig, e, res, q)
        results.append({
            "name": s["name"], "description": s["description"],
            "scores": {"readiness": round(r,1), "latency": round(l,1), "signatures": round(sig,1),
                       "errors": round(e,1), "resources": round(res,1), "queue": round(q,1)},
            "overall": overall,
        })
    return results


@app.get("/api/demo/traffic-scenarios")
async def demo_traffic_scenarios():
    """Return the 8 SSDLB routing scenarios for the Validation tab."""
    SPREAD_THRESHOLD = 70
    HEALTHY_FLOOR    = 60
    ENTER_RATIO      = 0.08
    EXIT_RATIO       = 0.03
    MIN_CHANGE       = 0.20
    COOLDOWN_S       = 60

    def _weighted_rates(rates, health):
        out = {}
        for v, rate in rates.items():
            score = health.get(v, 100)
            if score < HEALTHY_FLOOR:
                penalty = 3.0 * (HEALTHY_FLOOR - score) / HEALTHY_FLOOR
                out[v] = rate * (1.0 + penalty)
            else:
                out[v] = rate
        return out

    def _decide(s):
        rates, health, agg = s["rates"], s["icap_health"], s["icap_aggregate"]
        short, medium = s["short_rate"], s["medium_rate"]
        mode, selected = s["mode"], s["selected"]
        since_switch = s["seconds_since_switch"]

        if since_switch < COOLDOWN_S:
            return {"decision": "no_change", "mode": mode, "selected": selected,
                    "reason": f"Cooldown active ({since_switch}s elapsed, need {COOLDOWN_S}s)", "event": "guardrail_cooldown"}

        if agg < SPREAD_THRESHOLD:
            return {"decision": "force_spread", "mode": "spread", "selected": "all",
                    "reason": f"Aggregate ICAP health {agg} below threshold {SPREAD_THRESHOLD}",
                    "event": "icap_health_forced_spread"}

        if mode == "spread":
            if medium == 0:
                return {"decision": "no_change", "mode": "spread", "selected": "all",
                        "reason": "No traffic data available", "event": "spread_continue"}
            growth = (short - medium) / medium
            if growth <= EXIT_RATIO:
                wr = _weighted_rates(rates, {v: health[v] for v in rates})
                best = min(wr, key=wr.get)
                return {"decision": "collapse_to_single", "mode": "single", "selected": best,
                        "reason": f"Growth {growth:+.1%} <= exit threshold {EXIT_RATIO:.0%}",
                        "event": "recovered_to_single"}
            return {"decision": "no_change", "mode": "spread", "selected": "all",
                    "reason": f"Growth {growth:+.1%} > exit threshold {EXIT_RATIO:.0%}", "event": "spread_continue"}

        if medium > 0:
            growth = (short - medium) / medium
            if growth >= ENTER_RATIO:
                return {"decision": "enter_spread", "mode": "spread", "selected": "all",
                        "reason": f"Traffic growth {growth:+.1%} >= entry threshold {ENTER_RATIO:.0%}",
                        "event": "predictive_spread_entered"}

        wr = _weighted_rates(rates, {v: health[v] for v in rates})
        best = min(wr, key=wr.get)
        if best != selected:
            curr_load = wr.get(selected, 0)
            best_load = wr.get(best, 0)
            if curr_load > 0:
                improvement = (curr_load - best_load) / curr_load
                if improvement < MIN_CHANGE:
                    return {"decision": "no_change", "mode": "single", "selected": selected,
                            "reason": f"Improvement {improvement:.0%} < min threshold {MIN_CHANGE:.0%}",
                            "event": "no_switch_min_change"}
        return {"decision": "route" if best != selected else "no_change",
                "mode": "single", "selected": best,
                "reason": f"Lowest effective load: {', '.join(f'{v}={wr[v]:.1f}' for v in sorted(wr))}",
                "event": "ok"}

    scenarios = [
        {"id": 1, "name": "Healthy baseline", "description": "All versions healthy, balanced load",
         "rates": {"a":10,"b":10,"c":10}, "short_rate":30,"medium_rate":30,
         "icap_health":{"a":94,"b":91,"c":90}, "icap_aggregate":92, "mode":"single","selected":"a","seconds_since_switch":120},
        {"id": 2, "name": "Version A overloaded", "description": "Version A has 3x the traffic of B and C",
         "rates": {"a":30,"b":10,"c":10}, "short_rate":50,"medium_rate":50,
         "icap_health":{"a":91,"b":92,"c":90}, "icap_aggregate":91, "mode":"single","selected":"a","seconds_since_switch":120},
        {"id": 3, "name": "Traffic spike detected", "description": "1-minute rate 25% above 5-minute average",
         "rates": {"a":12.5,"b":12.5,"c":12.5}, "short_rate":37.5,"medium_rate":30,
         "icap_health":{"a":92,"b":91,"c":90}, "icap_aggregate":91, "mode":"single","selected":"b","seconds_since_switch":120},
        {"id": 4, "name": "ICAP penalty on version A", "description": "Version A ICAP health below floor (60) — effective load inflated",
         "rates": {"a":10,"b":10.5,"c":11}, "short_rate":31.5,"medium_rate":31.5,
         "icap_health":{"a":45,"b":91,"c":90}, "icap_aggregate":75, "mode":"single","selected":"a","seconds_since_switch":120},
        {"id": 5, "name": "Critical aggregate ICAP health", "description": "All instances degraded — aggregate below spread threshold",
         "rates": {"a":10,"b":10,"c":10}, "short_rate":30,"medium_rate":30,
         "icap_health":{"a":55,"b":60,"c":58}, "icap_aggregate":58, "mode":"single","selected":"b","seconds_since_switch":120},
        {"id": 6, "name": "Cooldown active", "description": "Recent switch 30s ago — routing locked for 60s",
         "rates": {"a":5,"b":20,"c":5}, "short_rate":30,"medium_rate":30,
         "icap_health":{"a":92,"b":91,"c":90}, "icap_aggregate":91, "mode":"single","selected":"a","seconds_since_switch":30},
        {"id": 7, "name": "Recovery from spread", "description": "Traffic stabilised — 1% growth below 3% exit threshold",
         "rates": {"a":10,"b":10.2,"c":9.8}, "short_rate":30.3,"medium_rate":30,
         "icap_health":{"a":92,"b":91,"c":90}, "icap_aggregate":91, "mode":"spread","selected":"all","seconds_since_switch":180},
        {"id": 8, "name": "Marginal improvement blocked", "description": "Best version only 9% better — below 20% min-change threshold",
         "rates": {"a":10,"b":9.1,"c":10.5}, "short_rate":29.6,"medium_rate":29.6,
         "icap_health":{"a":91,"b":92,"c":90}, "icap_aggregate":91, "mode":"single","selected":"a","seconds_since_switch":120},
    ]

    return [{"id": s["id"], "name": s["name"], "description": s["description"],
             "inputs": {"rates": s["rates"], "icap_aggregate": s["icap_aggregate"],
                        "icap_health": s["icap_health"],
                        "traffic_growth": f"{(s['short_rate']-s['medium_rate'])/s['medium_rate']*100:+.0f}%" if s["medium_rate"] > 0 else "N/A",
                        "current_mode": s["mode"]},
             "result": _decide(s)} for s in scenarios]


# ---------------------------------------------------------------------------
# Policy Engine proxy endpoints
# ---------------------------------------------------------------------------

_PE_NAMESPACE_FALLBACK = [
    {"namespace": "dev-test",     "environment": "development", "policy": "dev-policy"},
    {"namespace": "staging-test", "environment": "staging",     "policy": "staging-policy"},
    {"namespace": "prod-test",    "environment": "production",  "policy": "prod-policy"},
]


@app.get("/api/policy-engine/namespaces")
async def pe_namespaces():
    if not POLICY_ENGINE_URL:
        return _PE_NAMESPACE_FALLBACK
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{POLICY_ENGINE_URL}/api/namespaces", timeout=5.0)
            data = r.json()
            # Normalise: unwrap {"namespaces": [...]} or return as-is if already a list
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("namespaces", _PE_NAMESPACE_FALLBACK)
    except Exception:
        pass
    return _PE_NAMESPACE_FALLBACK


@app.get("/api/policy-engine/policies")
async def pe_policies():
    if not POLICY_ENGINE_URL:
        return []
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{POLICY_ENGINE_URL}/api/policies", timeout=5.0)
            data = r.json()
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("policies", [])
    except Exception:
        pass
    return []


@app.get("/api/policy-engine/compliance/frameworks")
async def pe_frameworks():
    if not POLICY_ENGINE_URL:
        return []
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{POLICY_ENGINE_URL}/api/compliance/frameworks", timeout=5.0)
            data = r.json()
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("frameworks", [])
    except Exception:
        pass
    return []


class _ApplyPolicyRequest(BaseModel):
    strategy: str = "compliance-first"


_NS_POLICY_MAP = {
    "dev-test":     {"environment": "development", "policy": "dev-policy",     "enforcement": "audit"},
    "staging-test": {"environment": "staging",     "policy": "staging-policy", "enforcement": "enforce"},
    "prod-test":    {"environment": "production",  "policy": "prod-policy",    "enforcement": "strict"},
}


@app.post("/api/policy-engine/namespaces/{namespace}/apply")
async def pe_apply_policy(namespace: str, body: _ApplyPolicyRequest):
    if POLICY_ENGINE_URL:
        try:
            async with httpx.AsyncClient() as client:
                r = await client.post(
                    f"{POLICY_ENGINE_URL}/api/namespaces/{namespace}/apply-policy",
                    json={"strategy": body.strategy},
                    timeout=10.0,
                )
                if r.status_code == 200 and r.text.strip():
                    return r.json()
        except Exception:
            pass
    # Fallback: simulate policy application from known namespace map
    info = _NS_POLICY_MAP.get(
        namespace,
        {"environment": "unknown", "policy": "default-policy", "enforcement": "audit"},
    )
    return {
        "namespace": namespace,
        "environment": info["environment"],
        "policy": info["policy"],
        "enforcement": info["enforcement"],
        "strategy": body.strategy,
        "status": "applied",
        "source": "local-fallback",
    }


# ---------------------------------------------------------------------------
# SSDLB proxy endpoints
# ---------------------------------------------------------------------------

@app.get("/api/ssdlb/state")
async def ssdlb_state():
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{SSDLB_URL}/state", timeout=5.0)
            return r.json()
    except Exception as exc:
        return {"error": str(exc), "mode": "unknown"}


@app.get("/api/ssdlb/trend")
async def ssdlb_trend():
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{SSDLB_URL}/trend-debug", timeout=5.0)
            if r.status_code != 200:
                raise ValueError(f"HTTP {r.status_code}")
            text = r.text.strip()
            if not text:
                raise ValueError("empty response")
            return r.json()
    except Exception as exc:
        # Prometheus is likely not running; return the live state with a note
        try:
            async with httpx.AsyncClient() as client:
                r2 = await client.get(f"{SSDLB_URL}/state", timeout=5.0)
                state = r2.json()
                state["_note"] = "Prometheus not available — showing routing state only"
                return state
        except Exception:
            return {"_note": "SSDLB trend unavailable (Prometheus not running)", "error": str(exc)}


@app.post("/api/ssdlb/auto-route")
async def ssdlb_auto_route():
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(f"{SSDLB_URL}/auto-route", timeout=10.0)
            return r.json()
    except Exception as exc:
        return {"error": str(exc)}


@app.post("/api/ssdlb/set-version/{version}")
async def ssdlb_set_version(version: str):
    if version not in ("a", "b", "c", "spread"):
        raise HTTPException(status_code=400, detail="version must be a, b, c, or spread")
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(f"{SSDLB_URL}/set-version/{version}", timeout=10.0)
            data = r.json()
            # Istio VirtualService not installed — translate the raw kubectl error
            err = data.get("error", "")
            if "VirtualService" in err or "istio" in err.lower() or "networking.istio" in err:
                return {
                    "status": "istio_unavailable",
                    "message": (
                        f"Routing override to instance {version.upper()} recorded. "
                        "Istio VirtualService CRDs are not installed in this cluster, "
                        "so live traffic steering is unavailable. "
                        "In a production cluster with Istio, this would redirect all "
                        "ICAP scanning traffic to instance " + version.upper() + "."
                    ),
                }
            return data
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# NLP Assistant — Groq integration
# ---------------------------------------------------------------------------

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
_groq_client = None

_CAPSLOCK_SYSTEM_PROMPT = """You are the CAPSLOCK assistant, an AI helper embedded in the CAPSLOCK \
Kubernetes deployment management system.

CAPSLOCK manages software promotions (deployments) through environments:
- Promotion pipeline: development → staging → production
- Each promotion has a risk score (0-100) from 4 weighted factors:
    configuration_complexity (30%), policy_changes (40%), version_delta (20%), environment_transition (10%)
- Risk thresholds: development max=80, staging max=60, production max=40
- Score > max → REJECTED; 80-100% of max → elevated risk; 60-80% → moderate; <60% → low risk

ICAP (Internet Content Adaptation Protocol) scanning runs on every deployment:
- Modes: block (default), warn, log-only
- Health score 0-100 weighted: readiness 25%, latency 25%, signature freshness 20%, error rate 15%, resources 10%, queue 5%

Supported compliance frameworks: CIS Kubernetes, PCI-DSS, SOC2, ISO 27001

You can help by:
1. Answering questions about promotions, risk scores, audit events — use the data tools
2. Explaining ICAP health and operator status
3. Setting up a promotion on the user's behalf — use fill_promotion_form (it fills the UI form; the user still submits)
4. Navigating to a specific tab — use switch_tab
5. Explaining any CAPSLOCK concept or metric

Be concise and direct. When you fill the form, confirm which fields you set."""

_NLP_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_promotions",
            "description": "Fetch recent promotions. Use for questions about deployments, approvals, rejections.",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Max to return (default 10)"},
                    "status_filter": {"type": "string", "enum": ["APPROVED", "REJECTED"],
                                      "description": "Optional filter by decision"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_audit_log",
            "description": "Fetch audit events. Use for questions about what happened, event history.",
            "parameters": {
                "type": "object",
                "properties": {
                    "event_type": {"type": "string",
                                   "description": "Filter: promotion_approved, promotion_rejected, icap_threat_detected, policy_rollback, promotion_created"},
                    "limit": {"type": "integer", "description": "Max events (default 20)"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_analytics",
            "description": "Get summary stats: total promotions, approved, rejected, average risk score.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_icap_status",
            "description": "Get current ICAP operator health score, scanning mode, replica status.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fill_promotion_form",
            "description": "Fill the promotion form in the Dashboard tab and navigate there. Use when the user wants to create or promote a deployment.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name":       {"type": "string", "description": "Promotion name"},
                    "app_name":   {"type": "string", "description": "Application name"},
                    "source_env": {"type": "string", "enum": ["development", "staging"]},
                    "target_env": {"type": "string", "enum": ["staging", "production"]},
                    "version":    {"type": "string", "description": "Version string, e.g. v1.2.3"},
                    "namespace":  {"type": "string", "description": "Kubernetes namespace (optional)"},
                },
                "required": ["name", "app_name", "source_env", "target_env", "version"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "switch_tab",
            "description": "Navigate to a specific tab in the CAPSLOCK dashboard.",
            "parameters": {
                "type": "object",
                "properties": {
                    "tab": {"type": "string",
                            "enum": ["dashboard", "icap", "audit", "versions", "validation", "assistant"],
                            "description": "Tab to navigate to"},
                },
                "required": ["tab"],
            },
        },
    },
]


def _exec_tool(name: str, args: dict) -> tuple[Any, Optional[dict]]:
    """Execute a tool call. Returns (result_for_model, ui_action_or_None)."""
    if name == "get_promotions":
        limit  = int(args.get("limit", 10))
        status = args.get("status_filter")
        items  = [
            {"id": p.metadata["id"], "name": p.metadata["name"],
             "app": p.spec.application.name,
             "source": p.spec.source_environment, "target": p.spec.target_environment,
             "version": p.spec.version, "decision": p.status.decision,
             "risk_score": p.status.risk_score}
            for p in promotions_db.values()
            if status is None or p.status.decision == status
        ]
        return items[-limit:], None

    if name == "get_audit_log":
        limit      = int(args.get("limit", 20))
        event_type = args.get("event_type")
        events     = audit_logger.get_events(limit=limit, event_type=event_type)
        return [e.model_dump() for e in events], None

    if name == "get_analytics":
        total    = len(promotions_db)
        approved = sum(1 for p in promotions_db.values() if p.status.decision == "APPROVED")
        avg_risk = sum(p.status.risk_score or 0 for p in promotions_db.values()) / total if total > 0 else 0
        return {"total_promotions": total, "approved": approved,
                "rejected": total - approved, "average_risk_score": round(avg_risk, 1)}, None

    if name == "get_icap_status":
        if not POLICY_ENGINE_URL:
            return {"aggregate_health_score": 92, "ready_replicas": 3, "desired_replicas": 3,
                    "scanning_mode": "block", "source": "synthetic"}, None
        try:
            import httpx as _httpx
            r = _httpx.get(f"{POLICY_ENGINE_URL}/api/icap/health", timeout=5.0)
            return r.json(), None
        except Exception as exc:
            return {"error": str(exc)}, None

    if name == "fill_promotion_form":
        action = {"type": "fill_promotion_form",
                  "name":       args.get("name", ""),
                  "app_name":   args.get("app_name", ""),
                  "source_env": args.get("source_env", "development"),
                  "target_env": args.get("target_env", "staging"),
                  "version":    args.get("version", ""),
                  "namespace":  args.get("namespace", "")}
        return "Promotion form filled and ready for the user to review and submit.", action

    if name == "switch_tab":
        tab    = args.get("tab", "dashboard")
        action = {"type": "switch_tab", "tab": tab}
        return f"Navigated to the '{tab}' tab.", action

    return f"Unknown tool: {name}", None


class _ChatRequest(BaseModel):
    message: str
    history: List[dict] = []


@app.post("/api/nlp/chat")
async def nlp_chat(req: _ChatRequest):
    """Natural-language assistant powered by Groq (llama-3.3-70b-versatile)."""
    if not GROQ_API_KEY:
        return {
            "reply": (
                "The CAPSLOCK Assistant requires a Groq API key. "
                "Get a free key at https://console.groq.com, then start the app with:\n\n"
                "  export GROQ_API_KEY=gsk_...\n\n"
                "Restart after setting the variable."
            ),
            "action": None,
        }

    try:
        from groq import AsyncGroq
    except ImportError:
        return {"reply": "groq package not installed. Run: pip install groq", "action": None}

    global _groq_client
    if _groq_client is None:
        _groq_client = AsyncGroq(api_key=GROQ_API_KEY)

    messages: List[dict] = [{"role": "system", "content": _CAPSLOCK_SYSTEM_PROMPT}]
    for h in req.history:
        if h.get("role") in ("user", "assistant"):
            messages.append({"role": h["role"], "content": h.get("content", "")})
    messages.append({"role": "user", "content": req.message})

    pending_action: Optional[dict] = None

    try:
        # First call — may return tool calls
        resp = await _groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=messages,
            tools=_NLP_TOOLS,
            tool_choice="auto",
            max_tokens=1024,
        )

        msg = resp.choices[0].message

        if msg.tool_calls:
            # Append the assistant message with tool_calls
            messages.append({
                "role": "assistant",
                "content": msg.content or "",
                "tool_calls": [
                    {"id": tc.id, "type": "function",
                     "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                    for tc in msg.tool_calls
                ],
            })

            # Execute each tool
            for tc in msg.tool_calls:
                fn_args = json.loads(tc.function.arguments)
                result, action = _exec_tool(tc.function.name, fn_args)
                if action:
                    pending_action = action
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps(result),
                })

            # Second call — model produces the final text reply
            resp2 = await _groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=messages,
                max_tokens=1024,
            )
            reply = resp2.choices[0].message.content or ""
        else:
            reply = msg.content or ""

    except Exception as exc:
        return {"reply": f"Assistant error: {exc}", "action": None}

    return {"reply": reply, "action": pending_action}


app.mount("/static", StaticFiles(directory="static"), name="static")
