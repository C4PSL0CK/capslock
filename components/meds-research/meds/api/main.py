from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from typing import Dict, Optional
import uuid
import time

from meds.models.promotion import Promotion, Environment, ApplicationRef, PolicyMigration, PromotionSpec
from meds.models.requests import CreatePromotionRequest, RollbackRequest
from meds.controllers.promotion_controller import PromotionController
from meds.policy.standards import POLICY_CATALOG, get_policies_for_environment
from meds.audit.log import AuditLogger, load_promotions, save_promotions
from meds.policy.version_store import PolicyVersionStore
from meds.monitoring import metrics
from meds.utils.logger import setup_logging, get_logger
from prometheus_client import CONTENT_TYPE_LATEST

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
environments_db: Dict[str, Environment] = {}

# Initialize environments
environments_db["development"] = Environment(
    name="development", type="development", max_risk_score=80,
    policies=get_policies_for_environment("development")
)
environments_db["staging"] = Environment(
    name="staging", type="staging", max_risk_score=60,
    policies=get_policies_for_environment("staging")
)
environments_db["production"] = Environment(
    name="production", type="production", max_risk_score=40,
    policies=get_policies_for_environment("production")
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
            "id": p.metadata["id"],
            "name": p.metadata["name"],
            "application": p.spec.application.name,
            "source": p.spec.source_environment,
            "target": p.spec.target_environment,
            "version": p.spec.version,
            "decision": p.status.decision,
            "risk_score": p.status.risk_score,
            "phase": p.status.phase
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


app.mount("/static", StaticFiles(directory="static"), name="static")
