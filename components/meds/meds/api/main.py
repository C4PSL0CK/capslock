from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from typing import List, Dict
import uuid

from meds.models.promotion import Promotion, Environment, ApplicationRef, PolicyMigration, PromotionSpec
from meds.models.requests import CreatePromotionRequest
from meds.controllers.promotion_controller import PromotionController
from meds.policy.standards import POLICY_CATALOG, get_policies_for_environment

app = FastAPI(title="MEDS API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

promotions_db: Dict[str, Promotion] = {}
environments_db: Dict[str, Environment] = {}

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

controller = PromotionController()

@app.get("/")
async def root():
    try:
        with open("static/index.html", "r") as f:
            return HTMLResponse(content=f.read())
    except:
        return {"message": "MEDS API running. Visit /docs for API documentation"}

@app.get("/api/policies")
async def get_policies():
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
    return policies

@app.get("/api/environments")
async def get_environments():
    return list(environments_db.values())

@app.post("/api/promotions")
async def create_promotion(request: CreatePromotionRequest):
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
    
    result = controller.process_promotion(
        promotion, 
        environments_db[request.source_environment],
        environments_db[request.target_environment]
    )
    
    promotions_db[promotion_id] = promotion
    
    return {
        "id": promotion_id,
        "name": request.name,
        "decision": result["decision"],
        "risk_score": result["risk_assessment"]["total_score"],
        "max_allowed": result["risk_assessment"]["max_allowed"],
        "message": result["message"],
        "risk_assessment": result["risk_assessment"],
        "policy_plan": result["policy_plan"]
    }

@app.get("/api/promotions")
async def get_promotions():
    return [
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

@app.get("/api/analytics")
async def get_analytics():
    total = len(promotions_db)
    approved = sum(1 for p in promotions_db.values() if p.status.decision == "APPROVED")
    avg_risk = sum(p.status.risk_score or 0 for p in promotions_db.values()) / total if total > 0 else 0
    
    return {
        "total_promotions": total,
        "approved": approved,
        "rejected": total - approved,
        "average_risk_score": round(avg_risk, 1)
    }

# Mount static files
from fastapi.staticfiles import StaticFiles
app.mount("/static", StaticFiles(directory="static"), name="static")
