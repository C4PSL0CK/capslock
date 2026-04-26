from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime


class ApplicationRef(BaseModel):
    name: str
    namespace: str = "default"


class PolicyMigration(BaseModel):
    add_policies: List[str] = []
    remove_policies: List[str] = []


class PromotionSpec(BaseModel):
    application: ApplicationRef
    source_environment: str
    target_environment: str
    version: str
    policy_migration: PolicyMigration


class GitOpsStatus(BaseModel):
    agent: str = "ArgoCD"
    app_name: str = ""
    sync_status: str = "pending"    # pending | syncing | synced | healthy | degraded
    health_status: str = "unknown"  # unknown | healthy | degraded | missing
    revision: str = ""
    cluster: str = "local"
    phases_completed: List[str] = []
    deployed_at: Optional[str] = None


class PromotionStatus(BaseModel):
    phase: str = "PENDING"          # PENDING | PENDING_APPROVAL | RUNNING | SUCCEEDED | FAILED | ROLLED_BACK
    risk_score: Optional[int] = None
    decision: Optional[str] = None  # APPROVED | REJECTED | PENDING_APPROVAL
    message: Optional[str] = None
    nlp_reasoning: Optional[str] = None  # Groq-generated plain-English explanation
    approval_required: bool = False
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    gitops: Optional[GitOpsStatus] = None
    rollback_version_id: Optional[str] = None
    policy_mode: str = "enforce"    # audit | enforce — effective mode at time of promotion


class Promotion(BaseModel):
    metadata: dict
    spec: PromotionSpec
    status: PromotionStatus = PromotionStatus()


class Environment(BaseModel):
    name: str
    type: str                        # development | staging | production
    max_risk_score: int
    policies: List[str]
    cluster: str = "local"           # logical cluster name
    policy_mode: str = "enforce"     # audit | enforce
    approval_threshold: float = 0.75 # risk > max*threshold requires human approval
