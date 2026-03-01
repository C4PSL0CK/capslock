from pydantic import BaseModel
from typing import List, Optional
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

class PromotionStatus(BaseModel):
    phase: str = "PENDING"
    risk_score: Optional[int] = None
    decision: Optional[str] = None
    message: Optional[str] = None

class Promotion(BaseModel):
    metadata: dict
    spec: PromotionSpec
    status: PromotionStatus = PromotionStatus()

class Environment(BaseModel):
    name: str
    type: str  # development, staging, production
    max_risk_score: int
    policies: List[str]
