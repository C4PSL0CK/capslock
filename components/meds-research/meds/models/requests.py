from pydantic import BaseModel
from typing import List

class CreatePromotionRequest(BaseModel):
    name: str
    application_name: str
    application_namespace: str = "default"
    source_environment: str
    target_environment: str
    version: str
    add_policies: List[str] = []
    remove_policies: List[str] = []


class RollbackRequest(BaseModel):
    version_id: str
