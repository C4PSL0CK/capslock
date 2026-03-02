import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel

from meds.utils.logger import get_logger

logger = get_logger("meds.policy.version_store")


class PolicyVersion(BaseModel):
    version_id: str
    environment: str
    policies: List[str]
    timestamp: str
    promotion_id: Optional[str] = None
    note: str = ""


class PolicyVersionStore:
    def __init__(self, data_dir: str = "data"):
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._store_file = self._data_dir / "policy_versions.json"
        self._versions: List[PolicyVersion] = []
        self._load()

    def _load(self) -> None:
        if not self._store_file.exists():
            self._versions = []
            return
        try:
            with open(self._store_file, "r") as f:
                data = json.load(f)
            self._versions = [PolicyVersion(**v) for v in data]
        except Exception:
            logger.warning("policy_version_store_load_failed", path=str(self._store_file))
            self._versions = []

    def _save(self) -> None:
        with open(self._store_file, "w") as f:
            json.dump([v.model_dump() for v in self._versions], f, indent=2)

    def save_version(
        self,
        environment: str,
        policies: List[str],
        promotion_id: Optional[str] = None,
        note: str = "",
    ) -> PolicyVersion:
        version = PolicyVersion(
            version_id=str(uuid.uuid4())[:8],
            environment=environment,
            policies=list(policies),
            timestamp=datetime.now(timezone.utc).isoformat(),
            promotion_id=promotion_id,
            note=note,
        )
        self._versions.append(version)
        self._save()
        logger.info("policy_version_saved", version_id=version.version_id, environment=environment)
        return version

    def get_versions(self, environment: str) -> List[PolicyVersion]:
        filtered = [v for v in self._versions if v.environment == environment]
        return sorted(filtered, key=lambda v: v.timestamp, reverse=True)

    def rollback(
        self, environment: str, version_id: str, environments_db: Dict
    ) -> PolicyVersion:
        target = next(
            (v for v in self._versions if v.environment == environment and v.version_id == version_id),
            None,
        )
        if target is None:
            raise ValueError(f"Version '{version_id}' not found for environment '{environment}'")

        environments_db[environment].policies = list(target.policies)

        rollback_version = self.save_version(
            environment=environment,
            policies=target.policies,
            note=f"Rollback to {version_id}",
        )
        logger.info("policy_rollback_applied", environment=environment, target_version=version_id)
        return rollback_version
