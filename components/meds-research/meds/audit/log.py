import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

from pydantic import BaseModel

from meds.utils.logger import get_logger


class AuditEvent(BaseModel):
    event_id: str
    timestamp: str
    event_type: str
    promotion_id: Optional[str] = None
    environment: Optional[str] = None
    details: dict = {}
    actor: str = "system"


class AuditLogger:
    def __init__(self, data_dir: str = "data"):
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._log_file = self._data_dir / "audit_log.jsonl"
        self._logger = get_logger("meds.audit")

    def log(
        self,
        event_type: str,
        details: dict,
        promotion_id: Optional[str] = None,
        environment: Optional[str] = None,
        actor: str = "system",
    ) -> AuditEvent:
        event = AuditEvent(
            event_id=str(uuid.uuid4())[:8],
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            promotion_id=promotion_id,
            environment=environment,
            details=details,
            actor=actor,
        )
        with open(self._log_file, "a") as f:
            f.write(event.model_dump_json() + "\n")

        self._logger.info("audit_event_logged", event_type=event_type, event_id=event.event_id)
        return event

    def get_events(
        self, limit: int = 100, event_type: Optional[str] = None
    ) -> List[AuditEvent]:
        if not self._log_file.exists():
            return []
        events: List[AuditEvent] = []
        with open(self._log_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(AuditEvent(**json.loads(line)))
                except Exception:
                    continue
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events[-limit:]


def save_promotions(promotions_db: Dict[str, Any], data_dir: str = "data") -> None:
    path = Path(data_dir)
    path.mkdir(parents=True, exist_ok=True)
    data = {pid: p.model_dump() for pid, p in promotions_db.items()}
    with open(path / "promotions.json", "w") as f:
        json.dump(data, f, indent=2)


def load_promotions(data_dir: str = "data") -> Dict[str, Any]:
    store = Path(data_dir) / "promotions.json"
    if not store.exists():
        return {}
    try:
        with open(store, "r") as f:
            return json.load(f)
    except Exception:
        return {}
