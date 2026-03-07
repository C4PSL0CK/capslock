import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

from pydantic import BaseModel

from meds.utils.logger import get_logger


class AuditEvent(BaseModel):
    event_id:   str
    timestamp:  str
    event_type: str
    promotion_id: Optional[str] = None
    environment:  Optional[str] = None
    details:    dict = {}
    actor:      str  = "system"
    prev_hash:  str  = "genesis"  # SHA-256 of the previous event — forms a verifiable chain
    event_hash: str  = ""         # SHA-256 of this event content (computed on write)


class AuditLogger:
    def __init__(self, data_dir: str = "data"):
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._log_file  = self._data_dir / "audit_log.jsonl"
        self._logger    = get_logger("meds.audit")
        self._last_hash: str = self._read_last_hash()

    # ── Public API ────────────────────────────────────────────────────────────

    def log(
        self,
        event_type: str,
        details: dict,
        promotion_id: Optional[str] = None,
        environment:  Optional[str] = None,
        actor:        str           = "system",
    ) -> AuditEvent:
        event = AuditEvent(
            event_id     = str(uuid.uuid4())[:8],
            timestamp    = datetime.now(timezone.utc).isoformat(),
            event_type   = event_type,
            promotion_id = promotion_id,
            environment  = environment,
            details      = details,
            actor        = actor,
            prev_hash    = self._last_hash,
            event_hash   = "",
        )
        # Compute hash over all fields EXCEPT event_hash itself
        content = event.model_dump()
        content.pop("event_hash", None)
        digest = hashlib.sha256(
            json.dumps(content, sort_keys=True, default=str).encode()
        ).hexdigest()
        event.event_hash = digest

        with open(self._log_file, "a") as f:
            f.write(event.model_dump_json() + "\n")

        self._last_hash = digest
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

    def verify_chain(self) -> Dict[str, Any]:
        """Verify SHA-256 hash chain integrity across the entire audit log."""
        events = self.get_events(limit=100_000)
        if not events:
            return {"valid": True, "events_checked": 0, "message": "Log is empty"}

        broken_at = None
        for i, event in enumerate(events):
            expected_prev = "genesis" if i == 0 else events[i - 1].event_hash
            if event.prev_hash != expected_prev:
                broken_at = event.event_id
                break
            # Recompute the hash to detect field tampering
            content = event.model_dump()
            content.pop("event_hash", None)
            recomputed = hashlib.sha256(
                json.dumps(content, sort_keys=True, default=str).encode()
            ).hexdigest()
            if recomputed != event.event_hash:
                broken_at = event.event_id
                break

        return {
            "valid":          broken_at is None,
            "events_checked": len(events),
            "broken_at":      broken_at,
            "message":        "Chain intact" if broken_at is None else f"Tamper detected at event {broken_at}",
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    def _read_last_hash(self) -> str:
        if not self._log_file.exists():
            return "genesis"
        try:
            with open(self._log_file, "rb") as f:
                # Read last non-empty line efficiently
                f.seek(0, 2)
                pos = f.tell()
                buf = b""
                while pos > 0:
                    step = min(512, pos)
                    pos -= step
                    f.seek(pos)
                    buf = f.read(step) + buf
                    lines = buf.split(b"\n")
                    for line in reversed(lines):
                        if line.strip():
                            data = json.loads(line.decode("utf-8", errors="replace"))
                            return data.get("event_hash", "genesis")
        except Exception:
            pass
        return "genesis"


# ── Persistence helpers (promotions) ──────────────────────────────────────────

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
