import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock
from typing import Any


_audit_logger = None


@dataclass
class AuditEvent:
    timestamp: str
    event_type: str
    user: str
    severity: str
    details: dict[str, Any]
    previous_hash: str
    hash: str


class AuditLogger:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = Lock()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        if not os.path.exists(path):
            open(path, "a", encoding="utf-8").close()

    def _read_events(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        with open(self.path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return events

    def log_event(
        self,
        event_type: str,
        user: str,
        severity: str = "INFO",
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        details = details or {}
        with self._lock:
            events = self._read_events()
            previous_hash = events[-1]["hash"] if events else ""
            payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": event_type,
                "user": user,
                "severity": severity,
                "details": details,
                "previous_hash": previous_hash,
            }
            digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
            payload["hash"] = digest
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
            return payload

    def get_events(
        self,
        event_type: str | None = None,
        user: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        events = self._read_events()
        if event_type:
            events = [e for e in events if e.get("event_type") == event_type]
        if user:
            events = [e for e in events if e.get("user") == user]
        return list(reversed(events[-limit:]))

    def verify_log_integrity(self) -> tuple[bool, list[str]]:
        errors: list[str] = []
        events = self._read_events()
        previous_hash = ""
        for idx, event in enumerate(events):
            expected_payload = {
                "timestamp": event.get("timestamp"),
                "event_type": event.get("event_type"),
                "user": event.get("user"),
                "severity": event.get("severity"),
                "details": event.get("details", {}),
                "previous_hash": event.get("previous_hash", ""),
            }
            expected_hash = hashlib.sha256(
                json.dumps(expected_payload, sort_keys=True).encode("utf-8")
            ).hexdigest()
            if event.get("previous_hash") != previous_hash:
                errors.append(f"broken_chain:{idx}")
            if event.get("hash") != expected_hash:
                errors.append(f"invalid_hash:{idx}")
            previous_hash = event.get("hash", "")
        return not errors, errors


def init_audit_logger(path: str) -> AuditLogger:
    global _audit_logger
    _audit_logger = AuditLogger(path)
    return _audit_logger


def get_audit_logger() -> AuditLogger:
    if _audit_logger is None:
        raise RuntimeError("Audit logger not initialised")
    return _audit_logger
