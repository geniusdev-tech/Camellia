import json
import logging
import sys
from datetime import datetime, timezone

from core.observability import current_request_id


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = current_request_id()
        if request_id:
            payload["request_id"] = request_id
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=True)


def configure_json_logging(siem_endpoint: str | None = None) -> None:
    root = logging.getLogger()
    if getattr(root, "_gatestack_configured", False):
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    root._gatestack_configured = True  # type: ignore[attr-defined]

    if siem_endpoint:
        root.info("SIEM logging requested for %s (dev stub)", siem_endpoint)
