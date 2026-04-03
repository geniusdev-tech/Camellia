import threading
import time
import uuid
from collections import defaultdict
from typing import Any

from flask import Flask, g, has_request_context, request


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = defaultdict(int)
        self._latencies_ms: dict[str, list[int]] = defaultdict(list)

    def record(self, method: str, route: str, status_code: int, duration_ms: int) -> None:
        key = f"{method} {route} {status_code}"
        with self._lock:
            self._counters[key] += 1
            self._latencies_ms[f"{method} {route}"].append(duration_ms)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "requests": dict(self._counters),
                "latency_ms": {
                    key: {
                        "count": len(values),
                        "avg": round(sum(values) / len(values), 2) if values else 0,
                        "max": max(values) if values else 0,
                    }
                    for key, values in self._latencies_ms.items()
                },
            }

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._latencies_ms.clear()


metrics_registry = MetricsRegistry()


def current_request_id() -> str | None:
    if not has_request_context():
        return None
    return getattr(g, "request_id", None)


def install_request_observability(app: Flask) -> None:
    @app.before_request
    def _before_request() -> None:
        g.request_id = request.headers.get("X-Request-Id") or uuid.uuid4().hex
        g.request_started_at = time.perf_counter()

    @app.after_request
    def _after_request(response):
        started = getattr(g, "request_started_at", None)
        if started is not None:
            duration_ms = int((time.perf_counter() - started) * 1000)
            route = request.url_rule.rule if request.url_rule else request.path
            metrics_registry.record(request.method, route, response.status_code, duration_ms)
            response.headers["X-Response-Time-Ms"] = str(duration_ms)
        request_id = current_request_id()
        if request_id:
            response.headers["X-Request-Id"] = request_id
        return response
