import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.exc import OperationalError

from core.iam.models import AsyncJob, ProjectStatusEvent, ProjectUpload

logger = logging.getLogger(__name__)

_worker_lock = threading.Lock()
_worker_started = False
SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\."
    r"(0|[1-9]\d*)\."
    r"(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z.-]+))?"
    r"(?:\+([0-9A-Za-z.-]+))?$"
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_semver(value: str) -> tuple[int, int, int, int, str]:
    match = SEMVER_RE.fullmatch(value)
    if not match:
        return (0, 0, 0, 0, value)
    major, minor, patch, prerelease, _build = match.groups()
    prerelease_rank = 1 if not prerelease else 0
    return int(major), int(minor), int(patch), prerelease_rank, prerelease or ""


def _set_latest_flags(db, package_name: str) -> None:
    published = (
        db.query(ProjectUpload)
        .filter_by(package_name=package_name, lifecycle_status="published")
        .all()
    )
    if not published:
        return
    latest = max(published, key=lambda item: _parse_semver(item.package_version))
    for item in published:
        item.is_latest = item.id == latest.id


def enqueue_async_job(
    *,
    job_type: str,
    payload: dict[str, Any] | None = None,
    project_id: str | None = None,
    created_by_user_id: int | None = None,
    priority: int = 100,
) -> str:
    from core.iam.db import SessionLocal

    db = SessionLocal()
    try:
        job = AsyncJob(
            job_type=job_type,
            payload_json=json.dumps(payload or {}, ensure_ascii=True),
            project_id=project_id,
            created_by_user_id=created_by_user_id,
            priority=priority,
        )
        db.add(job)
        db.commit()
        return job.id
    finally:
        db.close()


def _handle_project_scan(db, job: AsyncJob) -> dict[str, Any]:
    project = db.get(ProjectUpload, job.project_id)
    if not project:
        raise RuntimeError("Projeto do job não encontrado")
    result = {
        "checksum_sha256": project.checksum_sha256,
        "zip_entry_count": project.zip_entry_count,
        "uncompressed_size_bytes": project.uncompressed_size_bytes,
        "status": "clean",
    }
    metadata = json.loads(project.metadata_json or "{}")
    metadata["scan"] = {"status": "clean", "job_id": job.id, "completed_at": _utcnow()}
    project.metadata_json = json.dumps(metadata, ensure_ascii=True)
    return result


def _handle_project_publish(db, job: AsyncJob) -> dict[str, Any]:
    project = db.get(ProjectUpload, job.project_id)
    if not project:
        raise RuntimeError("Projeto do job não encontrado")
    if project.lifecycle_status not in {"approved", "archived"}:
        raise RuntimeError("Projeto não está pronto para publicação assíncrona")
    previous = project.lifecycle_status
    project.lifecycle_status = "published"
    project.published_at = _utcnow()
    project.is_latest = False
    db.flush()
    db.add(
        ProjectStatusEvent(
            project_id=project.id,
            actor_user_id=job.created_by_user_id or project.user_id,
            from_status=previous,
            to_status="published",
            reason="published_async",
        )
    )
    _set_latest_flags(db, project.package_name)
    return {"project_id": project.id, "published_at": project.published_at}


def _process_job(db, job: AsyncJob) -> dict[str, Any]:
    if job.job_type == "project_scan":
        return _handle_project_scan(db, job)
    if job.job_type == "project_publish":
        return _handle_project_publish(db, job)
    raise RuntimeError(f"Tipo de job desconhecido: {job.job_type}")


def _run_worker_loop(poll_interval: float) -> None:
    while True:
        from core.iam.db import SessionLocal

        db = SessionLocal()
        try:
            try:
                job = (
                    db.query(AsyncJob)
                    .filter(AsyncJob.status.in_(("queued", "retry")))
                    .order_by(AsyncJob.priority.asc(), AsyncJob.created_at.asc())
                    .first()
                )
            except OperationalError:
                time.sleep(poll_interval)
                continue
            if not job:
                time.sleep(poll_interval)
                continue

            job.status = "running"
            job.attempts = (job.attempts or 0) + 1
            job.started_at = _utcnow()
            db.commit()

            try:
                result = _process_job(db, job)
                job.status = "completed"
                job.result_json = json.dumps(result, ensure_ascii=True)
                job.error_message = None
                db.flush()
            except Exception as exc:
                logger.exception("Async job failed: %s", job.id)
                job.status = "failed"
                job.error_message = str(exc)
            finally:
                job.finished_at = _utcnow()
                db.commit()
        finally:
            db.close()


def start_async_job_worker() -> None:
    global _worker_started
    if os.getenv("GATESTACK_ASYNC_WORKER", "1").strip() == "0":
        return
    with _worker_lock:
        if _worker_started:
            return
        thread = threading.Thread(
            target=_run_worker_loop,
            args=(float(os.getenv("GATESTACK_ASYNC_POLL_SECONDS", "0.5")),),
            daemon=True,
            name="gatestack-async-worker",
        )
        thread.start()
        _worker_started = True
