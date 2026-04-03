import json

from flask import Blueprint, g, jsonify, request

from core.async_jobs import enqueue_async_job
from core.iam.db import SessionLocal
from core.iam.models import AsyncJob, ProjectUpload, User
from core.iam.rbac import require_auth, require_permission
from core.observability import metrics_registry


ops_bp = Blueprint("ops", __name__, url_prefix="/api/ops")


def _ok(**payload):
    return jsonify({"success": True, **payload})


def _fail(msg: str, code: int = 400):
    return jsonify({"success": False, "msg": msg}), code


def _job_payload(raw: str | None):
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _serialize_job(job: AsyncJob) -> dict:
    return {
        "id": job.id,
        "job_type": job.job_type,
        "status": job.status,
        "priority": job.priority,
        "payload": _job_payload(job.payload_json),
        "result": _job_payload(job.result_json),
        "error_message": job.error_message,
        "attempts": job.attempts,
        "project_id": job.project_id,
        "created_by_user_id": job.created_by_user_id,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "created_at": job.created_at,
    }


def _can_read_job(db, job: AsyncJob) -> bool:
    user = db.get(User, g.user_id)
    if user and user.role and user.role.name == "owner":
        return True
    return job.created_by_user_id == g.user_id


@ops_bp.route("/metrics", methods=["GET"])
@require_auth
@require_permission("audit:read")
def get_metrics():
    return _ok(metrics=metrics_registry.snapshot())


@ops_bp.route("/jobs", methods=["GET"])
@require_auth
@require_permission("projects:read")
def list_jobs():
    db = SessionLocal()
    try:
        query = db.query(AsyncJob)
        project_id = (request.args.get("project_id") or "").strip()
        if project_id:
            query = query.filter(AsyncJob.project_id == project_id)

        user = db.get(User, g.user_id)
        if not (user and user.role and user.role.name == "owner"):
            query = query.filter(AsyncJob.created_by_user_id == g.user_id)

        jobs = query.order_by(AsyncJob.created_at.desc()).limit(50).all()
        return _ok(jobs=[_serialize_job(job) for job in jobs])
    finally:
        db.close()


@ops_bp.route("/jobs/<job_id>", methods=["GET"])
@require_auth
@require_permission("projects:read")
def get_job(job_id: str):
    db = SessionLocal()
    try:
        job = db.get(AsyncJob, job_id)
        if not job:
            return _fail("Job não encontrado", 404)
        if not _can_read_job(db, job):
            return _fail("Permissões insuficientes", 403)
        return _ok(job=_serialize_job(job))
    finally:
        db.close()


@ops_bp.route("/projects/<project_id>/scan", methods=["POST"])
@require_auth
@require_permission("projects:write")
def enqueue_project_scan(project_id: str):
    db = SessionLocal()
    try:
        project = db.get(ProjectUpload, project_id)
        if not project:
            return _fail("Projeto não encontrado", 404)
        user = db.get(User, g.user_id)
        is_owner = bool(user and user.role and user.role.name == "owner")
        if not is_owner and project.user_id != g.user_id:
            return _fail("Permissões insuficientes", 403)
        job_id = enqueue_async_job(
            job_type="project_scan",
            project_id=project.id,
            created_by_user_id=g.user_id,
            priority=20,
        )
        return _ok(job_id=job_id)
    finally:
        db.close()


@ops_bp.route("/projects/<project_id>/publish", methods=["POST"])
@require_auth
@require_permission("projects:approve")
def enqueue_project_publish(project_id: str):
    db = SessionLocal()
    try:
        project = db.get(ProjectUpload, project_id)
        if not project:
            return _fail("Projeto não encontrado", 404)
        user = db.get(User, g.user_id)
        if not (user and user.role and user.role.name == "owner"):
            return _fail("Permissões insuficientes", 403)
        if project.visibility != "public":
            return _fail("Somente pacotes públicos podem ser publicados", 403)
        if project.lifecycle_status not in {"approved", "archived"}:
            return _fail("Projeto não está pronto para publicação", 409)

        job_id = enqueue_async_job(
            job_type="project_publish",
            project_id=project.id,
            created_by_user_id=g.user_id,
            priority=10,
        )
        return _ok(job_id=job_id)
    finally:
        db.close()
