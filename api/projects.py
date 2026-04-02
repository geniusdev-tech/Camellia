import os
import uuid

from flask import Blueprint, jsonify, request, g

from core.iam.db import SessionLocal
from core.iam.models import ProjectUpload
from core.iam.rbac import require_auth, require_permission
from utils.supabase_storage import upload_to_supabase


projects_bp = Blueprint("projects", __name__, url_prefix="/api/projects")

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET")


def _serialize_project(item: ProjectUpload) -> dict:
    return {
        "id": item.id,
        "filename": item.filename,
        "content_type": item.content_type,
        "size_bytes": item.size_bytes,
        "storage_key": item.storage_key,
        "bucket": getattr(item, "bucket", SUPABASE_BUCKET),
        "created_at": item.created_at,
    }


@projects_bp.route("/upload", methods=["POST"])
@require_auth
@require_permission("vault:write")
def upload_project():
    file = request.files.get("file")
    if not file:
        return jsonify({"success": False, "msg": "Arquivo obrigatorio"}), 400

    filename = (file.filename or "").strip()
    if not filename.lower().endswith(".zip"):
        return jsonify({"success": False, "msg": "Envie um arquivo .zip"}), 400

    payload = file.read()
    if not payload:
        return jsonify({"success": False, "msg": "Arquivo vazio"}), 400

    if len(payload) > MAX_UPLOAD_BYTES:
        return jsonify({"success": False, "msg": "Arquivo excede 25 MB"}), 400

    if not SUPABASE_BUCKET:
        return jsonify({"success": False, "msg": "Supabase bucket não configurado"}), 500

    storage_key = f"projects/{uuid.uuid4()}-{filename}"

    db = SessionLocal()
    try:
        upload_to_supabase(
            SUPABASE_BUCKET,
            storage_key,
            payload,
            file.mimetype or "application/zip",
        )

        item = ProjectUpload(
            user_id=g.user_id,
            filename=filename,
            content_type=file.mimetype,
            size_bytes=len(payload),
            storage_key=storage_key,
        )
        db.add(item)
        db.commit()
        db.refresh(item)
        return jsonify({"success": True, "project": _serialize_project(item)})
    except Exception as e:
        db.rollback()
        return jsonify({"success": False, "msg": str(e)}), 500
    finally:
        db.close()


@projects_bp.route("/list", methods=["GET"])
@require_auth
@require_permission("vault:read")
def list_projects():
    db = SessionLocal()
    try:
        items = (
            db.query(ProjectUpload)
            .filter_by(user_id=g.user_id)
            .order_by(ProjectUpload.created_at.desc())
            .all()
        )
        return jsonify({
            "success": True,
            "projects": [_serialize_project(item) for item in items],
        })
    finally:
        db.close()
