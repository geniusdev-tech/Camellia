import hashlib
import json
import os
import re
import tempfile
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Blueprint, g, jsonify, request
from sqlalchemy import and_, or_

from core.async_jobs import enqueue_async_job
from core.audit.logger import get_audit_logger
from core.iam.db import SessionLocal
from core.iam.models import (
    ProjectShareGrant,
    ProjectStatusEvent,
    ProjectTeamGrant,
    ProjectUpload,
    TeamMember,
    User,
)
from core.iam.rbac import require_auth, require_permission
from utils.supabase_storage import (
    create_signed_download_url,
    delete_from_supabase,
    upload_file_to_supabase,
)


projects_bp = Blueprint("projects", __name__, url_prefix="/api/projects")
public_packages_bp = Blueprint("public_packages", __name__, url_prefix="/api/public/packages")

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_ZIP_ENTRIES = 500
MAX_UNCOMPRESSED_BYTES = 250 * 1024 * 1024
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100
ALLOWED_VISIBILITY = {"private", "public", "shared"}
ALLOWED_STATUS = {"draft", "submitted", "approved", "published", "archived", "rejected"}
PUBLISHED_STATUSES = {"published", "archived"}
SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET")
SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\."
    r"(0|[1-9]\d*)\."
    r"(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z.-]+))?"
    r"(?:\+([0-9A-Za-z.-]+))?$"
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_response_ok(**payload: Any):
    return jsonify({"success": True, **payload})


def _json_response_fail(msg: str, code: int = 400):
    return jsonify({"success": False, "msg": msg}), code


def _normalize_shared_with(raw: str | None) -> list[int]:
    if not raw:
        return []
    values: list[int] = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            values.append(int(chunk))
        except ValueError:
            continue
    return sorted(set(values))


def _grant_is_active(grant: ProjectShareGrant | ProjectTeamGrant) -> bool:
    expires_at = getattr(grant, "expires_at", None)
    if not expires_at:
        return True
    try:
        return datetime.fromisoformat(expires_at) > datetime.now(timezone.utc)
    except ValueError:
        return True


def _shared_user_ids(project: ProjectUpload) -> list[int]:
    raw_grants = getattr(project, "share_grants", [])
    if raw_grants:
        return sorted(
            {
                grant.grantee_user_id
                for grant in raw_grants
                if _grant_is_active(grant)
            }
        )
    return _normalize_shared_with(project.shared_with)


def _serialize_share_grants(project: ProjectUpload) -> list[dict[str, Any]]:
    grants = []
    for grant in getattr(project, "share_grants", []):
        grants.append(
            {
                "user_id": grant.grantee_user_id,
                "grant_role": grant.grant_role,
                "expires_at": grant.expires_at,
                "created_at": grant.created_at,
            }
        )
    grants.sort(key=lambda item: (item["user_id"], item["grant_role"]))
    return grants


def _current_user_team_ids(db) -> list[str]:
    return [
        team_id
        for (team_id,) in (
            db.query(TeamMember.team_id)
            .filter(TeamMember.user_id == getattr(g, "user_id", None))
            .all()
        )
    ]


def _shared_team_ids(project: ProjectUpload) -> list[str]:
    return sorted(
        {
            grant.team_id
            for grant in getattr(project, "team_grants", [])
            if _grant_is_active(grant)
        }
    )


def _serialize_team_grants(project: ProjectUpload) -> list[dict[str, Any]]:
    grants = []
    for grant in getattr(project, "team_grants", []):
        grants.append(
            {
                "team_id": grant.team_id,
                "grant_role": grant.grant_role,
                "expires_at": grant.expires_at,
                "created_at": grant.created_at,
            }
        )
    grants.sort(key=lambda item: (item["team_id"], item["grant_role"]))
    return grants


def _parse_metadata(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _serialize_project(item: ProjectUpload) -> dict[str, Any]:
    return {
        "id": item.id,
        "user_id": item.user_id,
        "package_name": item.package_name,
        "package_version": item.package_version,
        "filename": item.filename,
        "description": item.description,
        "changelog": item.changelog,
        "content_type": item.content_type,
        "size_bytes": item.size_bytes,
        "uncompressed_size_bytes": item.uncompressed_size_bytes,
        "zip_entry_count": item.zip_entry_count,
        "checksum_sha256": item.checksum_sha256,
        "storage_key": item.storage_key,
        "bucket": item.bucket or SUPABASE_BUCKET,
        "visibility": item.visibility,
        "lifecycle_status": item.lifecycle_status,
        "status_reason": item.status_reason,
        "is_latest": bool(item.is_latest),
        "shared_with": _shared_user_ids(item),
        "share_grants": _serialize_share_grants(item),
        "team_grants": _serialize_team_grants(item),
        "metadata": _parse_metadata(item.metadata_json),
        "duplicate_of_id": item.duplicate_of_id,
        "download_count": item.download_count,
        "reviewed_by": item.reviewed_by,
        "reviewed_at": item.reviewed_at,
        "submitted_at": item.submitted_at,
        "approved_at": item.approved_at,
        "published_at": item.published_at,
        "archived_at": item.archived_at,
        "rejected_at": item.rejected_at,
        "created_at": item.created_at,
    }


def _serialize_status_event(event: ProjectStatusEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "project_id": event.project_id,
        "actor_user_id": event.actor_user_id,
        "from_status": event.from_status,
        "to_status": event.to_status,
        "reason": event.reason,
        "created_at": event.created_at,
    }


def _log_event(
    event_type: str,
    details: dict[str, Any] | None = None,
    severity: str = "INFO",
) -> None:
    try:
        get_audit_logger().log_event(
            event_type,
            user=str(getattr(g, "user_id", "anonymous")),
            severity=severity,
            details=details or {},
        )
    except Exception:
        pass


def _current_user_role(db) -> str:
    user = db.get(User, getattr(g, "user_id", None))
    if user and user.role:
        return user.role.name
    return "user"


def _can_manage_project(project: ProjectUpload, role_name: str) -> bool:
    return role_name == "owner" or project.user_id == getattr(g, "user_id", None)


def _can_read_project(project: ProjectUpload, role_name: str, db=None) -> bool:
    if role_name == "owner" or project.user_id == getattr(g, "user_id", None):
        return True
    if project.visibility == "public" and project.lifecycle_status in PUBLISHED_STATUSES:
        return True
    if project.visibility == "shared":
        if getattr(g, "user_id", None) in _shared_user_ids(project):
            return True
        if db is not None:
            active_team_ids = set(_shared_team_ids(project))
            if not active_team_ids:
                return False
            return bool(active_team_ids.intersection(_current_user_team_ids(db)))
    return False


def _validate_package_name(value: str) -> bool:
    return bool(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}", value))


def _parse_semver(value: str) -> tuple[int, int, int, int, str]:
    match = SEMVER_RE.fullmatch(value)
    if not match:
        raise ValueError("Versão deve seguir semver, por exemplo 1.2.3")
    major, minor, patch, prerelease, _build = match.groups()
    prerelease_rank = 1 if not prerelease else 0
    return int(major), int(minor), int(patch), prerelease_rank, prerelease or ""


def _validate_version(value: str) -> bool:
    return bool(SEMVER_RE.fullmatch(value))


def _record_status_event(
    db,
    project: ProjectUpload,
    from_status: str | None,
    to_status: str,
    reason: str | None = None,
) -> None:
    db.add(
        ProjectStatusEvent(
            project_id=project.id,
            actor_user_id=getattr(g, "user_id", project.user_id),
            from_status=from_status,
            to_status=to_status,
            reason=reason,
        )
    )


def _sync_share_grants(
    db,
    project: ProjectUpload,
    shared_with: list[int] | list[dict[str, Any]],
    grant_role: str = "viewer",
    expires_at: str | None = None,
) -> None:
    normalized_grants: dict[int, dict[str, Any]] = {}
    for item in shared_with:
        if isinstance(item, dict):
            user_id = int(item["user_id"])
            normalized_grants[user_id] = {
                "grant_role": item.get("grant_role") or grant_role,
                "expires_at": item.get("expires_at") or expires_at,
            }
        else:
            normalized_grants[int(item)] = {
                "grant_role": grant_role,
                "expires_at": expires_at,
            }

    current = {
        grant.grantee_user_id: grant
        for grant in db.query(ProjectShareGrant).filter_by(project_id=project.id).all()
    }
    desired = set(normalized_grants)

    for user_id, grant in current.items():
        if user_id not in desired:
            db.delete(grant)

    for user_id in desired:
        grant = current.get(user_id)
        details = normalized_grants[user_id]
        if grant:
            grant.grant_role = details["grant_role"]
            grant.expires_at = details["expires_at"]
            continue
        db.add(
            ProjectShareGrant(
                project_id=project.id,
                grantee_user_id=user_id,
                grant_role=details["grant_role"],
                expires_at=details["expires_at"],
            )
        )


def _sync_team_grants(
    db,
    project: ProjectUpload,
    team_grants: list[dict[str, Any]],
) -> None:
    normalized: dict[str, dict[str, Any]] = {}
    for item in team_grants:
        team_id = str(item["team_id"]).strip()
        if not team_id:
            continue
        normalized[team_id] = {
            "grant_role": (item.get("grant_role") or "viewer").strip(),
            "expires_at": item.get("expires_at"),
        }

    current = {
        grant.team_id: grant
        for grant in db.query(ProjectTeamGrant).filter_by(project_id=project.id).all()
    }
    desired = set(normalized)

    for team_id, grant in current.items():
        if team_id not in desired:
            db.delete(grant)

    for team_id in desired:
        grant = current.get(team_id)
        details = normalized[team_id]
        if grant:
            grant.grant_role = details["grant_role"]
            grant.expires_at = details["expires_at"]
            continue
        db.add(
            ProjectTeamGrant(
                project_id=project.id,
                team_id=team_id,
                grant_role=details["grant_role"],
                expires_at=details["expires_at"],
            )
        )


def _stamp_status_timestamp(project: ProjectUpload, status: str) -> None:
    now = _utcnow()
    if status == "submitted":
        project.submitted_at = now
    elif status == "approved":
        project.approved_at = now
    elif status == "published":
        project.published_at = now
    elif status == "archived":
        project.archived_at = now
    elif status == "rejected":
        project.rejected_at = now


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


def _validate_status_transition(
    role_name: str,
    current_status: str,
    new_status: str,
) -> bool:
    if new_status == current_status:
        return True
    owner_transitions = {
        "draft": {"submitted", "approved", "published", "rejected", "archived"},
        "submitted": {"approved", "rejected", "archived"},
        "approved": {"published", "rejected", "archived"},
        "published": {"archived"},
        "archived": {"published"},
        "rejected": {"draft", "submitted", "archived"},
    }
    user_transitions = {
        "draft": {"submitted", "archived"},
        "submitted": {"draft", "archived"},
        "rejected": {"draft", "submitted"},
        "published": {"archived"},
        "archived": {"draft"},
    }
    transitions = owner_transitions if role_name == "owner" else user_transitions
    return new_status in transitions.get(current_status, set())


def _validate_release_rules(
    db,
    project: ProjectUpload,
    role_name: str,
    new_status: str,
) -> str | None:
    if new_status != "published":
        return None
    if role_name != "owner":
        return "Somente owner pode publicar releases"
    if project.visibility != "public":
        return "Somente pacotes públicos podem ser publicados"
    duplicate = (
        db.query(ProjectUpload)
        .filter(
            ProjectUpload.package_name == project.package_name,
            ProjectUpload.package_version == project.package_version,
            ProjectUpload.lifecycle_status == "published",
            ProjectUpload.id != project.id,
        )
        .first()
    )
    if duplicate:
        return "Já existe release publicada para este pacote e versão"
    return None


def _write_upload_to_temp(file_storage) -> tuple[str, int, str]:
    fd, temp_path = tempfile.mkstemp(prefix="gatestack-upload-", suffix=".zip")
    sha256 = hashlib.sha256()
    total = 0
    try:
        with os.fdopen(fd, "wb") as handle:
            while True:
                chunk = file_storage.stream.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise ValueError("Arquivo excede 25 MB")
                sha256.update(chunk)
                handle.write(chunk)
    except Exception:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise

    if total == 0:
        os.remove(temp_path)
        raise ValueError("Arquivo vazio")

    return temp_path, total, sha256.hexdigest()


def _validate_zip_file(temp_path: str) -> tuple[int, int]:
    dangerous_exts = {".exe", ".dll", ".bat", ".cmd", ".sh", ".ps1", ".msi"}
    try:
        with zipfile.ZipFile(temp_path, "r") as archive:
            entries = archive.infolist()
            if not entries:
                raise ValueError("Arquivo .zip vazio")
            if len(entries) > MAX_ZIP_ENTRIES:
                raise ValueError("Arquivo .zip contém entradas demais")
            broken_member = archive.testzip()
            if broken_member:
                raise ValueError(f"Arquivo .zip corrompido: {broken_member}")

            total_uncompressed = 0
            file_entries = 0
            for info in entries:
                path = Path(info.filename)
                if path.is_absolute() or ".." in path.parts:
                    raise ValueError("Arquivo .zip contém caminhos inválidos")
                if len(path.parts) > 8:
                    raise ValueError("Arquivo .zip contém diretórios muito profundos")
                if info.is_dir():
                    continue
                if path.suffix.lower() in dangerous_exts:
                    raise ValueError("Arquivo .zip contém extensão não permitida")
                file_entries += 1
                total_uncompressed += info.file_size
                if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                    raise ValueError(
                        "Arquivo .zip excede o limite de conteúdo descompactado"
                    )
            if file_entries == 0:
                raise ValueError("Arquivo .zip não contém arquivos válidos")
            return file_entries, total_uncompressed
    except zipfile.BadZipFile as exc:
        raise ValueError("Arquivo .zip inválido") from exc


def _base_project_query(db, role_name: str):
    query = db.query(ProjectUpload)
    if role_name == "owner" and request.args.get("scope") == "all":
        return query

    shared_project_grants = (
        db.query(ProjectShareGrant)
        .filter(ProjectShareGrant.grantee_user_id == getattr(g, "user_id", None))
        .all()
    )
    shared_ids = [
        grant.project_id
        for grant in shared_project_grants
        if _grant_is_active(grant)
    ]
    team_ids = _current_user_team_ids(db)
    team_project_ids = []
    if team_ids:
        team_project_ids = [
            grant.project_id
            for grant in (
                db.query(ProjectTeamGrant)
                .filter(ProjectTeamGrant.team_id.in_(team_ids))
                .all()
            )
            if _grant_is_active(grant)
        ]
    return query.filter(
        or_(
            ProjectUpload.user_id == getattr(g, "user_id", None),
            and_(
                ProjectUpload.visibility == "public",
                ProjectUpload.lifecycle_status.in_(tuple(PUBLISHED_STATUSES)),
            ),
            and_(
                ProjectUpload.visibility == "shared",
                ProjectUpload.id.in_(shared_ids or [""]),
            ),
            and_(
                ProjectUpload.visibility == "shared",
                ProjectUpload.id.in_(team_project_ids or [""]),
            ),
        )
    )


def _apply_list_filters(query):
    search = (request.args.get("search") or "").strip()
    if search:
        like = f"%{search}%"
        query = query.filter(
            or_(
                ProjectUpload.filename.ilike(like),
                ProjectUpload.package_name.ilike(like),
                ProjectUpload.package_version.ilike(like),
                ProjectUpload.description.ilike(like),
                ProjectUpload.changelog.ilike(like),
                ProjectUpload.checksum_sha256.ilike(like),
            )
        )

    for arg_name, column in (
        ("visibility", ProjectUpload.visibility),
        ("status", ProjectUpload.lifecycle_status),
        ("package_name", ProjectUpload.package_name),
        ("package_version", ProjectUpload.package_version),
        ("checksum_sha256", ProjectUpload.checksum_sha256),
    ):
        value = (request.args.get(arg_name) or "").strip()
        if value:
            query = query.filter(column == value)

    sort_by = (request.args.get("sort_by") or "created_at").strip()
    sort_dir = (request.args.get("sort_dir") or "desc").strip().lower()
    sortable = {
        "created_at": ProjectUpload.created_at,
        "package_name": ProjectUpload.package_name,
        "package_version": ProjectUpload.package_version,
        "download_count": ProjectUpload.download_count,
    }
    column = sortable.get(sort_by, ProjectUpload.created_at)
    query = query.order_by(column.asc() if sort_dir == "asc" else column.desc())
    return query


@projects_bp.route("/upload", methods=["POST"])
@require_auth
@require_permission("projects:write")
def upload_project():
    file = request.files.get("file")
    if not file:
        return _json_response_fail("Arquivo obrigatório")

    filename = (file.filename or "").strip()
    if not filename.lower().endswith(".zip"):
        return _json_response_fail("Envie um arquivo .zip")

    package_name = (
        request.form.get("package_name") or Path(filename).stem or "default-package"
    ).strip()
    package_version = (request.form.get("package_version") or "1.0.0").strip()
    description = (request.form.get("description") or "").strip() or None
    changelog = (request.form.get("changelog") or "").strip() or None
    visibility = (request.form.get("visibility") or "private").strip().lower()
    metadata = _parse_metadata(request.form.get("metadata"))
    shared_with = _normalize_shared_with(request.form.get("shared_with"))

    if not _validate_package_name(package_name):
        return _json_response_fail("Nome do pacote inválido")
    if not _validate_version(package_version):
        return _json_response_fail("Versão inválida")
    if visibility not in ALLOWED_VISIBILITY:
        return _json_response_fail("Visibilidade inválida")
    if visibility == "shared" and not shared_with:
        return _json_response_fail("Informe utilizadores para compartilhamento")
    if not SUPABASE_BUCKET:
        return _json_response_fail("Supabase bucket não configurado", 500)

    db = SessionLocal()
    temp_path = None
    try:
        role_name = _current_user_role(db)
        temp_path, size_bytes, checksum_sha256 = _write_upload_to_temp(file)
        zip_entry_count, uncompressed_size_bytes = _validate_zip_file(temp_path)

        existing_duplicate = (
            db.query(ProjectUpload)
            .filter_by(user_id=g.user_id, checksum_sha256=checksum_sha256)
            .order_by(ProjectUpload.created_at.desc())
            .first()
        )
        if existing_duplicate:
            return _json_response_ok(
                project=_serialize_project(existing_duplicate),
                deduplicated=True,
            )

        lifecycle_status = "approved" if role_name == "owner" else "draft"
        storage_key = (
            f"projects/{g.user_id}/{package_name}/{package_version}/"
            f"{uuid.uuid4()}-{filename}"
        )

        with open(temp_path, "rb") as handle:
            upload_file_to_supabase(
                SUPABASE_BUCKET,
                storage_key,
                handle,
                file.mimetype or "application/zip",
            )

        item = ProjectUpload(
            user_id=g.user_id,
            package_name=package_name,
            package_version=package_version,
            filename=filename,
            description=description,
            changelog=changelog,
            content_type=file.mimetype,
            size_bytes=size_bytes,
            checksum_sha256=checksum_sha256,
            storage_key=storage_key,
            bucket=SUPABASE_BUCKET,
            visibility=visibility,
            lifecycle_status=lifecycle_status,
            shared_with=",".join(str(user_id) for user_id in shared_with) or None,
            metadata_json=json.dumps(metadata, ensure_ascii=True) if metadata else None,
            zip_entry_count=zip_entry_count,
            uncompressed_size_bytes=uncompressed_size_bytes,
        )
        _stamp_status_timestamp(item, lifecycle_status)
        db.add(item)
        db.flush()
        _sync_share_grants(db, item, shared_with)
        _record_status_event(db, item, None, lifecycle_status)
        db.commit()
        db.refresh(item)
        scan_job_id = enqueue_async_job(
            job_type="project_scan",
            project_id=item.id,
            created_by_user_id=g.user_id,
            priority=20,
        )

        _log_event(
            "projects.upload",
            {
                "project_id": item.id,
                "package_name": package_name,
                "package_version": package_version,
                "checksum_sha256": checksum_sha256,
                "visibility": visibility,
                "lifecycle_status": lifecycle_status,
            },
        )
        return _json_response_ok(
            project=_serialize_project(item),
            deduplicated=False,
            scan_job_id=scan_job_id,
        )
    except ValueError as exc:
        return _json_response_fail(str(exc))
    except Exception as exc:
        db.rollback()
        return _json_response_fail(str(exc), 500)
    finally:
        db.close()
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


@projects_bp.route("/list", methods=["GET"])
@require_auth
@require_permission("projects:read")
def list_projects():
    db = SessionLocal()
    try:
        role_name = _current_user_role(db)
        query = _apply_list_filters(_base_project_query(db, role_name))

        user_id = (request.args.get("user_id") or "").strip()
        if user_id and role_name == "owner":
            try:
                query = query.filter(ProjectUpload.user_id == int(user_id))
            except ValueError:
                return _json_response_fail("user_id inválido")

        page = max(int(request.args.get("page", 1)), 1)
        page_size = min(
            max(int(request.args.get("page_size", DEFAULT_PAGE_SIZE)), 1),
            MAX_PAGE_SIZE,
        )
        total = query.count()
        items = query.offset((page - 1) * page_size).limit(page_size).all()
        return _json_response_ok(
            projects=[_serialize_project(item) for item in items],
            pagination={
                "page": page,
                "page_size": page_size,
                "total": total,
                "pages": (total + page_size - 1) // page_size if total else 0,
            },
        )
    finally:
        db.close()


@projects_bp.route("/<project_id>", methods=["GET"])
@require_auth
@require_permission("projects:read")
def get_project(project_id: str):
    db = SessionLocal()
    try:
        role_name = _current_user_role(db)
        project = db.get(ProjectUpload, project_id)
        if not project:
            return _json_response_fail("Projeto não encontrado", 404)
        if not _can_read_project(project, role_name, db):
            return _json_response_fail("Permissões insuficientes", 403)
        events = (
            db.query(ProjectStatusEvent)
            .filter_by(project_id=project.id)
            .order_by(ProjectStatusEvent.created_at.asc())
            .all()
        )
        return _json_response_ok(
            project=_serialize_project(project),
            history=[_serialize_status_event(event) for event in events],
        )
    finally:
        db.close()


@projects_bp.route("/<project_id>", methods=["PATCH"])
@require_auth
@require_permission("projects:write")
def update_project(project_id: str):
    db = SessionLocal()
    try:
        role_name = _current_user_role(db)
        project = db.get(ProjectUpload, project_id)
        if not project:
            return _json_response_fail("Projeto não encontrado", 404)
        if not _can_manage_project(project, role_name):
            return _json_response_fail("Permissões insuficientes", 403)

        payload = request.get_json(silent=True) or {}
        if "description" in payload:
            project.description = (payload.get("description") or "").strip() or None
        if "changelog" in payload:
            project.changelog = (payload.get("changelog") or "").strip() or None
        if "metadata" in payload:
            metadata = payload.get("metadata") or {}
            if not isinstance(metadata, dict):
                return _json_response_fail("metadata inválido")
            project.metadata_json = json.dumps(metadata, ensure_ascii=True)
        if "visibility" in payload:
            visibility = (payload.get("visibility") or "").strip().lower()
            if visibility not in ALLOWED_VISIBILITY:
                return _json_response_fail("Visibilidade inválida")
            project.visibility = visibility
        if "shared_with" in payload:
            shared_with = payload.get("shared_with") or []
            if not isinstance(shared_with, list):
                return _json_response_fail("shared_with inválido")
            normalized = sorted({int(item) for item in shared_with if str(item).strip()})
            project.shared_with = ",".join(str(item) for item in normalized) or None
            _sync_share_grants(db, project, normalized)

        if "share_grants" in payload:
            share_grants = payload.get("share_grants") or []
            if not isinstance(share_grants, list):
                return _json_response_fail("share_grants inválido")
            normalized_share_grants = []
            normalized_ids = []
            for grant in share_grants:
                if not isinstance(grant, dict) or "user_id" not in grant:
                    return _json_response_fail("share_grants inválido")
                user_id = int(grant["user_id"])
                normalized_ids.append(user_id)
                normalized_share_grants.append(
                    {
                        "user_id": user_id,
                        "grant_role": (grant.get("grant_role") or "viewer").strip(),
                        "expires_at": grant.get("expires_at"),
                    }
                )
            project.shared_with = ",".join(str(item) for item in sorted(set(normalized_ids))) or None
            _sync_share_grants(db, project, normalized_share_grants)

        if "team_grants" in payload:
            team_grants = payload.get("team_grants") or []
            if not isinstance(team_grants, list):
                return _json_response_fail("team_grants inválido")
            normalized_team_grants = []
            for grant in team_grants:
                if not isinstance(grant, dict) or not str(grant.get("team_id") or "").strip():
                    return _json_response_fail("team_grants inválido")
                normalized_team_grants.append(
                    {
                        "team_id": str(grant["team_id"]).strip(),
                        "grant_role": (grant.get("grant_role") or "viewer").strip(),
                        "expires_at": grant.get("expires_at"),
                    }
                )
            _sync_team_grants(db, project, normalized_team_grants)

        if "lifecycle_status" in payload:
            new_status = (payload.get("lifecycle_status") or "").strip().lower()
            reason = (payload.get("status_reason") or "").strip() or None
            if new_status not in ALLOWED_STATUS:
                return _json_response_fail("Estado inválido")
            if not _validate_status_transition(role_name, project.lifecycle_status, new_status):
                return _json_response_fail("Transição de estado inválida", 403)
            release_rule_error = _validate_release_rules(db, project, role_name, new_status)
            if release_rule_error:
                return _json_response_fail(release_rule_error, 403)
            previous = project.lifecycle_status
            project.lifecycle_status = new_status
            project.status_reason = reason
            if role_name == "owner":
                project.reviewed_by = g.user_id
                project.reviewed_at = _utcnow()
            _stamp_status_timestamp(project, new_status)
            _record_status_event(db, project, previous, new_status, reason)

        if project.lifecycle_status != "published":
            project.is_latest = False
        db.commit()
        _set_latest_flags(db, project.package_name)
        db.commit()

        return _json_response_ok(project=_serialize_project(project))
    except ValueError:
        db.rollback()
        return _json_response_fail("shared_with inválido")
    finally:
        db.close()


@projects_bp.route("/<project_id>", methods=["DELETE"])
@require_auth
@require_permission("projects:write")
def delete_project(project_id: str):
    db = SessionLocal()
    try:
        role_name = _current_user_role(db)
        project = db.get(ProjectUpload, project_id)
        if not project:
            return _json_response_fail("Projeto não encontrado", 404)
        if not _can_manage_project(project, role_name):
            return _json_response_fail("Permissões insuficientes", 403)
        delete_from_supabase(project.bucket, project.storage_key)
        db.query(ProjectStatusEvent).filter_by(project_id=project_id).delete()
        db.delete(project)
        db.commit()
        _log_event("projects.delete", {"project_id": project_id})
        return _json_response_ok(msg="Projeto removido")
    except Exception as exc:
        db.rollback()
        return _json_response_fail(str(exc), 500)
    finally:
        db.close()


@projects_bp.route("/<project_id>/download", methods=["GET"])
@require_auth
@require_permission("projects:read")
def download_project(project_id: str):
    db = SessionLocal()
    try:
        role_name = _current_user_role(db)
        project = db.get(ProjectUpload, project_id)
        if not project:
            return _json_response_fail("Projeto não encontrado", 404)
        if not _can_read_project(project, role_name, db):
            return _json_response_fail("Permissões insuficientes", 403)
        if (
            project.lifecycle_status not in PUBLISHED_STATUSES
            and role_name != "owner"
            and project.user_id != g.user_id
        ):
            return _json_response_fail("Projeto não disponível para download", 403)

        expires_in = min(max(int(request.args.get("expires_in", 900)), 60), 3600)
        signed_url = create_signed_download_url(
            project.bucket,
            project.storage_key,
            expires_in=expires_in,
        )
        project.download_count = (project.download_count or 0) + 1
        db.commit()
        return _json_response_ok(
            download_url=signed_url,
            expires_in=expires_in,
            project=_serialize_project(project),
        )
    finally:
        db.close()


@projects_bp.route("/<project_id>/history", methods=["GET"])
@require_auth
@require_permission("projects:read")
def get_project_history(project_id: str):
    db = SessionLocal()
    try:
        role_name = _current_user_role(db)
        project = db.get(ProjectUpload, project_id)
        if not project:
            return _json_response_fail("Projeto não encontrado", 404)
        if not _can_read_project(project, role_name, db):
            return _json_response_fail("Permissões insuficientes", 403)
        events = (
            db.query(ProjectStatusEvent)
            .filter_by(project_id=project.id)
            .order_by(ProjectStatusEvent.created_at.asc())
            .all()
        )
        return _json_response_ok(history=[_serialize_status_event(event) for event in events])
    finally:
        db.close()


@projects_bp.route("/package/<package_name>/versions", methods=["GET"])
@require_auth
@require_permission("projects:read")
def package_versions(package_name: str):
    db = SessionLocal()
    try:
        role_name = _current_user_role(db)
        query = _base_project_query(db, role_name).filter(
            ProjectUpload.package_name == package_name
        )
        versions = query.all()
        versions.sort(key=lambda item: _parse_semver(item.package_version), reverse=True)
        return _json_response_ok(
            package_name=package_name,
            versions=[_serialize_project(item) for item in versions],
        )
    finally:
        db.close()


def _public_query(db):
    return db.query(ProjectUpload).filter(
        ProjectUpload.visibility == "public",
        ProjectUpload.lifecycle_status == "published",
    )


@public_packages_bp.route("", methods=["GET"])
def public_catalog():
    db = SessionLocal()
    try:
        query = _public_query(db)
        search = (request.args.get("search") or "").strip()
        if search:
            like = f"%{search}%"
            query = query.filter(
                or_(
                    ProjectUpload.package_name.ilike(like),
                    ProjectUpload.description.ilike(like),
                    ProjectUpload.changelog.ilike(like),
                )
            )
        page = max(int(request.args.get("page", 1)), 1)
        page_size = min(
            max(int(request.args.get("page_size", DEFAULT_PAGE_SIZE)), 1),
            MAX_PAGE_SIZE,
        )
        latest_only = request.args.get("latest", "1").strip() != "0"
        if latest_only:
            query = query.filter(ProjectUpload.is_latest.is_(True))
        total = query.count()
        items = (
            query.order_by(ProjectUpload.package_name.asc(), ProjectUpload.package_version.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )
        return _json_response_ok(
            packages=[_serialize_project(item) for item in items],
            pagination={
                "page": page,
                "page_size": page_size,
                "total": total,
                "pages": (total + page_size - 1) // page_size if total else 0,
            },
        )
    finally:
        db.close()


@public_packages_bp.route("/<package_name>", methods=["GET"])
def public_package_detail(package_name: str):
    db = SessionLocal()
    try:
        versions = _public_query(db).filter(ProjectUpload.package_name == package_name).all()
        if not versions:
            return _json_response_fail("Pacote não encontrado", 404)
        versions.sort(key=lambda item: _parse_semver(item.package_version), reverse=True)
        latest = next((item for item in versions if item.is_latest), versions[0])
        return _json_response_ok(
            package_name=package_name,
            latest=_serialize_project(latest),
            versions=[_serialize_project(item) for item in versions],
        )
    finally:
        db.close()


@public_packages_bp.route("/<package_name>/latest", methods=["GET"])
def public_package_latest(package_name: str):
    db = SessionLocal()
    try:
        item = (
            _public_query(db)
            .filter(ProjectUpload.package_name == package_name, ProjectUpload.is_latest.is_(True))
            .first()
        )
        if not item:
            return _json_response_fail("Pacote não encontrado", 404)
        return _json_response_ok(package_name=package_name, release=_serialize_project(item))
    finally:
        db.close()


@public_packages_bp.route("/<package_name>/versions/<package_version>", methods=["GET"])
def public_package_version_detail(package_name: str, package_version: str):
    db = SessionLocal()
    try:
        item = (
            _public_query(db)
            .filter_by(package_name=package_name, package_version=package_version)
            .first()
        )
        if not item:
            return _json_response_fail("Release não encontrada", 404)
        return _json_response_ok(release=_serialize_project(item))
    finally:
        db.close()


@public_packages_bp.route("/<package_name>/versions/<package_version>/download", methods=["GET"])
def public_package_version_download(package_name: str, package_version: str):
    db = SessionLocal()
    try:
        item = (
            _public_query(db)
            .filter_by(package_name=package_name, package_version=package_version)
            .first()
        )
        if not item:
            return _json_response_fail("Release não encontrada", 404)
        expires_in = min(max(int(request.args.get("expires_in", 900)), 60), 3600)
        signed_url = create_signed_download_url(item.bucket, item.storage_key, expires_in)
        item.download_count = (item.download_count or 0) + 1
        db.commit()
        return _json_response_ok(
            package_name=package_name,
            package_version=package_version,
            download_url=signed_url,
            expires_in=expires_in,
            release=_serialize_project(item),
        )
    finally:
        db.close()
