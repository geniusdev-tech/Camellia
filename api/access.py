import secrets
from datetime import datetime, timezone

from flask import Blueprint, g, jsonify, request

from core.iam.db import SessionLocal
from core.iam.models import ProjectTeamGrant, ProjectUpload, ShareInvite, Team, TeamMember, User
from core.iam.rbac import require_auth, require_permission


access_bp = Blueprint("access", __name__, url_prefix="/api/access")


def _ok(**payload):
    return jsonify({"success": True, **payload})


def _fail(msg: str, code: int = 400):
    return jsonify({"success": False, "msg": msg}), code


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_team_manager(team: Team, user_id: int, db) -> bool:
    if team.owner_user_id == user_id:
        return True
    membership = (
        db.query(TeamMember)
        .filter_by(team_id=team.id, user_id=user_id)
        .first()
    )
    return bool(membership and membership.role in {"manager", "owner"})


def _serialize_team(team: Team, db) -> dict:
    members = db.query(TeamMember).filter_by(team_id=team.id).all()
    return {
        "id": team.id,
        "name": team.name,
        "owner_user_id": team.owner_user_id,
        "created_at": team.created_at,
        "members": [
            {
                "user_id": item.user_id,
                "role": item.role,
                "created_at": item.created_at,
            }
            for item in members
        ],
    }


@access_bp.route("/teams", methods=["GET"])
@require_auth
@require_permission("projects:read")
def list_teams():
    db = SessionLocal()
    try:
        team_ids = [
            team_id
            for (team_id,) in db.query(TeamMember.team_id).filter_by(user_id=g.user_id).all()
        ]
        teams = (
            db.query(Team)
            .filter((Team.owner_user_id == g.user_id) | (Team.id.in_(team_ids or [""])))
            .order_by(Team.created_at.asc())
            .all()
        )
        return _ok(teams=[_serialize_team(team, db) for team in teams])
    finally:
        db.close()


@access_bp.route("/teams", methods=["POST"])
@require_auth
@require_permission("projects:write")
def create_team():
    db = SessionLocal()
    try:
        payload = request.get_json(silent=True) or {}
        name = (payload.get("name") or "").strip()
        if len(name) < 3:
            return _fail("Nome do time inválido")
        if db.query(Team).filter_by(name=name).first():
            return _fail("Time já existe", 409)

        team = Team(name=name, owner_user_id=g.user_id)
        db.add(team)
        db.flush()
        db.add(TeamMember(team_id=team.id, user_id=g.user_id, role="owner"))
        db.commit()
        db.refresh(team)
        return _ok(team=_serialize_team(team, db))
    finally:
        db.close()


@access_bp.route("/teams/<team_id>/invites", methods=["POST"])
@require_auth
@require_permission("projects:write")
def create_team_invite(team_id: str):
    db = SessionLocal()
    try:
        team = db.get(Team, team_id)
        if not team:
            return _fail("Time não encontrado", 404)
        if not _is_team_manager(team, g.user_id, db):
            return _fail("Permissões insuficientes", 403)

        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip().lower()
        role = (payload.get("role") or "member").strip().lower()
        expires_at = payload.get("expires_at")
        if not email:
            return _fail("Email obrigatório")
        if role not in {"member", "manager"}:
            return _fail("role inválido")

        invite = ShareInvite(
            team_id=team.id,
            email=email,
            role=role,
            token=secrets.token_hex(24),
            expires_at=expires_at,
        )
        db.add(invite)
        db.commit()
        return _ok(
            invite={
                "id": invite.id,
                "team_id": invite.team_id,
                "email": invite.email,
                "role": invite.role,
                "token": invite.token,
                "expires_at": invite.expires_at,
                "accepted_at": invite.accepted_at,
            }
        )
    finally:
        db.close()


@access_bp.route("/invites/<token>/accept", methods=["POST"])
@require_auth
@require_permission("projects:read")
def accept_invite(token: str):
    db = SessionLocal()
    try:
        invite = db.query(ShareInvite).filter_by(token=token).first()
        if not invite:
            return _fail("Convite não encontrado", 404)
        if invite.accepted_at:
            return _fail("Convite já aceito", 409)

        user = db.get(User, g.user_id)
        if not user:
            return _fail("Usuário não encontrado", 404)
        if user.username.lower() != invite.email.lower():
            return _fail("Convite pertence a outro utilizador", 403)
        if invite.expires_at:
            try:
                if datetime.fromisoformat(invite.expires_at) <= datetime.now(timezone.utc):
                    return _fail("Convite expirado", 410)
            except ValueError:
                pass

        existing = (
            db.query(TeamMember)
            .filter_by(team_id=invite.team_id, user_id=user.id)
            .first()
        )
        if not existing:
            db.add(TeamMember(team_id=invite.team_id, user_id=user.id, role=invite.role))
        invite.accepted_at = _utcnow()
        db.commit()

        team = db.get(Team, invite.team_id)
        return _ok(team=_serialize_team(team, db))
    finally:
        db.close()


@access_bp.route("/projects/<project_id>/team-grants", methods=["POST"])
@require_auth
@require_permission("projects:write")
def add_project_team_grant(project_id: str):
    db = SessionLocal()
    try:
        project = db.get(ProjectUpload, project_id)
        if not project:
            return _fail("Projeto não encontrado", 404)
        if project.user_id != g.user_id:
            current_user = db.get(User, g.user_id)
            if not current_user or not current_user.role or current_user.role.name != "owner":
                return _fail("Permissões insuficientes", 403)

        payload = request.get_json(silent=True) or {}
        team_id = str(payload.get("team_id") or "").strip()
        grant_role = (payload.get("grant_role") or "viewer").strip()
        expires_at = payload.get("expires_at")
        if not team_id:
            return _fail("team_id obrigatório")
        if not db.get(Team, team_id):
            return _fail("Time não encontrado", 404)

        existing = (
            db.query(ProjectTeamGrant)
            .filter_by(project_id=project.id, team_id=team_id)
            .first()
        )
        if existing:
            existing.grant_role = grant_role
            existing.expires_at = expires_at
        else:
            db.add(
                ProjectTeamGrant(
                    project_id=project.id,
                    team_id=team_id,
                    grant_role=grant_role,
                    expires_at=expires_at,
                )
            )
        project.visibility = "shared"
        db.commit()
        return _ok(msg="Grant atualizado")
    finally:
        db.close()
