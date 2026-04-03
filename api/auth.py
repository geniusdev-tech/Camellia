"""
Authentication API Blueprint — hardened version
"""
import base64
import re
from io import BytesIO
from datetime import datetime, timezone

import qrcode
from flask import Blueprint, request, jsonify, session, g
from core.iam.db import SessionLocal
from core.iam.auth import AuthController
from core.iam.models import RefreshTokenSession, Role, User
from core.iam.rbac import require_auth
from core.audit.logger import get_audit_logger
import traceback

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


# ── Helpers ─────────────────────────────────────────────────

def ok(data=None):
    return jsonify({"success": True, **(data or {})})

def fail(msg, code=400, error=None):
    return jsonify({
        "success": False,
        "msg": msg,
        "error": str(error) if error else None
    }), code


def _db_controller():
    db = SessionLocal()
    return db, AuthController(db)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _password_error(password: str) -> str | None:
    if len(password) < 12:
        return "Senha deve ter pelo menos 12 caracteres"
    if not re.search(r"[A-Z]", password):
        return "Senha deve conter ao menos uma letra maiúscula"
    if not re.search(r"[a-z]", password):
        return "Senha deve conter ao menos uma letra minúscula"
    if not re.search(r"[0-9]", password):
        return "Senha deve conter ao menos um número"
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Senha deve conter ao menos um caractere especial"
    return None


def _create_refresh_session(db, payload, user_id: int) -> RefreshTokenSession:
    session_row = RefreshTokenSession(
        user_id=user_id,
        token_jti=payload["jti"],
        token_type="refresh",
        issued_at=_utcnow(),
        expires_at=datetime.fromtimestamp(payload["exp"], timezone.utc).isoformat(),
        user_agent=request.headers.get("User-Agent"),
        ip_address=request.headers.get("X-Forwarded-For", request.remote_addr),
    )
    db.add(session_row)
    db.commit()
    return session_row


def _revoke_refresh_session(db, token_jti: str, replaced_by_jti: str | None = None) -> None:
    session_row = db.query(RefreshTokenSession).filter_by(token_jti=token_jti).first()
    if not session_row or session_row.revoked_at:
        return
    session_row.revoked_at = _utcnow()
    session_row.replaced_by_jti = replaced_by_jti
    db.commit()


def _log_event(event_type, user, severity="INFO", details=None):
    try:
        get_audit_logger().log_event(event_type, user=user, severity=severity, details=details or {})
    except Exception:
        pass


def _make_qr_data_url(value: str) -> str:
    buffer = BytesIO()
    qrcode.make(value).save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


# ── Login ───────────────────────────────────────────────────

@auth_bp.route("/login", methods=["POST"])
def login():
    db, controller = _db_controller()

    try:
        data = request.get_json(silent=True) or {}

        username = (data.get("email") or data.get("username") or "").strip()
        password = data.get("password", "")

        if not username or not password:
            return fail("Credenciais obrigatórias")

        user = db.query(User).filter_by(username=username).first()

        if not user or not controller.verify_password(user.password_hash, password):
            _log_event("auth.login.failure", username or "unknown", "WARNING")
            return fail("Credenciais inválidas", 401)

        if not user.is_active:
            _log_event("auth.login.failure", user.username, "WARNING", {"reason": "inactive"})
            return fail("Conta desativada", 403)

        # ── MFA ────────────────────────────────────
        if user.mfa_secret_enc:
            session["pre_auth_user_id"] = user.id
            return jsonify({
                "success": False,
                "requires_mfa": True,
                "user_id": user.id,
                "msg": "MFA necessário"
            })

        roles = [user.role.name] if user.role else []
        refresh_token = controller.create_refresh_token(user.id)
        refresh_payload = controller.decode_token(refresh_token)
        if not refresh_payload:
            return fail("Erro ao gerar sessão", 500)
        _create_refresh_session(db, refresh_payload, user.id)

        _log_event("auth.login.success", user.username)
        return ok({
            "access_token": controller.create_access_token(user.id, roles),
            "refresh_token": refresh_token,
            "email": user.username,
            "has_2fa": bool(user.mfa_secret_enc),
            "role": user.role.name if user.role else None,
        })

    except Exception as e:
        traceback.print_exc()
        return fail("Erro interno no login", 500, e)

    finally:
        db.close()


# ── Login MFA ───────────────────────────────────────────────

@auth_bp.route("/login/mfa", methods=["POST"])
def login_mfa():
    db, controller = _db_controller()

    try:
        data = request.get_json(silent=True) or {}
        code = data.get("code", "")
        user_id = session.get("pre_auth_user_id") or data.get("user_id")

        if not user_id:
            return fail("Sessão inválida", 401)

        user = db.get(User, user_id)

        if not user or not user.mfa_secret_enc:
            return fail("Erro na validação MFA")

        if not controller.verify_totp_token(user.mfa_secret_enc, code):
            _log_event("auth.mfa.failure", user.username, "WARNING")
            return fail("Código MFA inválido", 401)

        session.pop("pre_auth_user_id", None)

        roles = [user.role.name] if user.role else []
        refresh_token = controller.create_refresh_token(user.id)
        refresh_payload = controller.decode_token(refresh_token)
        if not refresh_payload:
            return fail("Erro ao gerar sessão", 500)
        _create_refresh_session(db, refresh_payload, user.id)

        _log_event("auth.mfa.success", user.username)
        return ok({
            "access_token": controller.create_access_token(user.id, roles),
            "refresh_token": refresh_token,
            "email": user.username,
            "has_2fa": True,
            "role": user.role.name if user.role else None,
        })

    except Exception as e:
        traceback.print_exc()
        return fail("Erro interno no MFA", 500, e)

    finally:
        db.close()


# ── Logout ─────────────────────────────────────────────────

@auth_bp.route("/logout", methods=["POST"])
def logout():
    db = SessionLocal()
    try:
        user_id = g.get("user_id") or session.get("pre_auth_user_id")
        data = request.get_json(silent=True) or {}
        refresh_token = data.get("refresh_token", "")

        if refresh_token:
            controller = AuthController(db)
            payload = controller.decode_token(refresh_token)
            if payload and payload.get("type") == "refresh" and payload.get("jti"):
                _revoke_refresh_session(db, payload["jti"])

        session.clear()
        _log_event("auth.logout", str(user_id or "anonymous"))

        return ok({"msg": "Sessão encerrada"})

    except Exception as e:
        traceback.print_exc()
        return fail("Erro ao fazer logout", 500, e)
    finally:
        db.close()


@auth_bp.route("/logout-all", methods=["POST"])
@require_auth
def logout_all():
    db = SessionLocal()
    try:
        sessions = db.query(RefreshTokenSession).filter_by(user_id=g.user_id).all()
        now = _utcnow()
        for session_row in sessions:
            session_row.revoked_at = now
        db.commit()
        _log_event("auth.logout_all", str(g.user_id))
        return ok({"msg": "Todas as sessões foram encerradas"})
    finally:
        db.close()


# ── Refresh ────────────────────────────────────────────────

@auth_bp.route("/refresh", methods=["POST"])
def refresh_token():
    db = None
    try:
        data = request.get_json(silent=True) or {}
        token = data.get("refresh_token", "")

        if not token:
            return fail("Token obrigatório")

        db, controller = _db_controller()

        payload = controller.decode_token(token)

        if not payload or payload.get("type") != "refresh" or not payload.get("jti"):
            return fail("Token inválido", 401)

        user_id = payload["sub"]

        user = db.get(User, user_id)

        if not user or not user.is_active:
            return fail("Usuário inválido", 401)

        session_row = db.query(RefreshTokenSession).filter_by(token_jti=payload["jti"]).first()
        if not session_row or session_row.revoked_at:
            _log_event("auth.refresh.failure", str(user_id), "WARNING", {"reason": "revoked_or_missing"})
            return fail("Refresh token revogado", 401)

        roles = [user.role.name] if user.role else []
        new_refresh_token = controller.create_refresh_token(user.id, payload.get("family"))
        new_refresh_payload = controller.decode_token(new_refresh_token)
        if not new_refresh_payload:
            return fail("Erro ao renovar sessão", 500)
        _create_refresh_session(db, new_refresh_payload, user.id)
        _revoke_refresh_session(db, payload["jti"], new_refresh_payload["jti"])

        return ok({
            "access_token": controller.create_access_token(user.id, roles),
            "refresh_token": new_refresh_token,
        })

    except Exception as e:
        traceback.print_exc()
        return fail("Erro no refresh", 500, e)
    finally:
        if db is not None:
            db.close()


# ── Register ───────────────────────────────────────────────

@auth_bp.route("/register", methods=["POST"])
def register():
    db, controller = _db_controller()

    try:
        data = request.get_json(silent=True) or {}

        email = (data.get("email") or "").strip()
        password = data.get("password", "")

        if not email or not password:
            return fail("Email e senha obrigatórios")

        password_error = _password_error(password)
        if password_error:
            return fail(password_error)

        if db.query(User).filter_by(username=email).first():
            return fail("Email já cadastrado", 409)

        user_role = db.query(Role).filter_by(name="user").first()

        user = User(
            username=email,
            password_hash=controller.hash_password(password),
            role=user_role,
            is_active=True,
        )

        db.add(user)
        db.commit()

        return ok({"msg": "Conta criada com sucesso"})

    except Exception as e:
        traceback.print_exc()
        return fail("Erro no registro", 500, e)

    finally:
        db.close()


@auth_bp.route("/status", methods=["GET"])
@require_auth
def status():
    db = SessionLocal()
    try:
        user = db.get(User, getattr(g, "user_id", None))
        if not user:
            return fail("Usuário não encontrado", 404)
        return ok({
            "user_id": user.id,
            "email": user.username,
            "has_2fa": bool(user.mfa_secret_enc),
            "role": user.role.name if user.role else None,
        })
    finally:
        db.close()


@auth_bp.route("/mfa/setup", methods=["POST"])
@require_auth
def mfa_setup():
    db, controller = _db_controller()
    try:
        user = db.get(User, getattr(g, "user_id", None))
        if not user:
            return fail("Usuário não encontrado", 404)

        secret = controller.generate_totp_secret()
        user.mfa_secret_enc = secret
        db.commit()

        return ok({
            "secret": secret,
            "qr_code": _make_qr_data_url(controller.build_totp_uri(user.username, secret)),
        })
    finally:
        db.close()


@auth_bp.route("/mfa/verify", methods=["POST"])
@require_auth
def mfa_verify():
    db, controller = _db_controller()
    try:
        user = db.get(User, getattr(g, "user_id", None))
        if not user or not user.mfa_secret_enc:
            return fail("MFA não configurado", 400)

        code = (request.get_json(silent=True) or {}).get("code", "")
        if not controller.verify_totp_token(user.mfa_secret_enc, code):
            return fail("Código MFA inválido", 401)

        _log_event("auth.mfa.enabled", user.username)
        return ok({"msg": "MFA verificado"})
    finally:
        db.close()


@auth_bp.route("/mfa/disable", methods=["POST"])
@require_auth
def mfa_disable():
    db = SessionLocal()
    try:
        user = db.get(User, getattr(g, "user_id", None))
        if not user:
            return fail("Usuário não encontrado", 404)
        user.mfa_secret_enc = None
        db.commit()
        _log_event("auth.mfa.disabled", user.username)
        return ok({"msg": "MFA desativado"})
    finally:
        db.close()
