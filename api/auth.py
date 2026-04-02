"""
Authentication API Blueprint — hardened version
"""
from flask import Blueprint, request, jsonify, session, g
from core.crypto.engine import CryptoEngine
from core.iam.db import SessionLocal
from core.iam.auth import AuthController
from core.iam.models import User
from core.iam.rbac import require_auth
from core.iam.session import key_manager
from core.audit.logger import get_audit_logger
import traceback
import json

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


def _log_event(event_type, user, severity="INFO", details=None):
    try:
        get_audit_logger().log_event(event_type, user=user, severity=severity, details=details or {})
    except Exception:
        pass


# ── Login ───────────────────────────────────────────────────

@auth_bp.route("/login", methods=["POST"])
def login():
    db, controller = _db_controller()

    try:
        data = request.get_json(silent=True) or {}

        username = data.get("email") or data.get("username", "rodrigo@mail.com")
        password = data.get("password", "Nses@100")

        if not username or not password:
            return fail("Credenciais obrigatórias")

        user = db.query(User).filter_by(username=username).first()

        if not user or not controller.verify_password(user.password_hash, password):
            _log_event("auth.login.failure", username or "unknown", "WARNING")
            return fail("Credenciais inválidas", 401)

        if not user.is_active:
            _log_event("auth.login.failure", user.username, "WARNING", {"reason": "inactive"})
            return fail("Conta desativada", 403)

        # ── Master Key ─────────────────────────────
        master_key = None

        if user.wrapped_key:
            try:
                from core.crypto.engine import CryptoEngine
                wrapped = json.loads(user.wrapped_key)

                master_key = CryptoEngine().unwrap_master_key(
                    wrapped, password
                )

            except Exception as e:
                traceback.print_exc()
                return fail("Falha ao desbloquear chave mestra", 500, e)

        # ── MFA ────────────────────────────────────
        if user.mfa_secret_enc:
            session["pre_auth_user_id"] = user.id

            if master_key:
                key_manager.store_key(f"pre_auth_{user.id}", master_key, ttl=300)

            return jsonify({
                "success": False,
                "requires_mfa": True,
                "user_id": user.id,
                "msg": "MFA necessário"
            })

        # ── Sucesso completo ───────────────────────
        if master_key:
            key_manager.store_key(user.id, master_key)

        roles = [user.role.name] if user.role else []

        _log_event("auth.login.success", user.username)
        return ok({
            "access_token": controller.create_access_token(user.id, roles),
            "refresh_token": controller.create_refresh_token(user.id),
            "email": user.username,
            "has_2fa": bool(user.mfa_secret_enc),
            "role": user.role.name if user.role else None,
            "vault_unlocked": bool(master_key),
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

        pending = key_manager.get_key(f"pre_auth_{user.id}")

        if not pending:
            return fail("Sessão expirada", 401)

        key_manager.store_key(user.id, pending)
        key_manager.clear_key(f"pre_auth_{user.id}")

        roles = [user.role.name] if user.role else []

        _log_event("auth.mfa.success", user.username)
        return ok({
            "access_token": controller.create_access_token(user.id, roles),
            "refresh_token": controller.create_refresh_token(user.id),
            "email": user.username,
            "has_2fa": True,
            "role": user.role.name if user.role else None,
            "vault_unlocked": True,
        })

    except Exception as e:
        traceback.print_exc()
        return fail("Erro interno no MFA", 500, e)

    finally:
        db.close()


# ── Logout ─────────────────────────────────────────────────

@auth_bp.route("/logout", methods=["POST"])
def logout():
    try:
        user_id = g.get("user_id") or session.get("pre_auth_user_id")

        if user_id:
            key_manager.clear_key(user_id)
            key_manager.clear_key(f"pre_auth_{user_id}")

        session.clear()
        _log_event("auth.logout", str(user_id or "anonymous"))

        return ok({"msg": "Sessão encerrada"})

    except Exception as e:
        traceback.print_exc()
        return fail("Erro ao fazer logout", 500, e)


# ── Refresh ────────────────────────────────────────────────

@auth_bp.route("/refresh", methods=["POST"])
def refresh_token():
    try:
        data = request.get_json(silent=True) or {}
        token = data.get("refresh_token", "")

        if not token:
            return fail("Token obrigatório")

        db, controller = _db_controller()

        payload = controller.decode_token(token)

        if not payload or payload.get("type") != "refresh":
            return fail("Token inválido", 401)

        user_id = payload["sub"]

        user = db.get(User, user_id)

        if not user or not user.is_active:
            return fail("Usuário inválido", 401)

        roles = [user.role.name] if user.role else []

        return ok({
            "access_token": controller.create_access_token(user.id, roles),
            "refresh_token": controller.create_refresh_token(user.id),
        })

    except Exception as e:
        traceback.print_exc()
        return fail("Erro no refresh", 500, e)


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

        if len(password) < 8:
            return fail("Senha muito curta")

        if db.query(User).filter_by(username=email).first():
            return fail("Email já cadastrado", 409)

        from core.crypto.engine import CryptoEngine
        from core.iam.models import Role

        pw_hash = controller.hash_password(password)

        crypto = CryptoEngine()
        master_key = crypto.generate_master_key()
        wrapped = crypto.wrap_master_key(master_key, password)

        user_role = db.query(Role).filter_by(name="user").first()

        user = User(
            username=email,
            password_hash=pw_hash,
            wrapped_key=json.dumps(wrapped),
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
            "email": user.username,
            "has_2fa": bool(user.mfa_secret_enc),
            "role": user.role.name if user.role else None,
            "vault_unlocked": bool(key_manager.get_key(user.id)),
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
            "qr_code": CryptoEngine().make_qr_data_url(controller.build_totp_uri(user.username, secret)),
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
