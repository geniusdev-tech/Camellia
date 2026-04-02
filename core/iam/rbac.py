from functools import wraps
from flask import request, jsonify, g
from core.iam.auth import AuthController
from core.iam.db import SessionLocal


def get_auth_controller():
    return AuthController(SessionLocal())


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        token  = header.split(" ")[1] if header.startswith("Bearer ") else None

        if not token:
            return jsonify({"error": "Token ausente"}), 401

        ctrl    = get_auth_controller()
        payload = ctrl.decode_token(token)
        if not payload:
            return jsonify({"error": "Token inválido ou expirado"}), 401

        # Coerce to int so SQLAlchemy .get(User, user_id) works
        try:
            g.user_id = int(payload["sub"])
        except (ValueError, KeyError):
            g.user_id = payload.get("sub")

        g.user_roles = payload.get("roles", [])
        return f(*args, **kwargs)
    return decorated


def require_role(role_name: str):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, "user_roles"):
                return jsonify({"error": "Autenticação necessária"}), 401
            if role_name not in g.user_roles and "owner" not in g.user_roles:
                return jsonify({"error": "Permissões insuficientes"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def require_permission(permission: str):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, "user_id"):
                return jsonify({"error": "Autenticação necessária"}), 401

            db = SessionLocal()
            try:
                from core.iam.models import User
                user = db.get(User, g.user_id)
                if not user:
                    return jsonify({"error": "Utilizador não encontrado"}), 404
                # owner bypasses all permission checks
                if user.role and user.role.name == "owner":
                    return f(*args, **kwargs)
                if not user.has_permission(permission):
                    return jsonify({"error": f"Permissão ausente: {permission}"}), 403
            finally:
                db.close()

            return f(*args, **kwargs)
        return decorated
    return decorator
