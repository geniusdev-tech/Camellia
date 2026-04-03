"""
GateStack — Flask Backend
Serves the REST API consumed by the Next.js/Tauri frontend.
"""
import os
import secrets
import logging
from warnings import filterwarnings
from flask import Flask, jsonify, request
from dotenv import load_dotenv

from config import DevelopmentConfig, ProductionConfig

filterwarnings("ignore", category=UserWarning, module="webview.guilib")
filterwarnings("ignore", message=".*in-memory storage.*", category=UserWarning)

load_dotenv()

from core.logging.json_logger import configure_json_logging
from core.observability import install_request_observability
from core.async_jobs import start_async_job_worker
from core.audit.logger import init_audit_logger
from core.iam.db import init_db

try:
    import redis
except ImportError:  # pragma: no cover - redis optional
    redis = None  # type: ignore[assignment]

try:
    from flask_session import Session
except ImportError:  # pragma: no cover - session optional
    Session = None  # type: ignore[assignment]

session_extension = Session() if Session is not None else None

try:
    from flask_talisman import Talisman
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    from flask_seasurf import SeaSurf
except Exception:
    Talisman = Limiter = get_remote_address = SeaSurf = None  # type: ignore[assignment,misc]


def _runtime_writable_root() -> str:
    if os.getenv("VERCEL"):
        return "/tmp"
    return os.getcwd()


def _allowed_origins() -> set[str]:
    raw = os.getenv("ALLOWED_ORIGIN", "")
    return {item.strip() for item in raw.split(",") if item.strip()}


def create_app() -> Flask:
    app = Flask(__name__)
    init_db()
    install_request_observability(app)

    env = os.getenv("FLASK_ENV", "production").lower()
    desktop_mode = os.getenv("DESKTOP_MODE", "0").lower() in ("1", "true", "yes")
    is_vercel = bool(os.getenv("VERCEL"))

    if env == "development":
        app.config.from_object(DevelopmentConfig)
    else:
        app.config.from_object(ProductionConfig)

    # SECRET_KEY
    secret = os.getenv("SECRET_KEY") or app.config.get("SECRET_KEY")
    if secret:
        app.secret_key = secret
    elif env == "development" or desktop_mode:
        app.secret_key = secrets.token_hex(32)
        logging.getLogger(__name__).debug("Using temporary SECRET_KEY.")
    else:
        raise RuntimeError("SECRET_KEY environment variable is required in production.")

    # ── Session / Redis helpers ───────────────────────
    redis_url = os.getenv("REDIS_URL")
    limiter_storage = os.getenv("LIMITER_STORAGE_URI") or redis_url
    redis_client = None

    if redis is not None and redis_url:
        redis_client = redis.from_url(redis_url, decode_responses=True)
        if session_extension is not None:
            app.config["SESSION_TYPE"] = "redis"
            app.config["SESSION_REDIS"] = redis_client
    elif session_extension is not None:
        app.config.setdefault("SESSION_TYPE", "filesystem")

    if Session is not None and session_extension is not None:
        session_extension.init_app(app)

    # ── Blueprints ────────────────────────────────────
    from api.auth import auth_bp
    from api.projects import projects_bp, public_packages_bp
    from api.access import access_bp
    from api.audit import audit_bp
    from api.ops import ops_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(projects_bp)
    app.register_blueprint(public_packages_bp)
    app.register_blueprint(access_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(ops_bp)

    # ── Security middleware ───────────────────────────
    if Talisman is not None and not desktop_mode and env != "development":
        csp = {
            "default-src": ["'self'"],
            "script-src":  ["'self'"],
            "style-src":   ["'self'", "'unsafe-inline'"],
            "img-src":     ["'self'", "data:"],
            "connect-src": ["'self'"],
        }
        Talisman(
            app,
            content_security_policy=csp,
            force_https=False,          # TLS terminated upstream (reverse proxy / Tauri)
            strict_transport_security=False,
        )

    if Limiter is not None and get_remote_address is not None:
        if desktop_mode or env == "development":
            limits = ["100000 per day", "20000 per hour"]
        else:
            limits = ["2000 per day", "500 per hour"]
        limiter_kwargs: dict[str, object] = {
            "key_func": get_remote_address,
            "app": app,
            "default_limits": limits,
        }
        if limiter_storage:
            limiter_kwargs["storage_uri"] = limiter_storage
        Limiter(**limiter_kwargs)

    if SeaSurf is not None and not desktop_mode and env not in ("development",):
        csrf = SeaSurf(app)
        csrf.exempt(auth_bp)
        csrf.exempt(projects_bp)
        csrf.exempt(audit_bp)

    # ── Logging ───────────────────────────────────────
    siem = os.getenv("SIEM_ENDPOINT")
    configure_json_logging(siem_endpoint=siem)

    audit_path = os.getenv("AUDIT_LOG_PATH", os.path.join(_runtime_writable_root(), "audit.log"))
    try:
        init_audit_logger(audit_path)
    except Exception:
        pass

    # ── Health-check ──────────────────────────────────
    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "version": "2.1.0"})

    # ── CORS headers (Tauri / dev only) ───────────────
    @app.after_request
    def add_cors(response):
        origin = request.headers.get("Origin", "").strip()
        if (desktop_mode or env == "development") and not is_vercel:
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            return response

        allowed_origins = _allowed_origins()
        if origin and origin in allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            response.headers["Access-Control-Allow-Credentials"] = "true"
        return response

    @app.route("/api/<path:path>", methods=["OPTIONS"])
    def options_handler(path):
        return "", 204

    start_async_job_worker()

    return app


app = create_app()

if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    port  = int(os.getenv("PORT", 5000))
    host  = os.getenv("HOST", "127.0.0.1")  # Bind only localhost by default
    app.run(host=host, port=port, debug=debug)
