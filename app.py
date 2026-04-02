"""
Camellia Shield — Flask Backend
Serves the REST API consumed by the Next.js/Tauri frontend.
"""
import os
import secrets
import logging
from warnings import filterwarnings
from flask import Flask, jsonify
from dotenv import load_dotenv

from config import DevelopmentConfig, ProductionConfig

filterwarnings("ignore", category=UserWarning, module="webview.guilib")
filterwarnings("ignore", message=".*in-memory storage.*", category=UserWarning)

load_dotenv()

from core.logging.json_logger import configure_json_logging
from core.audit.logger import init_audit_logger
from core.kms.file_kms import FileKMS
from core.kms.aws_kms import AWSKMSProvider
from core.iam.db import init_db

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


def create_app() -> Flask:
    app = Flask(__name__)
    init_db()

    env = os.getenv("FLASK_ENV", "production").lower()
    desktop_mode = os.getenv("DESKTOP_MODE", "0").lower() in ("1", "true", "yes")

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

    # ── Blueprints ────────────────────────────────────
    from api.auth import auth_bp
    from api.vault import vault_bp
    from api.audit import audit_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(vault_bp)
    app.register_blueprint(audit_bp)

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
        Limiter(
            key_func=get_remote_address,
            app=app,
            default_limits=limits,
        )

    if SeaSurf is not None and not desktop_mode and env not in ("development",):
        SeaSurf(app)

    # ── Logging ───────────────────────────────────────
    siem = os.getenv("SIEM_ENDPOINT")
    configure_json_logging(siem_endpoint=siem)

    audit_path = os.getenv("AUDIT_LOG_PATH", os.path.join(_runtime_writable_root(), "audit.log"))
    try:
        init_audit_logger(audit_path)
    except Exception:
        pass

    # ── KMS ───────────────────────────────────────────
    kms_provider = os.getenv("KMS_PROVIDER", "file")
    if kms_provider == "file":
        kms_path = os.getenv("KMS_FILE_PATH", os.path.join(_runtime_writable_root(), "kms.key"))
        try:
            app.kms = FileKMS(kms_path)  # type: ignore[attr-defined]
        except Exception:
            app.kms = None  # type: ignore[attr-defined]
    elif kms_provider == "aws":
        aws_key_id = os.getenv("AWS_KMS_KEY_ID")
        aws_region = os.getenv("AWS_REGION")
        try:
            app.kms = AWSKMSProvider(aws_key_id, region_name=aws_region) if aws_key_id else None  # type: ignore[attr-defined]
        except Exception:
            app.kms = None  # type: ignore[attr-defined]
    else:
        app.kms = None  # type: ignore[attr-defined]

    # ── Health-check ──────────────────────────────────
    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "version": "2.1.0"})

    # ── CORS headers (Tauri / dev only) ───────────────
    @app.after_request
    def add_cors(response):
        if desktop_mode or env == "development":
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        return response

    @app.route("/api/<path:path>", methods=["OPTIONS"])
    def options_handler(path):
        return "", 204

    return app


app = create_app()

if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    port  = int(os.getenv("PORT", 5000))
    host  = os.getenv("HOST", "127.0.0.1")  # Bind only localhost by default
    app.run(host=host, port=port, debug=debug)
