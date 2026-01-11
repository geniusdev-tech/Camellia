import os
import secrets
from warnings import warn
from flask import Flask, render_template

from config import DevelopmentConfig, ProductionConfig
from core.logging.json_logger import configure_json_logging
from core.audit.logger import init_audit_logger
from core.kms.file_kms import FileKMS
from core.kms.aws_kms import AWSKMSProvider

# Optional security extensions
try:
    from flask_talisman import Talisman
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    from flask_seasurf import SeaSurf
except Exception:
    Talisman = None
    Limiter = None
    get_remote_address = None
    SeaSurf = None


def create_app():
    app = Flask(__name__)

    # Load configuration based on FLASK_ENV
    env = os.getenv('FLASK_ENV', 'production')
    if env.lower() == 'development':
        app.config.from_object(DevelopmentConfig)
    else:
        app.config.from_object(ProductionConfig)

    # SECRET_KEY must be provided in production
    secret = os.getenv('SECRET_KEY') or app.config.get('SECRET_KEY')
    if not secret:
        # in development only: generate a temporary key but warn
        warn('SECRET_KEY not set; using insecure random key for development. Set SECRET_KEY env in production.')
        app.secret_key = secrets.token_hex(32)
    else:
        app.secret_key = secret

    # Register blueprints
    from api.auth import auth_bp
    from api.vault import vault_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(vault_bp)

    # Desktop mode detection: when running in an embedded webview we
    # may need to relax some security middleware that assume a browser
    # environment with full TLS and CSRF token handling.
    desktop_mode = os.getenv('DESKTOP_MODE', '0').lower() in ('1', 'true', 'yes')

    # Initialize Talisman (CSP/HSTS) only when not in desktop mode
    if Talisman is not None and not desktop_mode:
        csp = {
            'default-src': ['\'self\''],
            'script-src': ['\'self\''],
            'style-src': ['\'self\''],
            'img-src': ['\'self\'', 'data:']
        }
        Talisman(
            app,
            content_security_policy=csp,
            force_https=not app.config.get('DEBUG', False),
            strict_transport_security=not app.config.get('DEBUG', False),
        )

    if Limiter is not None and get_remote_address is not None:
        limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
        limiter.init_app(app)

    # SeaSurf (CSRF) can block AJAX calls from embedded webviews if tokens
    # are not propagated correctly. Skip SeaSurf in desktop mode.
    if SeaSurf is not None and not desktop_mode:
        SeaSurf(app)

    # Initialize structured logging (optional SIEM endpoint)
    siem = os.getenv('SIEM_ENDPOINT')
    configure_json_logging(siem_endpoint=siem)

    # Initialize audit logger to local file if not already set
    audit_path = os.getenv('AUDIT_LOG_PATH', os.path.join(os.getcwd(), 'audit.log'))
    try:
        init_audit_logger(audit_path)
    except Exception:
        # ignore if already initialized or not writable
        pass

    # Initialize simple FileKMS if requested (local testing only)
    kms_provider = os.getenv('KMS_PROVIDER', 'file')
    if kms_provider == 'file':
        kms_path = os.getenv('KMS_FILE_PATH', os.path.join(os.getcwd(), 'kms.key'))
        try:
            app.kms = FileKMS(kms_path)
        except Exception:
            app.kms = None
    elif kms_provider == 'aws':
        # Requires AWS credentials and AWS_KMS_KEY_ID env var
        aws_key_id = os.getenv('AWS_KMS_KEY_ID')
        aws_region = os.getenv('AWS_REGION')
        try:
            if aws_key_id:
                app.kms = AWSKMSProvider(aws_key_id, region_name=aws_region)
            else:
                app.kms = None
        except Exception:
            app.kms = None

    @app.route('/')
    def index():
        return render_template('index.html')

    return app


app = create_app()


if __name__ == '__main__':
    # Respect FLASK_DEBUG/FLASK_ENV; prefer running via WSGI in production
    debug = os.getenv('FLASK_DEBUG', '0') == '1'
    port = int(os.getenv('PORT', 5000))
    app.run(port=port, debug=debug)
