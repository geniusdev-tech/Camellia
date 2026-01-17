import os
import secrets
import logging
from warnings import warn, filterwarnings
from flask import Flask, render_template, jsonify, send_from_directory

from config import DevelopmentConfig, ProductionConfig

# Suppress GTK warnings (webview fallback to Qt works fine)
filterwarnings('ignore', category=UserWarning, module='webview.guilib')
# Suppress Flask-Limiter warning when using in-memory storage (expected in development)
filterwarnings('ignore', message='.*in-memory storage.*', category=UserWarning)
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

    # SECRET_KEY handling
    env = os.getenv('FLASK_ENV', 'production').lower()
    secret = os.getenv('SECRET_KEY') or app.config.get('SECRET_KEY')
    
    if secret:
        app.secret_key = secret
    elif env == 'development':
        # Generate temporary key for development (suppressed warning)
        app.secret_key = secrets.token_hex(32)
        logging.getLogger(__name__).debug('Using temporary SECRET_KEY for development.')
    else:
        # Production requires SECRET_KEY
        raise RuntimeError('SECRET_KEY environment variable is required in production. Set it before starting the app.')

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
        # Configure rate limiter with file-based storage for persistence
        # For high-traffic production, use Redis: redis://localhost:6379
        
        # Relax limits for desktop mode and development to prevent 429s on local polling
        if desktop_mode or env == 'development':
            default_limits = ["100000 per day", "20000 per hour"]
        else:
            default_limits = ["2000 per day", "500 per hour"]
            
        limiter = Limiter(
            key_func=get_remote_address, 
            default_limits=default_limits
        )
        limiter.init_app(app)

    # SeaSurf (CSRF) can block AJAX calls from embedded webviews if tokens
    # are not propagated correctly. Skip SeaSurf in desktop mode.
    # Also skip in development mode for easier testing on local network
    if SeaSurf is not None and not desktop_mode and env != 'development':
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

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def serve_spa(path=''):
        """Serve React SPA"""
        # API routes are handled separately by blueprints
        if path.startswith('api/'):
            return jsonify({'error': 'Not found'}), 404
        
        dist_path = os.path.join(app.root_path, 'static', 'dist')
        
        # Try to serve static file from dist
        file_path = os.path.join(dist_path, path)
        if os.path.isfile(file_path):
            return send_from_directory(dist_path, path)
        
        # Fallback to index.html for client-side routing
        index_path = os.path.join(dist_path, 'index.html')
        if os.path.isfile(index_path):
            return send_from_directory(dist_path, 'index.html')
        
        # If React build doesn't exist, show helpful error
        return jsonify({
            'error': 'Frontend not built',
            'message': 'Run "cd frontend && npm run build" to build the React frontend.'
        }), 500

    return app


app = create_app()


if __name__ == '__main__':
    # Respect FLASK_DEBUG/FLASK_ENV; prefer running via WSGI in production
    debug = os.getenv('FLASK_DEBUG', '0') == '1'
    port = int(os.getenv('PORT', 5000))
    host = os.getenv('HOST', '0.0.0.0')  # Listen on all interfaces for LAN access
    app.run(host=host, port=port, debug=debug)

