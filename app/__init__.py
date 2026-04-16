"""
GAZE Security Platform - Application Factory
Security-first Flask application initialization
"""
import os
import uuid
from datetime import datetime, timezone

import redis
import structlog
from flask import Flask, g, request, Response, jsonify
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS

from config import get_config

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()
sess = Session()
limiter = Limiter(
    key_func=get_remote_address, 
    storage_uri=os.environ.get("REDIS_URL"),
)
cors = CORS()

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


def create_app(config_class=None) -> Flask:
    """Application factory"""
    app = Flask(__name__)
    
    # Disable strict slashes to prevent redirects that break CORS preflight
    app.url_map.strict_slashes = False
    
    # Load configuration
    config = config_class or get_config()
    app.config.from_object(config)
    
    # Initialize extensions
    init_extensions(app)
    
    # Register security middleware
    register_security_middleware(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Health check endpoint
    @app.route('/health')
    @app.route('/api/health')
    @limiter.exempt
    def health_check():
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'version': '1.0.0'
        })
    
    return app


def init_extensions(app: Flask) -> None:
    """Initialize Flask extensions"""
    
    # Database
    db.init_app(app)
    migrate.init_app(app, db)
    
    # Session (Redis-backed)
    redis_client = redis.from_url(app.config['REDIS_URL'])
    app.config['SESSION_REDIS'] = redis_client
    sess.init_app(app)
    
    # Authentication
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'warning'
    login_manager.session_protection = 'strong'
    
    # Return JSON 401 for API routes instead of redirecting
    @login_manager.unauthorized_handler
    def unauthorized_api():
        from flask import request, jsonify, redirect, url_for
        if request.path.startswith('/api/'):
            return jsonify({
                'success': False,
                'error': 'Authentication required',
                'code': 'UNAUTHORIZED'
            }), 401
        return redirect(url_for('auth.login'))
    
    # CSRF Protection (exempt API routes that use token auth)
    csrf.init_app(app)
    
    # CORS Configuration for API access from frontend
    cors_origins = app.config.get('CORS_ORIGINS', 'http://localhost:3000').split(',')
    cors.init_app(
        app,
        resources={
            r"/api/.*": {
                "origins": cors_origins,
                "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization", "X-Requested-With", "X-CSRF-Token", "Accept"],
                "supports_credentials": True,  # Important for cookie-based sessions
                "expose_headers": ["X-Request-ID", "X-RateLimit-Remaining", "Set-Cookie"],
                "max_age": 600,  # Cache preflight for 10 minutes
            }
        },
        supports_credentials=True  # Global setting for credentials
    )
    
    # Rate Limiting
    app.config['RATELIMIT_STORAGE_URL'] = app.config['REDIS_URL']
    limiter.init_app(app)
    
    # Security Headers (Talisman)
    csp = {
        'default-src': "'self'",
        'script-src': ["'self'", "'unsafe-inline'", "https://unpkg.com"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", "data:", "blob:"],
        'font-src': "'self'",
        'connect-src': "'self'",
        'frame-ancestors': "'none'",
        'base-uri': "'self'",
        'form-action': "'self'",
    }
    
    Talisman(
        app,
        force_https=app.config['FLASK_ENV'] == 'production',
        strict_transport_security=True,
        strict_transport_security_max_age=63072000,
        strict_transport_security_include_subdomains=True,
        strict_transport_security_preload=True,
        content_security_policy=csp,
        content_security_policy_nonce_in=['script-src'],
        referrer_policy='strict-origin-when-cross-origin',
        feature_policy={
            'accelerometer': "'none'",
            'camera': "'none'",
            'geolocation': "'none'",
            'gyroscope': "'none'",
            'magnetometer': "'none'",
            'microphone': "'none'",
            'payment': "'none'",
            'usb': "'none'",
        },
        # For development with frontend on different port, use Lax and disable Secure
        # In production, these should be Strict and True
        session_cookie_secure=app.config.get('SESSION_COOKIE_SECURE', False),
        session_cookie_http_only=True,
        session_cookie_samesite=app.config.get('SESSION_COOKIE_SAMESITE', 'Lax'),
    )


def register_security_middleware(app: Flask) -> None:
    """Register security middleware"""
    
    @app.before_request
    def before_request():
        """Pre-request security checks"""
        # Generate request ID for correlation
        g.request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
        g.request_start = datetime.now(timezone.utc)
        
        # Bind request context to logger
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=g.request_id,
            method=request.method,
            path=request.path,
            remote_addr=request.remote_addr,
            user_agent=request.user_agent.string[:100] if request.user_agent else None,
        )
        
        # Host header validation
        allowed_hosts = app.config.get('ALLOWED_HOSTS', 'localhost').split(',')
        if request.path != '/health' and request.host.split(':')[0] not in allowed_hosts:
            logger.warning("invalid_host_header", host=request.host)
            return Response("Invalid host header", status=400)
    
    @app.after_request
    def after_request(response: Response) -> Response:
        """Post-request processing"""
        # Add security headers not covered by Talisman
        response.headers['X-Request-ID'] = g.get('request_id', 'unknown')
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        # Remove server header
        response.headers.pop('Server', None)
        
        # Log request completion
        duration = (datetime.now(timezone.utc) - g.get('request_start', datetime.now(timezone.utc))).total_seconds()
        logger.info(
            "request_completed",
            status_code=response.status_code,
            duration_seconds=duration,
            content_length=response.content_length,
        )
        
        return response
    
    @app.teardown_request
    def teardown_request(exception=None):
        """Cleanup after request"""
        if exception:
            logger.error("request_exception", exc_info=exception)


def register_blueprints(app: Flask) -> None:
    """Register application blueprints with /api prefix"""
    from app.routes.auth import auth_bp
    from app.routes.api_auth import api_auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.products import products_bp
    from app.routes.assets import assets_bp
    from app.routes.assessments import assessments_bp
    from app.routes.findings import findings_bp
    from app.routes.reports import reports_bp
    from app.routes.admin import admin_bp
    from app.routes.api_keys import api_keys_bp
    
    # HTML routes (for legacy/fallback)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    
    # All API routes under /api prefix for clean separation
    # These are exempt from CSRF since they use JSON + session cookies
    api_blueprints = [
        (api_auth_bp, '/api/auth'),
        (dashboard_bp, '/api/dashboard'),
        (products_bp, '/api/products'),
        (assets_bp, '/api'),
        (assessments_bp, '/api/assessments'),
        (findings_bp, '/api/findings'),
        (reports_bp, '/api/reports'),
        (admin_bp, '/api/admin'),
        (api_keys_bp, '/api/keys'),
    ]
    
    for bp, prefix in api_blueprints:
        app.register_blueprint(bp, url_prefix=prefix)
        # API blueprints use session cookies + SameSite for CSRF protection;
        # exempted here at registration — do NOT add per-route/per-request exemptions.
        csrf.exempt(bp)


def register_error_handlers(app: Flask) -> None:
    """Register error handlers"""
    
    @app.errorhandler(400)
    def bad_request(e):
        logger.warning("bad_request", error=str(e))
        return {'error': 'Bad request'}, 400
    
    @app.errorhandler(401)
    def unauthorized(e):
        logger.warning("unauthorized", error=str(e))
        return {'error': 'Unauthorized'}, 401
    
    @app.errorhandler(403)
    def forbidden(e):
        logger.warning("forbidden", error=str(e))
        return {'error': 'Forbidden'}, 403
    
    @app.errorhandler(404)
    def not_found(e):
        return {'error': 'Not found'}, 404
    
    @app.errorhandler(429)
    def rate_limited(e):
        logger.warning("rate_limited")
        return {'error': 'Too many requests'}, 429
    
    @app.errorhandler(500)
    def internal_error(e):
        logger.error("internal_error", exc_info=e)
        return {'error': 'Internal server error'}, 500
