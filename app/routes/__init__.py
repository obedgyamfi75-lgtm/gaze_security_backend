"""
GAZE Security Platform - Routes
"""
from app.routes.api_auth import api_auth_bp as auth_bp
from app.routes.dashboard import dashboard_bp
from app.routes.assets import assets_bp
from app.routes.assessments import assessments_bp
from app.routes.findings import findings_bp
from app.routes.reports import reports_bp
from app.routes.admin import admin_bp

__all__ = [
    'auth_bp',
    'dashboard_bp',
    'assets_bp',
    'assessments_bp',
    'findings_bp',
    'reports_bp',
    'admin_bp',
]
