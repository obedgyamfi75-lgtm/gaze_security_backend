"""
GAZE Security Platform - Security Module
"""
from app.security.auth import AuthService, require_mfa, require_role, log_security_event
from app.security.rbac import RBAC, Role, Permission, require_permission, require_any_permission
from app.security.audit import AuditLogger, AuditAction, audit_action
from app.security.sanitize import Sanitizer, validate_request_json, sanitize_output
from app.security.api_key_auth import require_api_key_or_login

__all__ = [
    # Auth
    'AuthService',
    'require_mfa',
    'require_role',
    'log_security_event',
    # RBAC
    'RBAC',
    'Role',
    'Permission',
    'require_permission',
    'require_any_permission',
    # Audit
    'AuditLogger',
    'AuditAction',
    'audit_action',
    # Sanitize
    'Sanitizer',
    'validate_request_json',
    'sanitize_output',
    # API Key Auth
    'require_api_key_or_login',
]