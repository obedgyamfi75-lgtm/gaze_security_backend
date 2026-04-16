"""
GAZE Security Platform - Role-Based Access Control
RBAC with attribute-based constraints
"""
from enum import Enum
from functools import wraps
from typing import Optional, Set

from flask import abort, request
from flask_login import current_user
import structlog

logger = structlog.get_logger()


class Role(str, Enum):
    """User roles in order of privilege"""
    SUPERADMIN = "superadmin"      # Break-glass access
    ADMIN = "admin"                 # Full management
    SECURITY_LEAD = "security_lead" # Team lead
    ANALYST = "analyst"             # Security analyst
    DEVELOPER = "developer"         # Read-only access


class Permission(str, Enum):
    """Granular permissions"""
    # User management
    USER_CREATE = "user:create"
    USER_READ = "user:read"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    
    # Asset management
    ASSET_CREATE = "asset:create"
    ASSET_READ = "asset:read"
    ASSET_UPDATE = "asset:update"
    ASSET_DELETE = "asset:delete"
    
    # Assessment management
    ASSESSMENT_CREATE = "assessment:create"
    ASSESSMENT_READ = "assessment:read"
    ASSESSMENT_UPDATE = "assessment:update"
    ASSESSMENT_DELETE = "assessment:delete"
    
    # Finding management
    FINDING_CREATE = "finding:create"
    FINDING_READ = "finding:read"
    FINDING_UPDATE = "finding:update"
    FINDING_DELETE = "finding:delete"
    
    # Report management
    REPORT_CREATE = "report:create"
    REPORT_READ = "report:read"
    REPORT_UPDATE = "report:update"
    REPORT_DELETE = "report:delete"
    
    # Excel export
    EXPORT_CREATE = "export:create"
    EXPORT_READ = "export:read"
    
    # Audit logs
    AUDIT_READ = "audit:read"
    
    # System settings
    SETTINGS_READ = "settings:read"
    SETTINGS_UPDATE = "settings:update"


# Role to permissions mapping
ROLE_PERMISSIONS: dict[Role, Set[Permission]] = {
    Role.SUPERADMIN: set(Permission),  # All permissions
    
    Role.ADMIN: {
        # Users
        Permission.USER_CREATE, Permission.USER_READ, 
        Permission.USER_UPDATE, Permission.USER_DELETE,
        # Assets
        Permission.ASSET_CREATE, Permission.ASSET_READ,
        Permission.ASSET_UPDATE, Permission.ASSET_DELETE,
        # Assessments
        Permission.ASSESSMENT_CREATE, Permission.ASSESSMENT_READ,
        Permission.ASSESSMENT_UPDATE, Permission.ASSESSMENT_DELETE,
        # Findings
        Permission.FINDING_CREATE, Permission.FINDING_READ,
        Permission.FINDING_UPDATE, Permission.FINDING_DELETE,
        # Reports
        Permission.REPORT_CREATE, Permission.REPORT_READ,
        Permission.REPORT_UPDATE, Permission.REPORT_DELETE,
        # Export
        Permission.EXPORT_CREATE, Permission.EXPORT_READ,
        # Audit
        Permission.AUDIT_READ,
        # Settings
        Permission.SETTINGS_READ,
    },
    
    Role.SECURITY_LEAD: {
        # Users (read only)
        Permission.USER_READ,
        # Assets
        Permission.ASSET_CREATE, Permission.ASSET_READ,
        Permission.ASSET_UPDATE, Permission.ASSET_DELETE,
        # Assessments
        Permission.ASSESSMENT_CREATE, Permission.ASSESSMENT_READ,
        Permission.ASSESSMENT_UPDATE, Permission.ASSESSMENT_DELETE,
        # Findings
        Permission.FINDING_CREATE, Permission.FINDING_READ,
        Permission.FINDING_UPDATE, Permission.FINDING_DELETE,
        # Reports
        Permission.REPORT_CREATE, Permission.REPORT_READ,
        Permission.REPORT_UPDATE, Permission.REPORT_DELETE,
        # Export
        Permission.EXPORT_CREATE, Permission.EXPORT_READ,
    },
    
    Role.ANALYST: {
        # Assets (create/read)
        Permission.ASSET_CREATE, Permission.ASSET_READ,
        # Assessments
        Permission.ASSESSMENT_CREATE, Permission.ASSESSMENT_READ,
        Permission.ASSESSMENT_UPDATE, Permission.ASSESSMENT_DELETE,
        # Findings
        Permission.FINDING_CREATE, Permission.FINDING_READ,
        Permission.FINDING_UPDATE, Permission.FINDING_DELETE,
        # Reports (read)
        Permission.REPORT_READ,
        # Export (read)
        Permission.EXPORT_READ,
    },
    
    Role.DEVELOPER: {
        # Read-only access
        Permission.ASSET_READ,
        Permission.ASSESSMENT_READ,
        Permission.FINDING_READ,
        Permission.REPORT_READ,
    },
}


class RBAC:
    """Role-Based Access Control service"""
    
    @staticmethod
    def has_permission(user, permission: Permission) -> bool:
        """Check if user has a specific permission"""
        if not user or not user.is_authenticated:
            return False
        
        try:
            role = Role(user.role)
            permissions = ROLE_PERMISSIONS.get(role, set())
            return permission in permissions
        except ValueError:
            logger.error("invalid_role", role=user.role)
            return False
    
    @staticmethod
    def has_any_permission(user, permissions: Set[Permission]) -> bool:
        """Check if user has any of the specified permissions"""
        return any(RBAC.has_permission(user, p) for p in permissions)
    
    @staticmethod
    def has_all_permissions(user, permissions: Set[Permission]) -> bool:
        """Check if user has all of the specified permissions"""
        return all(RBAC.has_permission(user, p) for p in permissions)
    
    @staticmethod
    def get_user_permissions(user) -> Set[Permission]:
        """Get all permissions for a user"""
        if not user or not user.is_authenticated:
            return set()
        
        try:
            role = Role(user.role)
            return ROLE_PERMISSIONS.get(role, set())
        except ValueError:
            return set()
    
    @staticmethod
    def can_access_resource(user, resource, action: str) -> bool:
        """
        Check if user can perform action on a specific resource.
        Implements attribute-based access control (ABAC).
        """
        if not user or not user.is_authenticated:
            return False
        
        # Superadmin bypass
        if user.role == Role.SUPERADMIN.value:
            return True
        
        # Check base permission
        permission_name = f"{resource.__class__.__name__.lower()}:{action}"
        try:
            permission = Permission(permission_name)
            if not RBAC.has_permission(user, permission):
                return False
        except ValueError:
            logger.warning("unknown_permission", permission=permission_name)
            return False
        
        # ABAC: Check resource ownership for certain roles
        if user.role in [Role.ANALYST.value, Role.SECURITY_LEAD.value]:
            # Analysts can only modify their own findings/assessments
            if hasattr(resource, 'created_by_id'):
                if action in ['update', 'delete'] and resource.created_by_id != user.id:
                    # Security leads can modify team members' work
                    if user.role == Role.SECURITY_LEAD.value:
                        # Check if resource creator is on the same team
                        # This would need team_id on user model
                        pass
                    else:
                        return False
        
        return True


def require_permission(*permissions: Permission):
    """Decorator to require specific permission(s)"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            
            for perm in permissions:
                if not RBAC.has_permission(current_user, perm):
                    logger.warning(
                        "permission_denied",
                        user_id=str(current_user.id),
                        required_permission=perm.value,
                        user_role=current_user.role
                    )
                    abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_any_permission(*permissions: Permission):
    """Decorator to require at least one of the specified permissions"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            
            if not RBAC.has_any_permission(current_user, set(permissions)):
                logger.warning(
                    "permission_denied",
                    user_id=str(current_user.id),
                    required_permissions=[p.value for p in permissions],
                    user_role=current_user.role
                )
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_resource_access(action: str):
    """
    Decorator for resource-level access control.
    Use with routes that have a resource ID parameter.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            
            # The actual resource check happens in the route
            # This decorator marks the intent
            kwargs['_required_action'] = action
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator
