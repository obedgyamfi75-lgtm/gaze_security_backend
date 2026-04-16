"""
GAZE Security Platform - Audit Logging
Immutable, structured audit trail for security events
"""
import json
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

from flask import g, request
from flask_login import current_user
import structlog

from app import db

logger = structlog.get_logger()


class AuditAction:
    """Audit action types"""
    # Authentication
    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILED = "auth.login.failed"
    LOGOUT = "auth.logout"
    MFA_ENABLED = "auth.mfa.enabled"
    MFA_DISABLED = "auth.mfa.disabled"
    MFA_VERIFIED = "auth.mfa.verified"
    PASSWORD_CHANGED = "auth.password.changed"
    PASSWORD_RESET_REQUESTED = "auth.password.reset_requested"
    ACCOUNT_LOCKED = "auth.account.locked"
    ACCOUNT_UNLOCKED = "auth.account.unlocked"
    
    # User management
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    USER_ROLE_CHANGED = "user.role.changed"
    
    # Asset management
    ASSET_CREATED = "asset.created"
    ASSET_UPDATED = "asset.updated"
    ASSET_DELETED = "asset.deleted"
    
    # Assessment management
    ASSESSMENT_CREATED = "assessment.created"
    ASSESSMENT_UPDATED = "assessment.updated"
    ASSESSMENT_DELETED = "assessment.deleted"
    ASSESSMENT_STARTED = "assessment.started"
    ASSESSMENT_COMPLETED = "assessment.completed"
    
    # Finding management
    FINDING_CREATED = "finding.created"
    FINDING_UPDATED = "finding.updated"
    FINDING_DELETED = "finding.deleted"
    FINDING_STATUS_CHANGED = "finding.status.changed"
    
    # Evidence
    EVIDENCE_UPLOADED = "evidence.uploaded"
    EVIDENCE_DELETED = "evidence.deleted"
    EVIDENCE_DOWNLOADED = "evidence.downloaded"
    
    # Reports
    REPORT_GENERATED = "report.generated"
    REPORT_DOWNLOADED = "report.downloaded"
    REPORT_DELETE = "report.deleted"
    REPORT_DELETED = "report.deleted"
    
    # Export
    EXPORT_CREATED = "export.created"
    EXPORT_DOWNLOADED = "export.downloaded"
    
    # Admin
    SETTINGS_UPDATED = "settings.updated"
    BULK_DATA_ACCESS = "data.bulk_access"


class AuditLogger:
    """Audit logging service"""
    
    @staticmethod
    def log(
        action: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[UUID] = None,
        changes: Optional[dict] = None,
        old_values: Optional[dict] = None,
        new_values: Optional[dict] = None,
        metadata: Optional[dict] = None,
        outcome: str = "success",
    ) -> None:
        """
        Log an auditable event.
        
        Args:
            action: The action being performed (use AuditAction constants)
            resource_type: Type of resource being acted upon
            resource_id: ID of the resource
            changes: Dictionary of field changes {field: {before, after}}
            old_values: Previous state of resource
            new_values: New state of resource
            metadata: Additional context
            outcome: success, failure, or error
        """
        from app.models.audit_log import AuditLog
        
        # Get current user info
        user_id = None
        user_email = None
        if current_user and current_user.is_authenticated:
            user_id = current_user.id
            user_email = current_user.email
        
        # Create audit log entry
        audit_entry = AuditLog(
            request_id=g.get('request_id'),
            user_id=user_id,
            user_email=user_email,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            changes=changes,
            old_values=AuditLogger._sanitize_values(old_values),
            new_values=AuditLogger._sanitize_values(new_values),
            ip_address=request.remote_addr if request else None,
            user_agent=request.user_agent.string[:255] if request and request.user_agent else None,
            event_metadata=metadata,
            outcome=outcome,
            created_at=datetime.now(timezone.utc)
        )
        
        try:
            db.session.add(audit_entry)
            db.session.commit()
        except Exception as e:
            # Don't fail the main operation if audit logging fails
            # But do log it for investigation
            logger.error("audit_log_failed", error=str(e), action=action)
            db.session.rollback()
        
        # Also log to structured logger for SIEM
        logger.info(
            "audit_event",
            action=action,
            user_id=str(user_id) if user_id else None,
            user_email=user_email,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            outcome=outcome,
            ip_address=request.remote_addr if request else None,
        )
    
    @staticmethod
    def _sanitize_values(values: Optional[dict]) -> Optional[dict]:
        """Remove sensitive fields from audit values"""
        if not values:
            return None
        
        sensitive_fields = {
            'password', 'password_hash', 'totp_secret', 
            'backup_codes', 'api_key', 'secret_key',
            'access_token', 'refresh_token'
        }
        
        sanitized = {}
        for key, value in values.items():
            if key.lower() in sensitive_fields:
                sanitized[key] = '[REDACTED]'
            elif isinstance(value, dict):
                sanitized[key] = AuditLogger._sanitize_values(value)
            else:
                sanitized[key] = value
        
        return sanitized
    
    @staticmethod
    def log_data_change(
        action: str,
        resource_type: str,
        resource_id: UUID,
        old_obj: Any,
        new_obj: Any,
        fields_to_track: Optional[list] = None
    ) -> None:
        """
        Log changes between two object states.
        
        Args:
            action: The action type
            resource_type: Type of resource
            resource_id: Resource ID
            old_obj: Previous state (SQLAlchemy model or dict)
            new_obj: New state (SQLAlchemy model or dict)
            fields_to_track: Specific fields to track (None = all)
        """
        # Convert objects to dicts if needed
        old_dict = AuditLogger._obj_to_dict(old_obj, fields_to_track)
        new_dict = AuditLogger._obj_to_dict(new_obj, fields_to_track)
        
        # Calculate changes
        changes = {}
        all_keys = set(old_dict.keys()) | set(new_dict.keys())
        
        for key in all_keys:
            old_val = old_dict.get(key)
            new_val = new_dict.get(key)
            
            if old_val != new_val:
                changes[key] = {
                    'before': old_val,
                    'after': new_val
                }
        
        if changes:
            AuditLogger.log(
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                changes=changes,
                old_values=old_dict,
                new_values=new_dict
            )
    
    @staticmethod
    def _obj_to_dict(obj: Any, fields: Optional[list] = None) -> dict:
        """Convert an object to a dictionary for audit logging"""
        if obj is None:
            return {}
        
        if isinstance(obj, dict):
            if fields:
                return {k: v for k, v in obj.items() if k in fields}
            return obj
        
        # SQLAlchemy model
        result = {}
        columns = obj.__table__.columns.keys() if hasattr(obj, '__table__') else []
        
        for col in columns:
            if fields and col not in fields:
                continue
            
            value = getattr(obj, col, None)
            
            # Handle special types
            if isinstance(value, datetime):
                value = value.isoformat()
            elif isinstance(value, UUID):
                value = str(value)
            elif hasattr(value, '__dict__'):
                value = str(value)
            
            result[col] = value
        
        return result


def audit_action(action: str, resource_type: Optional[str] = None):
    """
    Decorator to automatically audit a function call.
    
    Usage:
        @audit_action(AuditAction.USER_CREATED, "user")
        def create_user(data):
            ...
    """
    def decorator(f):
        from functools import wraps
        
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                result = f(*args, **kwargs)
                
                # Try to extract resource ID from result
                resource_id = None
                if result and hasattr(result, 'id'):
                    resource_id = result.id
                
                AuditLogger.log(
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    outcome="success"
                )
                
                return result
            except Exception as e:
                AuditLogger.log(
                    action=action,
                    resource_type=resource_type,
                    outcome="failure",
                    metadata={"error": str(e)}
                )
                raise
        
        return decorated_function
    return decorator
