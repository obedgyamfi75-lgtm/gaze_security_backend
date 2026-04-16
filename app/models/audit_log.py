"""
GAZE Security Platform - Audit Log Model
Immutable audit trail
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, Text, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app import db


class AuditLog(db.Model):
    """Immutable audit log entry"""
    __tablename__ = 'audit_logs'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Request context
    request_id = Column(String(36), nullable=True, index=True)

    # Actor
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    user_email = Column(String(255), nullable=True)

    # Action
    action = Column(String(100), nullable=False, index=True)

    # Resource
    table_name = Column(String(100), nullable=True)
    resource_type = Column(String(100), nullable=True)
    resource_id = Column(UUID(as_uuid=True), nullable=True)

    # Changes
    changes = Column(JSONB, nullable=True)
    old_values = Column(JSONB, nullable=True)
    new_values = Column(JSONB, nullable=True)

    # Context
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)
    event_metadata = Column(JSONB, nullable=True)

    # Outcome
    outcome = Column(String(20), default='success')  # success, failure, error

    # Timestamp (immutable)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Relationships
    user = relationship('User', foreign_keys=[user_id], lazy='joined')

    def __repr__(self):
        return f'<AuditLog {self.action} by {self.user_email}>'

    def _map_action(self) -> str:
        """Map backend dot-notation action to frontend AuditAction type"""
        a = self.action or ''
        if 'login' in a:
            return 'login'
        if 'logout' in a:
            return 'logout'
        if a.endswith('.created'):
            return 'create'
        if a.endswith('.updated') or a.endswith('.changed'):
            return 'update'
        if a.endswith('.deleted'):
            return 'delete'
        if 'export' in a or 'download' in a:
            return 'export'
        if 'status' in a:
            return 'status_change'
        return 'update'  # safe fallback

    def to_dict(self) -> dict:
        # Build nested user object matching frontend UserRef shape
        user_obj = None
        if self.user:
            name = self.user.full_name or self.user_email or ''
            parts = name.split()
            initials = ''.join(p[0].upper() for p in parts[:2]) or '??'
            user_obj = {
                'id': str(self.user_id),
                'name': name,
                'email': self.user.email,
                'initials': initials,
            }
        elif self.user_email:
            # Fallback: construct from email if user was deleted
            local = self.user_email.split('@')[0]
            parts = local.replace('.', ' ').replace('_', ' ').split()
            initials = ''.join(p[0].upper() for p in parts[:2]) or '??'
            user_obj = {
                'id': str(self.user_id) if self.user_id else None,
                'name': ' '.join(p.capitalize() for p in parts) or self.user_email,
                'email': self.user_email,
                'initials': initials,
            }

        return {
            'id': str(self.id),
            'action': self._map_action(),
            'entityType': self.resource_type or 'system',
            'entityId': str(self.resource_id) if self.resource_id else None,
            'entityName': (self.event_metadata or {}).get('entity_name'),
            'user': user_obj,
            'userId': str(self.user_id) if self.user_id else None,
            'changes': self.changes,
            'ipAddress': self.ip_address,
            'userAgent': self.user_agent,
            'outcome': self.outcome,
            'createdAt': self.created_at.isoformat(),
        }
