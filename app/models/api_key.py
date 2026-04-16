"""
GazeSec - API Key Model
Scoped API keys for MCP and programmatic access
"""
import uuid
import secrets
import hashlib
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, ForeignKey, Boolean
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import relationship

from app import db


VALID_SCOPES = {"mcp", "api", "jira", "slack", "github", "pagerduty", "splunk", "servicenow"}


class ApiKey(db.Model):
    __tablename__ = 'api_keys'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    name = Column(String(100), nullable=False, default='API Key')
    key_hash = Column(String(64), nullable=False, unique=True, index=True)
    key_prefix = Column(String(12), nullable=False)
    key_raw = Column(String(100), nullable=True)
    scopes = Column(ARRAY(String(50)), nullable=False, default=list)
    is_active = Column(Boolean, default=True, nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    user = relationship('User', back_populates='api_keys')

    @staticmethod
    def generate(name: str, scopes: list[str]) -> tuple['ApiKey', str]:
        """
        Generate a new API key.
        Returns (ApiKey instance, raw_key).
        raw_key is shown once — never stored.
        """
        raw = f"sk_live_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(raw.encode()).hexdigest()
        key_prefix = raw[:12]

        instance = ApiKey(
            name=name,
            key_hash=key_hash,
            key_prefix=key_prefix,
            key_raw=raw,
            scopes=[s for s in scopes if s in VALID_SCOPES],
        )
        return instance, raw

    @staticmethod
    def verify(raw_key: str) -> 'ApiKey | None':
        """Verify a raw key and return the ApiKey if valid and active."""
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        key = ApiKey.query.filter_by(key_hash=key_hash, is_active=True).first()
        if key:
            key.touch()
            db.session.commit()
        return key

    def has_scope(self, scope: str) -> bool:
        return scope in (self.scopes or [])

    def touch(self) -> None:
        self.last_used_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        return {
            'id': str(self.id),
            'name': self.name,
            'prefix': self.key_prefix,
            'scopes': self.scopes or [],
            'isActive': self.is_active,
            'lastUsedAt': self.last_used_at.isoformat() if self.last_used_at else None,
            'createdAt': self.created_at.isoformat(),
        }
