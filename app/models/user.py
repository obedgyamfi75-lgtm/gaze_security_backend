"""
GAZE Security Platform - User Model
Secure user model with MFA support
"""
import uuid
from datetime import datetime, timezone
from typing import Optional, List

from flask_login import UserMixin
from sqlalchemy import Column, String, Boolean, DateTime, Integer, Text
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import relationship

from app import db
from app.security.auth import AuthService


class User(db.Model, UserMixin):
    """User model with security features"""
    __tablename__ = 'users'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    
    # Profile
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    role = Column(String(50), nullable=False, default='analyst')
    is_active = Column(Boolean, default=True, nullable=False)
    
    # MFA
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    totp_secret = Column(String(32), nullable=True)  # Encrypted at rest
    backup_codes = Column(ARRAY(String(64)), nullable=True)  # Hashed codes
    
    # Security tracking
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    lockout_until = Column(DateTime(timezone=True), nullable=True)
    last_login = Column(DateTime(timezone=True), nullable=True)
    last_login_ip = Column(String(45), nullable=True)
    last_failed_login = Column(DateTime(timezone=True), nullable=True)
    password_changed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationships
    created_assets = relationship('Asset', back_populates='created_by', foreign_keys='Asset.created_by_id')
    created_assessments = relationship('Assessment', back_populates='created_by', foreign_keys='Assessment.created_by_id')
    assigned_assessments = relationship('Assessment', back_populates='assigned_to', foreign_keys='Assessment.assigned_to_id')
    created_findings = relationship('Finding', back_populates='created_by', foreign_keys='Finding.created_by_id')
    generated_reports = relationship('Report', back_populates='generated_by', foreign_keys='Report.generated_by_id')
    api_keys = relationship('ApiKey', back_populates='user', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.email}>'
    
    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"
    
    def set_password(self, password: str) -> None:
        """Set password hash"""
        self.password_hash = AuthService.hash_password(password)
        self.password_changed_at = datetime.now(timezone.utc)
    
    def check_password(self, password: str) -> bool:
        """Verify password"""
        return AuthService.verify_password(password, self.password_hash)
    
    def setup_mfa(self) -> tuple:
        """
        Initialize MFA for user.
        Returns (secret, qr_svg, backup_codes)
        """
        secret = AuthService.generate_totp_secret()
        self.totp_secret = secret
        
        qr_svg = AuthService.generate_totp_qr(secret, self.email)
        
        backup_codes = AuthService.generate_backup_codes()
        self.backup_codes = [AuthService.hash_backup_code(code) for code in backup_codes]
        
        return secret, qr_svg, backup_codes
    
    def enable_mfa(self) -> None:
        """Enable MFA after successful verification"""
        self.mfa_enabled = True
    
    def disable_mfa(self) -> None:
        """Disable MFA"""
        self.mfa_enabled = False
        self.totp_secret = None
        self.backup_codes = None
    
    def verify_totp(self, code: str) -> bool:
        """Verify TOTP code"""
        if not self.totp_secret:
            return False
        return AuthService.verify_totp(self.totp_secret, code)
    
    def use_backup_code(self, code: str) -> bool:
        """Use and invalidate a backup code"""
        if not self.backup_codes:
            return False
        
        code_hash = AuthService.hash_backup_code(code.upper())
        
        if code_hash in self.backup_codes:
            self.backup_codes = [c for c in self.backup_codes if c != code_hash]
            return True
        
        return False
    
    def to_dict(self, include_sensitive: bool = False) -> dict:
        """Convert to dictionary for API responses"""
        parts = self.full_name.split()
        initials = ''.join(p[0].upper() for p in parts[:2]) if parts else '??'
        data = {
            'id': str(self.id),
            'email': self.email,
            'name': self.full_name,          # Frontend User.name
            'firstName': self.first_name,    # camelCase for frontend
            'lastName': self.last_name,
            'first_name': self.first_name,   # keep for normalizeKeys compat
            'last_name': self.last_name,
            'full_name': self.full_name,
            'initials': initials,
            'role': self.role,
            'isActive': self.is_active,
            'is_active': self.is_active,
            'mfaEnabled': self.mfa_enabled,
            'mfa_enabled': self.mfa_enabled,
            'lastLogin': self.last_login.isoformat() if self.last_login else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'createdAt': self.created_at.isoformat(),
            'created_at': self.created_at.isoformat(),
            'updatedAt': self.updated_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }
        
        if include_sensitive:
            data.update({
                'backup_codes_remaining': len(self.backup_codes) if self.backup_codes else 0,
                'failed_login_attempts': self.failed_login_attempts,
                'lockout_until': self.lockout_until.isoformat() if self.lockout_until else None,
            })
        
        return data
