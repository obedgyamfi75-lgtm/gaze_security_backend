"""
GAZE Security Platform - Evidence Model
Secure evidence storage with file validation
"""
import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import Column, String, Text, DateTime, Integer, ForeignKey, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app import db


class EvidenceType(str, Enum):
    SCREENSHOT = "screenshot"
    REQUEST_RESPONSE = "request_response"
    LOG_FILE = "log_file"
    CODE_SNIPPET = "code_snippet"
    VIDEO = "video"
    OTHER = "other"


class Evidence(db.Model):
    """Evidence model for finding attachments"""
    __tablename__ = 'evidence'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # File info
    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(255), nullable=False, unique=True)  # UUID-based
    mime_type = Column(String(100), nullable=False)
    file_size = Column(Integer, nullable=False)  # bytes
    file_hash = Column(String(64), nullable=False)  # SHA-256
    
    # Classification
    evidence_type = Column(SQLEnum(EvidenceType), nullable=False, default=EvidenceType.OTHER)
    description = Column(Text, nullable=True)
    
    # Security
    scan_status = Column(String(20), default='pending')  # pending, clean, infected, error
    scan_result = Column(Text, nullable=True)
    
    # References
    finding_id = Column(UUID(as_uuid=True), ForeignKey('findings.id'), nullable=False)
    uploaded_by_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationships
    finding = relationship('Finding', back_populates='evidence')
    uploaded_by = relationship('User')
    
    def __repr__(self):
        return f'<Evidence {self.original_filename}>'
    
    @property
    def file_size_human(self) -> str:
        """Human-readable file size"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if self.file_size < 1024:
                return f"{self.file_size:.1f} {unit}"
            self.file_size /= 1024
        return f"{self.file_size:.1f} TB"
    
    @property
    def is_safe(self) -> bool:
        """Check if file passed virus scan"""
        return self.scan_status == 'clean'
    
    def to_dict(self) -> dict:
        # Map internal evidence_type to frontend-expected type names
        type_map = {
            'screenshot': 'screenshot',
            'request_response': 'request',
            'log_file': 'file',
            'code_snippet': 'code',
            'video': 'file',
            'other': 'file',
        }
        frontend_type = type_map.get(self.evidence_type.value, 'file')

        return {
            'id': str(self.id),
            # Frontend-compatible keys (camelCase, already correct after normalizeKeys)
            'filename': self.original_filename,
            'type': frontend_type,
            'description': self.description,
            'fileSize': self.file_size,
            'fileSizeHuman': self.file_size_human,
            'scanStatus': self.scan_status,
            'isSafe': self.is_safe,
            'findingId': str(self.finding_id),
            'uploadedBy': self.uploaded_by.full_name if self.uploaded_by else None,
            'createdAt': self.created_at.isoformat(),
        }
