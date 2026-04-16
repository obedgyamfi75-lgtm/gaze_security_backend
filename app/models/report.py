"""
GAZE Security Platform - Report Model
Tracks report generation lifecycle with status, metadata, and file references.
"""
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlalchemy import Column, String, Text, DateTime, Integer, ForeignKey, Enum as SQLEnum, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app import db


class ReportType(str, Enum):
    """Report type classifications"""
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    COMPLIANCE = "compliance"
    FULL = "full"
    CUSTOM = "custom"


class ReportStatus(str, Enum):
    """Report generation status"""
    PENDING = "pending"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"


class ReportFormat(str, Enum):
    """Output format types"""
    PDF = "pdf"
    DOCX = "docx"
    XLSX = "xlsx"
    HTML = "html"


class Report(db.Model):
    """
    Report model for tracking generated security reports.
    
    Supports async generation with status tracking, multiple output formats,
    and linkage to source assessments.
    """
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False, index=True)
    
    # Type and format
    report_type = Column(SQLEnum(ReportType), nullable=False, default=ReportType.EXECUTIVE)
    format = Column(SQLEnum(ReportFormat), nullable=False, default=ReportFormat.PDF)
    status = Column(SQLEnum(ReportStatus), nullable=False, default=ReportStatus.PENDING)
    
    # Source assessment (required - reports are always based on an assessment)
    assessment_id = Column(UUID(as_uuid=True), ForeignKey('assessments.id'), nullable=False)
    
    # Generation options stored as JSON
    # Example: {"include_evidence": true, "include_remediation": true, "include_metrics": true}
    options = Column(JSON, default=dict)
    
    # Custom template path (for CUSTOM report type - future LLM integration)
    template_path = Column(String(512), nullable=True)
    
    # File metadata (populated after generation)
    file_path = Column(String(512), nullable=True)
    file_size = Column(Integer, nullable=True)  # bytes
    page_count = Column(Integer, nullable=True)
    
    # Error tracking
    error_message = Column(Text, nullable=True)
    
    # Generation timestamps
    generation_started_at = Column(DateTime(timezone=True), nullable=True)
    generation_completed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Audit fields
    generated_by_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationships
    assessment = relationship('Assessment', back_populates='reports')
    generated_by = relationship('User', back_populates='generated_reports', foreign_keys=[generated_by_id])

    def __repr__(self) -> str:
        return f"<Report {self.name} [{self.status.value}]>"

    def start_generation(self) -> None:
        """Mark report as generating"""
        self.status = ReportStatus.GENERATING
        self.generation_started_at = datetime.now(timezone.utc)
        self.error_message = None

    def complete_generation(self, file_path: str, file_size: int, page_count: Optional[int] = None) -> None:
        """Mark report as completed with file metadata"""
        self.status = ReportStatus.COMPLETED
        self.generation_completed_at = datetime.now(timezone.utc)
        self.file_path = file_path
        self.file_size = file_size
        self.page_count = page_count

    def fail_generation(self, error_message: str) -> None:
        """Mark report as failed with error details"""
        self.status = ReportStatus.FAILED
        self.generation_completed_at = datetime.now(timezone.utc)
        self.error_message = error_message

    @property
    def download_url(self) -> Optional[str]:
        """Generate download URL if report is completed"""
        if self.status == ReportStatus.COMPLETED and self.file_path:
            return f"/api/reports/{self.id}/download"
        return None

    @property
    def generation_duration(self) -> Optional[float]:
        """Calculate generation duration in seconds"""
        if self.generation_started_at and self.generation_completed_at:
            delta = self.generation_completed_at - self.generation_started_at
            return delta.total_seconds()
        return None

    def to_dict(self) -> dict:
        """Serialize report to dictionary for API response"""
        return {
            "id": str(self.id),
            "name": self.name,
            "type": self.report_type.value if self.report_type else None,
            "format": self.format.value if self.format else None,
            "status": self.status.value if self.status else None,
            "assessmentId": str(self.assessment_id) if self.assessment_id else None,
            "assessment": {
                "id": str(self.assessment.id),
                "name": self.assessment.name,
            } if self.assessment else None,
            "options": self.options or {},
            "templatePath": self.template_path,
            "filePath": self.file_path,
            "fileSize": self.file_size,
            "pageCount": self.page_count,
            "downloadUrl": self.download_url,
            "errorMessage": self.error_message,
            "generationStartedAt": self.generation_started_at.isoformat() if self.generation_started_at else None,
            "generationCompletedAt": self.generation_completed_at.isoformat() if self.generation_completed_at else None,
            "generationDuration": self.generation_duration,
            "generatedBy": {
                "id": str(self.generated_by.id),
                "name": self.generated_by.full_name if hasattr(self.generated_by, 'full_name') else self.generated_by.username,
                "initials": self._get_user_initials(),
            } if self.generated_by else None,
            "createdAt": self.created_at.isoformat(),
            "updatedAt": self.updated_at.isoformat(),
        }

    def _get_user_initials(self) -> str:
        """Get initials from generated_by user"""
        if not self.generated_by:
            return "??"
        name = getattr(self.generated_by, "full_name", None) or getattr(self.generated_by, "username", "")
        if name:
            parts = name.split()
            return "".join(p[0].upper() for p in parts[:2])
        return "??"