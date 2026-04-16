"""
GAZE Security Platform - Assessment Model
"""
import uuid
from datetime import datetime, timezone, date
from enum import Enum

from sqlalchemy import Column, String, Text, DateTime, Date, ForeignKey, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app import db


class AssessmentType(str, Enum):
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    PENETRATION_TEST = "penetration_test"
    CODE_REVIEW = "code_review"
    CONFIGURATION_REVIEW = "configuration_review"
    COMPLIANCE_AUDIT = "compliance_audit"
    RED_TEAM = "red_team"
    BUG_BOUNTY = "bug_bounty"


class AssessmentStatus(str, Enum):
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    PENDING_REVIEW = "pending_review"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class Assessment(db.Model):
    """Assessment model for security assessments"""
    __tablename__ = 'assessments'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    
    # Type and status
    assessment_type = Column(SQLEnum(AssessmentType), nullable=False, default=AssessmentType.VULNERABILITY_ASSESSMENT)
    status = Column(SQLEnum(AssessmentStatus), nullable=False, default=AssessmentStatus.PLANNED)
    
    # Scope
    scope_description = Column(Text, nullable=True)
    methodology = Column(Text, nullable=True)
    
    # Schedule
    scheduled_start = Column(Date, nullable=True)
    scheduled_end = Column(Date, nullable=True)
    actual_start = Column(DateTime(timezone=True), nullable=True)
    actual_end = Column(DateTime(timezone=True), nullable=True)
    
    # References
    asset_id = Column(UUID(as_uuid=True), ForeignKey('assets.id'), nullable=True)
    assigned_to_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    
    # Notes
    notes = Column(Text, nullable=True)
    executive_summary = Column(Text, nullable=True)
    
    # Audit
    created_by_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationships
    asset = relationship('Asset', back_populates='assessments')
    created_by = relationship('User', back_populates='created_assessments', foreign_keys=[created_by_id])
    assigned_to = relationship('User', back_populates='assigned_assessments', foreign_keys=[assigned_to_id])
    findings = relationship('Finding', back_populates='assessment', cascade='all, delete-orphan')
    reports = relationship('Report', back_populates='assessment', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Assessment {self.name}>'
    
    @property
    def findings_count(self) -> dict:
        """Count findings by severity (frontend-compatible keys)"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0}
        for finding in self.findings:
            sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            # Map informational → info
            if sev == 'informational':
                sev = 'info'
            if sev in counts:
                counts[sev] += 1
            counts['total'] += 1
        return counts
    
    @property
    def open_findings(self) -> int:
        return sum(1 for f in self.findings if f.status in ['open', 'in_progress'])
    
    def start(self) -> None:
        """Start the assessment"""
        self.status = AssessmentStatus.IN_PROGRESS
        self.actual_start = datetime.now(timezone.utc)
    
    def complete(self) -> None:
        """Complete the assessment"""
        self.status = AssessmentStatus.COMPLETED
        self.actual_end = datetime.now(timezone.utc)
    
    def to_dict(self) -> dict:
        # Build nested assignee object matching frontend UserRef shape
        assignee_obj = None
        if self.assigned_to:
            parts = (self.assigned_to.full_name or '').split()
            initials = ''.join(p[0].upper() for p in parts[:2]) or '??'
            assignee_obj = {
                'id': str(self.assigned_to_id),
                'name': self.assigned_to.full_name,
                'email': self.assigned_to.email,
                'initials': initials,
            }

        # Build nested asset object matching frontend AssetRef shape
        asset_obj = None
        if self.asset:
            asset_obj = {
                'id': str(self.asset_id),
                'name': self.asset.name,
            }

        return {
            'id': str(self.id),
            'name': self.name,
            'description': self.description,
            'type': self.assessment_type.value,
            'status': self.status.value,
            'priority': 'medium',
            'progress': 0,
            'scope': self.scope_description,
            'methodology': self.methodology,
            # camelCase dates for frontend
            'startDate': self.scheduled_start.isoformat() if self.scheduled_start else None,
            'dueDate': self.scheduled_end.isoformat() if self.scheduled_end else None,
            'actualStart': self.actual_start.isoformat() if self.actual_start else None,
            'actualEnd': self.actual_end.isoformat() if self.actual_end else None,
            'asset': asset_obj,
            'assetId': str(self.asset_id) if self.asset_id else None,
            'assignee': assignee_obj,
            'assigneeId': str(self.assigned_to_id) if self.assigned_to_id else None,
            'findingsCount': self.findings_count,
            'openFindings': self.open_findings,
            'createdBy': self.created_by.full_name if self.created_by else None,
            'createdAt': self.created_at.isoformat(),
            'updatedAt': self.updated_at.isoformat(),
        }
