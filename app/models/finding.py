"""
GAZE Security Platform - Finding Model
Security finding with remediation tracking
"""
import uuid
from datetime import datetime, timezone, timedelta
from enum import Enum

from sqlalchemy import Column, String, Text, DateTime, Date, Float, ForeignKey, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app import db


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    ACCEPTED = "accepted"  # Risk accepted
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"


# SLA days by severity
SLA_DAYS = {
    Severity.CRITICAL: 7,
    Severity.HIGH: 30,
    Severity.MEDIUM: 90,
    Severity.LOW: 180,
    Severity.INFORMATIONAL: None,  # No SLA
}


class Finding(db.Model):
    """Security finding model with full vulnerability details"""
    __tablename__ = 'findings'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String(500), nullable=False, index=True)
    description = Column(Text, nullable=False)
    
    # Classification
    severity = Column(SQLEnum(Severity), nullable=False, default=Severity.MEDIUM)
    status = Column(SQLEnum(FindingStatus), nullable=False, default=FindingStatus.OPEN)
    
    # CVSS
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(100), nullable=True)
    
    # References
    cwe_id = Column(String(20), nullable=True)  # e.g., CWE-79
    cve_id = Column(String(20), nullable=True)  # e.g., CVE-2023-1234
    owasp_category = Column(String(100), nullable=True)  # e.g., A01:2021
    
    # Technical details
    affected_component = Column(String(500), nullable=True)
    affected_url = Column(Text, nullable=True)
    affected_parameter = Column(String(255), nullable=True)
    
    # Reproduction
    steps_to_reproduce = Column(Text, nullable=True)
    poc_code = Column(Text, nullable=True)
    
    # Impact & remediation
    impact = Column(Text, nullable=True)
    root_cause = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    remediation_notes = Column(Text, nullable=True)
    
    # SLA tracking
    sla_due_date = Column(Date, nullable=True)
    remediated_at = Column(DateTime(timezone=True), nullable=True)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    
    # References
    assessment_id = Column(UUID(as_uuid=True), ForeignKey('assessments.id'), nullable=True)

    # Asset 
    # asset_id = Column(UUID(as_uuid=True), ForeignKey('assets.id'), nullable=True)
    
    # Audit
    created_by_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationships
    assessment = relationship('Assessment', back_populates='findings')
    created_by = relationship('User', back_populates='created_findings', foreign_keys=[created_by_id])
    evidence = relationship('Evidence', back_populates='finding', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Finding {self.title[:50]}>'
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Auto-set SLA due date based on severity
        if not self.sla_due_date and self.severity:
            self.calculate_sla()
    
    def calculate_sla(self) -> None:
        """Calculate SLA due date based on severity"""
        sla_days = SLA_DAYS.get(self.severity)
        if sla_days:
            self.sla_due_date = (datetime.now(timezone.utc) + timedelta(days=sla_days)).date()
    
    @property
    def is_overdue(self) -> bool:
        """Check if finding is past SLA"""
        if not self.sla_due_date:
            return False
        if self.status in [FindingStatus.REMEDIATED, FindingStatus.ACCEPTED, FindingStatus.FALSE_POSITIVE]:
            return False
        return datetime.now(timezone.utc).date() > self.sla_due_date
    
    @property
    def days_until_due(self) -> int:
        """Days until SLA due date (negative if overdue)"""
        if not self.sla_due_date:
            return None
        return (self.sla_due_date - datetime.now(timezone.utc).date()).days
    
    @property
    def sla_status(self) -> str:
        """Human-readable SLA status"""
        if not self.sla_due_date:
            return "No SLA"
        if self.status in [FindingStatus.REMEDIATED, FindingStatus.ACCEPTED]:
            return "Closed"
        
        days = self.days_until_due
        if days < 0:
            return f"Overdue ({abs(days)} days)"
        elif days <= 7:
            return f"Due soon ({days} days)"
        else:
            return f"On track ({days} days)"
    
    def mark_remediated(self) -> None:
        """Mark finding as remediated"""
        self.status = FindingStatus.REMEDIATED
        self.remediated_at = datetime.now(timezone.utc)
    
    def verify_remediation(self) -> None:
        """Verify the remediation"""
        self.verified_at = datetime.now(timezone.utc)
    
    def reopen(self) -> None:
        """Reopen a closed finding"""
        self.status = FindingStatus.OPEN
        self.remediated_at = None
        self.verified_at = None
    
    def to_dict(self, include_poc: bool = False) -> dict:
        assessment_ref = None
        if self.assessment:
            assessment_ref = {
                'id': str(self.assessment.id),
                'name': self.assessment.name,
            }

        # Map informational → info for frontend compatibility
        severity_value = self.severity.value
        if severity_value == 'informational':
            severity_value = 'info'

        data = {
            'id': str(self.id),
            'title': self.title,
            'description': self.description,
            'severity': severity_value,
            'status': self.status.value,
            # camelCase for frontend normalizeKeys compatibility
            'cvssScore': self.cvss_score,
            'cvssVector': self.cvss_vector,
            'cweId': self.cwe_id,
            'cveId': self.cve_id,
            'owaspCategory': self.owasp_category,
            'affectedComponent': self.affected_component,
            'affectedUrl': self.affected_url,
            'affectedParameter': self.affected_parameter,
            'impact': self.impact,
            'recommendation': self.recommendation,
            'slaDueDate': self.sla_due_date.isoformat() if self.sla_due_date else None,
            'slaStatus': self.sla_status,
            'isOverdue': self.is_overdue,
            'daysUntilDue': self.days_until_due,
            'remediatedAt': self.remediated_at.isoformat() if self.remediated_at else None,
            'verifiedAt': self.verified_at.isoformat() if self.verified_at else None,
            'assessmentId': str(self.assessment_id) if self.assessment_id else None,
            'assessment': assessment_ref,
            'evidenceCount': len(self.evidence),
            'createdBy': self.created_by.full_name if self.created_by else None,
            'createdAt': self.created_at.isoformat(),
            'updatedAt': self.updated_at.isoformat(),
        }

        if include_poc:
            data['stepsToReproduce'] = self.steps_to_reproduce
            data['pocCode'] = self.poc_code
            data['rootCause'] = self.root_cause
            data['remediationNotes'] = self.remediation_notes
            data['evidence'] = [e.to_dict() for e in self.evidence]

        return data
