"""
GAZE Security Platform - Asset Model
Updated to match Next.js frontend expectations
"""
import uuid
import json
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import Column, String, Text, DateTime, ForeignKey, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app import db


class AssetType(str, Enum):
    WEB_APPLICATION = "web_application"
    MOBILE_APP = "mobile_app"
    API = "api"
    NETWORK = "network"
    CLOUD_INFRASTRUCTURE = "cloud_infrastructure"
    DATABASE = "database"
    IOT_DEVICE = "iot_device"
    OTHER = "other"


class AssetCriticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# Mapping backend enum values to frontend expected values
BACKEND_TO_FRONTEND_TYPE = {
    'web_application': 'web',
    'mobile_app': 'mobile',
    'api': 'api',
    'database': 'database',
    'cloud_infrastructure': 'cloud',
    'network': 'network',
    'iot_device': 'iot',
    'other': 'other'
}


class Asset(db.Model):
    """Asset model for tracking organizational assets"""
    __tablename__ = 'assets'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    
    # Classification
    asset_type = Column(SQLEnum(AssetType), nullable=False, default=AssetType.WEB_APPLICATION)
    criticality = Column(SQLEnum(AssetCriticality), nullable=False, default=AssetCriticality.MEDIUM)
    
    # Technical details
    url = Column(String(500), nullable=True)
    ip_address = Column(String(45), nullable=True)
    hostname = Column(String(255), nullable=True)
    environment = Column(String(50), nullable=True)  # production, staging, development
    
    # Ownership
    business_owner = Column(String(255), nullable=True)
    technical_owner = Column(String(255), nullable=True)
    team = Column(String(100), nullable=True)
    
    # Product relationship
    product_id = Column(UUID(as_uuid=True), ForeignKey('products.id'), nullable=True)
    product = relationship('Product', back_populates='assets')
    
    # Metadata
    tags = Column(Text, nullable=True)  # JSON array - used for technologies
    notes = Column(Text, nullable=True)
    
    # Audit
    created_by_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationships
    created_by = relationship('User', back_populates='created_assets', foreign_keys=[created_by_id])
    assessments = relationship('Assessment', back_populates='asset', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Asset {self.name}>'
    
    @property
    def total_assessments(self) -> int:
        return len(self.assessments)
    
    @property
    def open_findings_count(self) -> int:
        count = 0
        for assessment in self.assessments:
            count += sum(1 for f in assessment.findings if f.status in ['open', 'in_progress'])
        return count
    
    @property
    def technologies(self) -> list:
        """Parse technologies from tags field"""
        if self.tags:
            try:
                return json.loads(self.tags)
            except (json.JSONDecodeError, TypeError):
                return []
        return []
    
    @property
    def last_assessment_date(self):
        """Get the date of the most recent assessment"""
        if self.assessments:
            sorted_assessments = sorted(
                self.assessments, 
                key=lambda a: a.created_at, 
                reverse=True
            )
            return sorted_assessments[0].created_at
        return None
    
    def to_dict(self) -> dict:
        """Convert asset to dictionary matching frontend expectations"""
        # Get product info if exists
        product_info = None
        if self.product:
            product_info = {
                'id': str(self.product.id),
                'name': self.product.name,
                'shortName': self.product.short_name if hasattr(self.product, 'short_name') else self.product.name
            }
        
        # Calculate findings count
        findings_count = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'total': 0
        }
        for assessment in self.assessments:
            for finding in assessment.findings:
                severity = finding.severity.value if finding.severity else 'info'
                severity = severity.lower()
                if severity == 'informational':
                    severity = 'info'
                if severity in findings_count:
                    findings_count[severity] += 1
                findings_count['total'] += 1
        
        # Determine status based on findings
        status = 'secure'
        if findings_count['critical'] > 0 or findings_count['high'] > 0:
            status = 'at-risk'
        elif findings_count['medium'] > 0:
            status = 'moderate'
        elif findings_count['total'] > 0:
            status = 'moderate'
        
        # Get last assessment date
        last_assessment = None
        if self.last_assessment_date:
            last_assessment = self.last_assessment_date.isoformat()
        
        # Convert backend asset_type to frontend type
        frontend_type = BACKEND_TO_FRONTEND_TYPE.get(
            self.asset_type.value if self.asset_type else 'web_application',
            'web'
        )
        
        return {
            'id': str(self.id),
            'name': self.name,
            'description': self.description or '',
            'type': frontend_type,  # Frontend format: web, mobile, api, etc
            'criticality': self.criticality.value if self.criticality else 'medium',
            'environment': self.environment or 'production',
            'status': status,
            'url': self.url,
            'ipAddress': self.ip_address,
            'hostname': self.hostname,
            'technologies': self.technologies,  # Parse from tags JSON
            'owner': self.business_owner or self.technical_owner or '',
            'team': self.team,
            'product': product_info,
            'productId': str(self.product_id) if self.product_id else '',
            'findingsCount': findings_count,
            'lastAssessment': last_assessment,
            'nextAssessment': '',  # TODO: Implement scheduling
            'createdAt': self.created_at.isoformat() if self.created_at else '',
            'updatedAt': self.updated_at.isoformat() if self.updated_at else '',
        }