"""
GAZE Security Platform - Product Model
"""
from datetime import datetime, timezone
from enum import Enum
from typing import List
import uuid

from sqlalchemy import Column, String, Text, DateTime, ForeignKey, Enum as SQLEnum, Integer, Float, JSON
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import relationship

from app import db


class ProductStatus(str, Enum):
    ACTIVE = "active"
    DEVELOPMENT = "development"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"


class Criticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Product(db.Model):
    """Product/Application being assessed"""
    __tablename__ = 'products'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    short_name = Column(String(50), nullable=False)
    description = Column(Text)
    status = Column(SQLEnum(ProductStatus), default=ProductStatus.ACTIVE, nullable=False)
    criticality = Column(SQLEnum(Criticality), default=Criticality.MEDIUM, nullable=False)
    
    # Owner
    owner_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    owner = relationship('User', foreign_keys=[owner_id], backref='owned_products')
    
    # Security metrics
    security_score = Column(Float, default=0.0)
    compliance = Column(ARRAY(String), default=list)
    
    # Timestamps
    last_assessment_at = Column(DateTime(timezone=True))
    next_assessment_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), 
                       onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationships
    assets = relationship('Asset', back_populates='product', lazy='dynamic')
    team_members = relationship('User', secondary='product_team', backref='team_products')
    
    def __repr__(self):
        return f'<Product {self.short_name}>'
    
    @property
    def assets_count(self) -> int:
        return self.assets.count() if self.assets else 0
    
    @property
    def findings_count(self) -> dict:
        """Get findings count by severity across all assets"""
        from app.models import Finding, Severity
        
        counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'total': 0
        }
        
        for asset in self.assets:
            for assessment in asset.assessments:
                for finding in assessment.findings:
                    severity = finding.severity.value if finding.severity else 'info'
                    if severity == 'informational':
                        severity = 'info'
                    if severity in counts:
                        counts[severity] += 1
                    counts['total'] += 1
        
        return counts
    
    def to_dict(self, include_team: bool = False) -> dict:
        data = {
            'id': str(self.id),
            'name': self.name,
            'shortName': self.short_name,
            'description': self.description,
            'status': self.status.value,
            'criticality': self.criticality.value,
            'ownerId': str(self.owner_id),
            'owner': {
                'id': str(self.owner.id),
                'name': self.owner.full_name,
                'email': self.owner.email
            } if self.owner else None,
            'securityScore': self.security_score or 0,
            'compliance': self.compliance or [],
            'assetsCount': self.assets_count,
            'findingsCount': self.findings_count,
            'lastAssessment': self.last_assessment_at.isoformat() if self.last_assessment_at else None,
            'nextAssessment': self.next_assessment_at.isoformat() if self.next_assessment_at else None,
            'createdAt': self.created_at.isoformat(),
            'updatedAt': self.updated_at.isoformat(),
        }
        
        if include_team:
            data['teamMembers'] = [
                {'id': str(m.id), 'name': m.full_name, 'email': m.email}
                for m in self.team_members
            ]
        
        return data


# Association table for product team members
product_team = db.Table(
    'product_team',
    Column('product_id', UUID(as_uuid=True), ForeignKey('products.id'), primary_key=True),
    Column('user_id', UUID(as_uuid=True), ForeignKey('users.id'), primary_key=True),
)