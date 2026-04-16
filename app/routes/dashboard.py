"""
GAZE Security Platform - Dashboard Routes
"""
from datetime import datetime, timezone, timedelta

from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required, current_user
from sqlalchemy import func

from app import db
from app.models import Asset, Assessment, Finding, Severity, FindingStatus, Product

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
@login_required
def index():
    """Main dashboard - HTML version"""
    stats = get_dashboard_stats()
    return render_template('dashboard/index.html', stats=stats)


@dashboard_bp.route('/stats')
@login_required
def api_stats():
    """Dashboard statistics API"""
    stats = get_dashboard_stats()
    return jsonify({
        'success': True,
        'data': stats
    })


@dashboard_bp.route('/trends')
@login_required
def api_findings_trend():
    """Findings trend over time (last 12 months)"""
    days = request.args.get('days', 180, type=int)
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days)
    
    # Get monthly finding counts
    findings = db.session.query(
        func.date_trunc('month', Finding.created_at).label('month'),
        Finding.severity,
        func.count(Finding.id).label('count')
    ).filter(
        Finding.created_at >= start_date
    ).group_by(
        func.date_trunc('month', Finding.created_at),
        Finding.severity
    ).all()
    
    # Organize data by month
    trend_data = {}
    for finding in findings:
        month_str = finding.month.strftime('%Y-%m')
        if month_str not in trend_data:
            trend_data[month_str] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        severity_val = finding.severity.value
        # Map 'informational' -> 'info' for frontend
        if severity_val == 'informational':
            severity_val = 'info'
        trend_data[month_str][severity_val] = finding.count

    # Fill in missing months
    current = start_date.replace(day=1)
    while current <= end_date:
        month_str = current.strftime('%Y-%m')
        if month_str not in trend_data:
            trend_data[month_str] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        current = (current + timedelta(days=32)).replace(day=1)

    # Sort by month; use 'date' key (frontend TrendData expects 'date')
    sorted_data = [{'date': k, **v} for k, v in sorted(trend_data.items())]
    
    return jsonify({
        'success': True,
        'data': sorted_data
    })


@dashboard_bp.route('/severity-distribution')
@login_required
def api_severity_distribution():
    """Current severity distribution of open findings"""
    distribution = db.session.query(
        Finding.severity,
        func.count(Finding.id).label('count')
    ).filter(
        Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS])
    ).group_by(
        Finding.severity
    ).all()
    
    result = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'informational': 0
    }
    
    for item in distribution:
        result[item.severity.value] = item.count
    
    return jsonify({
        'success': True,
        'data': result
    })


@dashboard_bp.route('/overdue-findings')
@login_required
def api_overdue_findings():
    """Get overdue findings"""
    today = datetime.now(timezone.utc).date()
    
    overdue = Finding.query.filter(
        Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS]),
        Finding.sla_due_date < today
    ).order_by(
        Finding.sla_due_date.asc()
    ).limit(10).all()
    
    return jsonify({
        'success': True,
        'data': [{
            'id': str(f.id),
            'title': f.title,
            'severity': f.severity.value,
            'sla_due_date': f.sla_due_date.isoformat(),
            'days_overdue': (today - f.sla_due_date).days,
            'assessment': f.assessment.name if f.assessment else None,
            'asset': f.assessment.asset.name if f.assessment and f.assessment.asset else None,
        } for f in overdue]
    })


@dashboard_bp.route('/activity')
@login_required
def api_recent_activity():
    """Recent activity feed — returns ActivityItem format for the frontend"""
    from app.models import AuditLog, User

    limit = request.args.get('limit', 20, type=int)

    recent = AuditLog.query.filter(
        AuditLog.action.in_([
            'finding.created', 'finding.status.changed',
            'assessment.created', 'assessment.completed',
            'asset.created', 'user.login',
        ])
    ).order_by(
        AuditLog.created_at.desc()
    ).limit(limit).all()

    # Map action names to human-readable descriptions
    ACTION_LABELS = {
        'finding.created':         ('finding',    'Created finding'),
        'finding.status.changed':  ('finding',    'Updated finding status'),
        'assessment.created':      ('assessment', 'Created assessment'),
        'assessment.completed':    ('assessment', 'Completed assessment'),
        'asset.created':           ('asset',      'Added new asset'),
        'user.login':              ('user',        'Logged in'),
    }

    items = []
    for log in recent:
        label = ACTION_LABELS.get(log.action, ('finding', log.action))
        entity_type, description = label

        # Look up user name
        user_name = log.user_email or 'System'
        if log.user_id:
            user_obj = User.query.get(log.user_id)
            if user_obj:
                user_name = user_obj.full_name

        parts = user_name.split()
        initials = ''.join(p[0].upper() for p in parts[:2]) or '??'

        items.append({
            'id': str(log.id),
            'type': entity_type,
            'action': log.action,
            'description': description,
            'user': {
                'id': str(log.user_id) if log.user_id else None,
                'name': user_name,
                'email': log.user_email,
                'initials': initials,
            },
            'entityId': str(log.resource_id) if log.resource_id else None,
            'timestamp': log.created_at.isoformat(),
        })

    return jsonify({
        'success': True,
        'data': items
    })


def get_dashboard_stats() -> dict:
    """Calculate dashboard statistics matching frontend DashboardStats interface"""
    from app.models.assessment import AssessmentStatus
    
    today = datetime.now(timezone.utc).date()
    this_week = today + timedelta(days=7)
    
    # ==========================================================================
    # FINDINGS STATS
    # ==========================================================================
    total_findings = Finding.query.count()
    
    open_findings = Finding.query.filter(
        Finding.status == FindingStatus.OPEN
    ).count()
    
    in_progress_findings = Finding.query.filter(
        Finding.status == FindingStatus.IN_PROGRESS
    ).count()
    
    resolved_findings = Finding.query.filter(
        Finding.status.in_([FindingStatus.REMEDIATED])
    ).count()
    
    # Findings by severity (all open/in-progress)
    severity_counts = db.session.query(
        Finding.severity,
        func.count(Finding.id)
    ).filter(
        Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS])
    ).group_by(Finding.severity).all()
    
    severity_dict = {s.value: 0 for s in Severity}
    for sev, count in severity_counts:
        severity_dict[sev.value] = count
    
    # ==========================================================================
    # ASSESSMENTS STATS
    # ==========================================================================
    total_assessments = Assessment.query.count()
    
    in_progress_assessments = Assessment.query.filter(
        Assessment.status == AssessmentStatus.IN_PROGRESS
    ).count()
    
    completed_assessments = Assessment.query.filter(
        Assessment.status == AssessmentStatus.COMPLETED
    ).count()
    
    planned_assessments = Assessment.query.filter(
        Assessment.status == AssessmentStatus.PLANNED
    ).count()
    
    # ==========================================================================
    # ASSETS STATS
    # ==========================================================================
    total_assets = Asset.query.count()
    
    # Assets with critical/high findings are "at risk"
    at_risk_assets = db.session.query(
        func.count(func.distinct(Assessment.asset_id))
    ).join(Finding).filter(
        Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS]),
        Finding.severity.in_([Severity.CRITICAL, Severity.HIGH])
    ).scalar() or 0
    
    secure_assets = total_assets - at_risk_assets
    
    # ==========================================================================
    # SLA STATS
    # ==========================================================================
    overdue = Finding.query.filter(
        Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS]),
        Finding.sla_due_date < today
    ).count()
    
    due_this_week = Finding.query.filter(
        Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS]),
        Finding.sla_due_date >= today,
        Finding.sla_due_date <= this_week
    ).count()
    
    # Calculate compliance rate (findings remediated on time vs total remediated)
    total_remediated = Finding.query.filter(
        Finding.status.in_([FindingStatus.REMEDIATED])
    ).count()
    
    on_time_remediated = Finding.query.filter(
        Finding.status.in_([FindingStatus.REMEDIATED]),
        Finding.remediated_at <= func.cast(Finding.sla_due_date, db.DateTime)
    ).count() if total_remediated > 0 else 0
    
    compliance_rate = round((on_time_remediated / total_remediated) * 100) if total_remediated > 0 else 100
    
    # ==========================================================================
    # RETURN FORMATTED RESPONSE
    # ==========================================================================
    return {
        'findings': {
            'total': total_findings,
            'open': open_findings,
            'inProgress': in_progress_findings,
            'resolved': resolved_findings,
            'bySeverity': {
                'critical': severity_dict.get('critical', 0),
                'high': severity_dict.get('high', 0),
                'medium': severity_dict.get('medium', 0),
                'low': severity_dict.get('low', 0),
                'info': severity_dict.get('informational', 0),
            }
        },
        'assessments': {
            'total': total_assessments,
            'inProgress': in_progress_assessments,
            'completed': completed_assessments,
            'planned': planned_assessments,
        },
        'assets': {
            'total': total_assets,
            'atRisk': at_risk_assets,
            'secure': secure_assets,
        },
        'products': {
            'total': Product.query.count(),
            'avgSecurityScore': round(
                db.session.query(func.avg(Product.security_score)).scalar() or 0, 1
            ),
        },
        'sla': {
            'overdue': overdue,
            'dueThisWeek': due_this_week,
            'complianceRate': compliance_rate,
        }
    }