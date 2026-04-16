"""
GAZE Security Platform - Assessments Routes
"""
from datetime import datetime, timezone
from flask import Blueprint, request, render_template, jsonify
from flask_login import login_required, current_user

from app import db
from app.models import Assessment, AssessmentType, AssessmentStatus, Asset
from app.security import require_permission, Permission, AuditLogger, AuditAction, Sanitizer, require_api_key_or_login

assessments_bp = Blueprint('assessments', __name__)


@assessments_bp.route('/')
@require_api_key_or_login(scope='mcp')
# @login_required
def index():
    """List all assessments"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('perPage', 20, type=int)
    status = request.args.get('status', '')
    
    query = Assessment.query
    
    if status:
        try:
            query = query.filter(Assessment.status == AssessmentStatus(status))
        except ValueError:
            pass
    
    assessments = query.order_by(Assessment.created_at.desc()).paginate(page=page, per_page=per_page)
    
    return jsonify({
        'success': True,
        'data': {
            'items': [a.to_dict() for a in assessments.items],
            'meta': {
                'page': page,
                'perPage': per_page,
                'totalPages': assessments.pages,
                'totalItems': assessments.total,
            }
        }
    })


@assessments_bp.route('/new', methods=['POST'])
@require_api_key_or_login(scope='mcp')
# @login_required
@require_permission(Permission.ASSESSMENT_CREATE)
def create():
    """Create new assessment"""
    from datetime import date as date_type

    data = request.get_json() or {}

    # Accept both camelCase (from frontend) and snake_case (direct API calls)
    assessment_type_raw = data.get('type') or data.get('assessment_type', 'vulnerability_assessment')
    asset_id = data.get('assetId') or data.get('asset_id') or None
    assigned_to_id = data.get('assigneeId') or data.get('assigned_to_id') or None
    start_date_raw = data.get('startDate') or data.get('start_date') or data.get('scheduled_start')
    due_date_raw = data.get('dueDate') or data.get('due_date') or data.get('scheduled_end')
    scope = data.get('scope') or data.get('scope_description')
    methodology = data.get('methodology')

    # Validate enum — fall back gracefully for frontend-only types not yet in the DB enum
    try:
        assessment_type = AssessmentType(assessment_type_raw)
    except ValueError:
        assessment_type = AssessmentType.VULNERABILITY_ASSESSMENT

    def parse_date(val):
        if not val:
            return None
        try:
            return date_type.fromisoformat(str(val)[:10])
        except ValueError:
            return None

    assessment = Assessment(
        name=Sanitizer.clean_text(data.get('name'), max_length=255),
        description=Sanitizer.clean_html(data.get('description', ''), allow_html=True),
        assessment_type=assessment_type,
        asset_id=asset_id,
        assigned_to_id=assigned_to_id,
        scheduled_start=parse_date(start_date_raw),
        scheduled_end=parse_date(due_date_raw),
        scope_description=scope,
        methodology=methodology,
        created_by_id=current_user.id,
    )

    db.session.add(assessment)
    db.session.commit()

    AuditLogger.log(
        action=AuditAction.ASSESSMENT_CREATED,
        resource_type='assessment',
        resource_id=assessment.id
    )

    return jsonify({'success': True, 'data': assessment.to_dict()}), 201


@assessments_bp.route('/<uuid:assessment_id>')
@require_api_key_or_login(scope='mcp')
# @login_required
@require_permission(Permission.ASSESSMENT_READ)
def view(assessment_id):
    """View assessment details including findings"""
    assessment = Assessment.query.get_or_404(assessment_id)
    data = assessment.to_dict()
    # Include findings for detail view
    data['findings'] = [f.to_dict(include_poc=False) for f in assessment.findings]
    return jsonify({'success': True, 'data': data})

@assessments_bp.route('/<uuid:assessment_id>', methods=['PUT'])
@login_required
@require_permission(Permission.ASSESSMENT_UPDATE)
def update(assessment_id):
    """Update an assessment"""
    from datetime import date as date_type

    assessment = Assessment.query.get_or_404(assessment_id)
    data = request.get_json() or {}

    def parse_date(val):
        if not val:
            return None
        try:
            return date_type.fromisoformat(str(val)[:10])
        except ValueError:
            return None

    if 'name' in data:
        assessment.name = Sanitizer.clean_text(data['name'], max_length=255)
    if 'description' in data:
        assessment.description = Sanitizer.clean_html(data['description'], allow_html=True)
    if 'type' in data or 'assessment_type' in data:
        raw = data.get('type') or data.get('assessment_type')
        try:
            assessment.assessment_type = AssessmentType(raw)
        except ValueError:
            pass
    if 'assetId' in data or 'asset_id' in data:
        assessment.asset_id = data.get('assetId') or data.get('asset_id') or None
    if 'assigneeId' in data or 'assigned_to_id' in data:
        assessment.assigned_to_id = data.get('assigneeId') or data.get('assigned_to_id') or None
    if 'startDate' in data or 'start_date' in data or 'scheduled_start' in data:
        raw = data.get('startDate') or data.get('start_date') or data.get('scheduled_start')
        assessment.scheduled_start = parse_date(raw)
    if 'dueDate' in data or 'due_date' in data or 'scheduled_end' in data:
        raw = data.get('dueDate') or data.get('due_date') or data.get('scheduled_end')
        assessment.scheduled_end = parse_date(raw)
    if 'scope' in data or 'scope_description' in data:
        assessment.scope_description = data.get('scope') or data.get('scope_description')
    if 'methodology' in data:
        assessment.methodology = data['methodology']
    if 'notes' in data:
        assessment.notes = data['notes']
    if 'executive_summary' in data:
        assessment.executive_summary = data['executive_summary']

    db.session.commit()

    AuditLogger.log(
        action=AuditAction.ASSESSMENT_UPDATED,
        resource_type='assessment',
        resource_id=assessment.id
    )

    return jsonify({'success': True, 'data': assessment.to_dict()})


@assessments_bp.route('/<uuid:assessment_id>/status', methods=['PATCH', 'POST'])
@login_required
@require_permission(Permission.ASSESSMENT_UPDATE)
def update_status(assessment_id):
    """Update assessment status"""
    assessment = Assessment.query.get_or_404(assessment_id)
    data = request.get_json() or {}
    new_status = data.get('status')

    if not new_status:
        return jsonify({'success': False, 'error': 'Status is required'}), 400

    try:
        assessment.status = AssessmentStatus(new_status)
        if new_status == 'in_progress' and not assessment.actual_start:
            assessment.actual_start = datetime.now(timezone.utc)
        elif new_status == 'completed' and not assessment.actual_end:
            assessment.actual_end = datetime.now(timezone.utc)
        db.session.commit()
    except ValueError:
        return jsonify({'success': False, 'error': f'Invalid status: {new_status}'}), 400

    AuditLogger.log(
        action=AuditAction.ASSESSMENT_UPDATED,
        resource_type='assessment',
        resource_id=assessment.id,
        changes={'status': new_status}
    )

    return jsonify({'success': True, 'data': assessment.to_dict()})


@assessments_bp.route('/<uuid:assessment_id>/findings')
@require_api_key_or_login(scope='mcp')
# @login_required
@require_permission(Permission.FINDING_READ)
def get_findings(assessment_id):
    """Get all findings for an assessment"""
    assessment = Assessment.query.get_or_404(assessment_id)
    return jsonify({
        'success': True,
        'data': [f.to_dict() for f in assessment.findings]
    })


@assessments_bp.route('/<uuid:assessment_id>', methods=['DELETE'])
@login_required
@require_permission(Permission.ASSESSMENT_DELETE)
def delete(assessment_id):
    """Delete an assessment"""
    assessment = Assessment.query.get_or_404(assessment_id)

    # Store info for audit log before deletion
    assessment_name = assessment.name
    assessment_type = assessment.assessment_type.value

    try:
        db.session.delete(assessment)
        db.session.commit()

        AuditLogger.log(
            action=AuditAction.ASSESSMENT_DELETED,
            resource_type='assessment',
            resource_id=str(assessment_id),
            changes={
                'name': assessment_name,
                'type': assessment_type
            }
        )

        return jsonify({
            'success': True,
            'message': 'Assessment deleted successfully'
        }), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@assessments_bp.route('/<uuid:assessment_id>/start', methods=['POST'])
@require_api_key_or_login(scope='mcp')
# @login_required
@require_permission(Permission.ASSESSMENT_UPDATE)
def start(assessment_id):
    """Start an assessment"""
    assessment = Assessment.query.get_or_404(assessment_id)
    assessment.start()
    db.session.commit()
    
    AuditLogger.log(
        action=AuditAction.ASSESSMENT_STARTED,
        resource_type='assessment',
        resource_id=assessment.id
    )
    
    return jsonify(assessment.to_dict())


@assessments_bp.route('/<uuid:assessment_id>/complete', methods=['POST'])
@require_api_key_or_login(scope='mcp')
# @login_required
@require_permission(Permission.ASSESSMENT_UPDATE)
def complete(assessment_id):
    """Complete an assessment"""
    assessment = Assessment.query.get_or_404(assessment_id)
    assessment.complete()
    db.session.commit()
    
    AuditLogger.log(
        action=AuditAction.ASSESSMENT_COMPLETED,
        resource_type='assessment',
        resource_id=assessment.id
    )
    
    return jsonify(assessment.to_dict())