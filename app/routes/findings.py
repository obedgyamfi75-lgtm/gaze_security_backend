"""
GAZE Security Platform - Findings Routes
"""
from flask import Blueprint, request, render_template, jsonify
from flask_login import login_required, current_user
import structlog

from app import db
from app.models import Finding, Severity, FindingStatus, Assessment
from app.security import require_permission, Permission, AuditLogger, AuditAction, Sanitizer, require_api_key_or_login

logger = structlog.get_logger()

findings_bp = Blueprint('findings', __name__)


@findings_bp.route('/')
@require_api_key_or_login(scope='mcp')
# @login_required
def index():
    """List all findings"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('perPage', 20, type=int)  # Frontend sends perPage
        severity = request.args.get('severity', '')
        status = request.args.get('status', '')
        
        query = Finding.query
        
        if severity:
            try:
                query = query.filter(Finding.severity == Severity(severity))
            except ValueError:
                pass
        
        if status:
            try:
                query = query.filter(Finding.status == FindingStatus(status))
            except ValueError:
                pass
        
        findings = query.order_by(Finding.created_at.desc()).paginate(page=page, per_page=per_page)
        
        return jsonify({
            'success': True,
            'data': {
                'items': [f.to_dict() for f in findings.items],
                'meta': {
                    'page': page,
                    'perPage': per_page,
                    'totalPages': findings.pages,
                    'totalItems': findings.total,
                }
            }
        })
    except Exception:
        logger.error("findings_list_error", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        }), 500


@findings_bp.route('/new', methods=['GET', 'POST'])
@require_api_key_or_login(scope='mcp')
# @login_required
@require_permission(Permission.FINDING_CREATE)
def create():
    """Create new finding — accepts both camelCase (from API) and snake_case"""
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form

        # Accept camelCase or snake_case for all fields
        def get(camel, snake=None):
            return data.get(camel) or (data.get(snake) if snake else None)

        def _severity(val):
            v = val or 'medium'
            return Severity('informational' if v == 'info' else v)

        cvss_raw = get('cvssScore', 'cvss_score')
        finding = Finding(
            title=Sanitizer.clean_text(get('title'), max_length=500),
            description=Sanitizer.clean_html(get('description') or '', allow_html=True),
            severity=_severity(get('severity')),
            cvss_score=float(cvss_raw) if cvss_raw else None,
            cvss_vector=Sanitizer.clean_text(get('cvssVector', 'cvss_vector'), max_length=100),
            cwe_id=Sanitizer.clean_text(get('cweId', 'cwe_id'), max_length=20),
            cve_id=Sanitizer.clean_text(get('cveId', 'cve_id'), max_length=20),
            owasp_category=Sanitizer.clean_text(get('owaspCategory', 'owasp_category'), max_length=100),
            affected_component=Sanitizer.clean_text(get('affectedComponent', 'affected_component'), max_length=500),
            affected_url=Sanitizer.clean_text(get('affectedUrl', 'affected_url')),
            affected_parameter=Sanitizer.clean_text(get('affectedParameter', 'affected_parameter'), max_length=255),
            steps_to_reproduce=Sanitizer.clean_html(get('stepsToReproduce', 'steps_to_reproduce') or '', allow_html=True),
            poc_code=get('pocCode', 'poc_code') or '',
            impact=Sanitizer.clean_html(get('impact') or '', allow_html=True),
            recommendation=Sanitizer.clean_html(get('recommendation') or '', allow_html=True),
            assessment_id=get('assessmentId', 'assessment_id'),
            created_by_id=current_user.id
        )

        db.session.add(finding)
        db.session.commit()

        AuditLogger.log(
            action=AuditAction.FINDING_CREATED,
            resource_type='finding',
            resource_id=finding.id
        )

        return jsonify({'success': True, 'data': finding.to_dict(include_poc=True)}), 201

    assessments = Assessment.query.order_by(Assessment.created_at.desc()).all()
    return render_template('findings/form.html', finding=None, assessments=assessments, severities=Severity)



@findings_bp.route('/<uuid:finding_id>')
@require_api_key_or_login(scope='mcp')
# @login_required
@require_permission(Permission.FINDING_READ)
def view(finding_id):
    """View finding details"""
    finding = Finding.query.get_or_404(finding_id)
    return jsonify({'success': True, 'data': finding.to_dict(include_poc=True)})


@findings_bp.route('/<uuid:finding_id>', methods=['PUT'])
@require_api_key_or_login(scope='mcp')
# @login_required
@require_permission(Permission.FINDING_UPDATE)
def update(finding_id):
    """Update a finding — accepts camelCase or snake_case"""
    finding = Finding.query.get_or_404(finding_id)
    data = request.get_json() or {}

    def get(camel, snake=None):
        v = data.get(camel)
        if v is None and snake:
            v = data.get(snake)
        return v

    if get('title'):
        finding.title = Sanitizer.clean_text(get('title'), max_length=500)
    if get('description') is not None:
        finding.description = Sanitizer.clean_html(get('description') or '', allow_html=True)
    if get('severity'):
        try:
            sv = get('severity')
            finding.severity = Severity('informational' if sv == 'info' else sv)
            finding.calculate_sla()  # Recalculate SLA when severity changes
        except ValueError:
            pass
    if get('status'):
        try:
            new_status = FindingStatus(get('status'))
            finding.status = new_status
            if new_status == FindingStatus.REMEDIATED and not finding.remediated_at:
                finding.mark_remediated()
        except ValueError:
            pass
    if get('cvssScore', 'cvss_score') is not None:
        raw = get('cvssScore', 'cvss_score')
        finding.cvss_score = float(raw) if raw else None
    if get('cvssVector', 'cvss_vector') is not None:
        finding.cvss_vector = Sanitizer.clean_text(get('cvssVector', 'cvss_vector'), max_length=100)
    if get('cweId', 'cwe_id') is not None:
        finding.cwe_id = Sanitizer.clean_text(get('cweId', 'cwe_id'), max_length=20)
    if get('cveId', 'cve_id') is not None:
        finding.cve_id = Sanitizer.clean_text(get('cveId', 'cve_id'), max_length=20)
    if get('owaspCategory', 'owasp_category') is not None:
        finding.owasp_category = Sanitizer.clean_text(get('owaspCategory', 'owasp_category'), max_length=100)
    if get('affectedComponent', 'affected_component') is not None:
        finding.affected_component = Sanitizer.clean_text(get('affectedComponent', 'affected_component'), max_length=500)
    if get('affectedUrl', 'affected_url') is not None:
        finding.affected_url = Sanitizer.clean_text(get('affectedUrl', 'affected_url'))
    if get('affectedParameter', 'affected_parameter') is not None:
        finding.affected_parameter = Sanitizer.clean_text(get('affectedParameter', 'affected_parameter'), max_length=255)
    if get('stepsToReproduce', 'steps_to_reproduce') is not None:
        finding.steps_to_reproduce = Sanitizer.clean_html(get('stepsToReproduce', 'steps_to_reproduce') or '', allow_html=True)
    if get('pocCode', 'poc_code') is not None:
        finding.poc_code = get('pocCode', 'poc_code') or ''
    if get('impact') is not None:
        finding.impact = Sanitizer.clean_html(get('impact') or '', allow_html=True)
    if get('recommendation') is not None:
        finding.recommendation = Sanitizer.clean_html(get('recommendation') or '', allow_html=True)
    if get('remediationNotes', 'remediation_notes') is not None:
        finding.remediation_notes = Sanitizer.clean_html(get('remediationNotes', 'remediation_notes') or '', allow_html=True)
    if get('assessmentId', 'assessment_id') is not None:
        finding.assessment_id = get('assessmentId', 'assessment_id') or None

    db.session.commit()

    AuditLogger.log(
        action=AuditAction.FINDING_UPDATED,
        resource_type='finding',
        resource_id=finding.id
    )

    return jsonify({'success': True, 'data': finding.to_dict(include_poc=True)})

@findings_bp.route('/<uuid:finding_id>', methods=['DELETE'])
@require_api_key_or_login(scope='mcp')
# @login_required
@require_permission(Permission.FINDING_DELETE)
def delete(finding_id):
    """Delete a finding"""
    finding = Finding.query.get_or_404(finding_id)

    # Store info for audit log before deletion
    finding_title = finding.title
    finding_severity = finding.severity.value

    try: 
        db.session.delete(finding)
        db.session.commit()

        AuditLogger.log(
            action=AuditAction.FINDING_DELETED,
            resource_type='finding',
            resource_id=str(finding_id),
            changes={
                'title': finding_title,
                'severity': finding_severity
            }
        )

        if request.headers.get('Accept') == 'application/json' or request.is_json:
            return jsonify({
                'success': True,
                'message': 'Finding deleted successfully'
            }), 200 
        
        return jsonify({'success': True}), 200

    except Exception:
        db.session.rollback()
        logger.error("finding_delete_error", finding_id=str(finding_id), exc_info=True)
        return jsonify({
            'success': False,
            'message': 'An unexpected error occurred'
        }), 500

@findings_bp.route('/<uuid:finding_id>/status', methods=['POST', 'PATCH'])
@require_api_key_or_login(scope='mcp')
# @login_required
@require_permission(Permission.FINDING_UPDATE)
def update_status(finding_id):
    """Update finding status"""
    finding = Finding.query.get_or_404(finding_id)
    old_status = finding.status
    
    json_data = request.get_json() or {}
    new_status = request.form.get('status') or json_data.get('status')
    
    try:
        finding.status = FindingStatus(new_status)
        
        if finding.status == FindingStatus.REMEDIATED:
            finding.mark_remediated()
        
        db.session.commit()
        
        AuditLogger.log(
            action=AuditAction.FINDING_STATUS_CHANGED,
            resource_type='finding',
            resource_id=finding.id,
            changes={'status': {'before': old_status.value, 'after': new_status}}
        )
        
        return jsonify(finding.to_dict())
    except ValueError:
        return jsonify({'error': 'Invalid status'}), 400


@findings_bp.route('/<uuid:finding_id>/remediate', methods=['POST'])
@require_api_key_or_login(scope='mcp')
# @login_required
@require_permission(Permission.FINDING_UPDATE)
def remediate(finding_id):
    """Mark finding as remediated"""
    finding = Finding.query.get_or_404(finding_id)
    
    finding.mark_remediated()
    finding.remediation_notes = Sanitizer.clean_html(
        request.form.get('notes', '') or request.json.get('notes', ''),
        allow_html=True
    )
    
    db.session.commit()
    
    AuditLogger.log(
        action=AuditAction.FINDING_STATUS_CHANGED,
        resource_type='finding',
        resource_id=finding.id,
        changes={'status': {'before': 'open', 'after': 'remediated'}}
    )
    
    return jsonify(finding.to_dict())


@findings_bp.route('/<uuid:finding_id>/verify', methods=['POST'])
@require_api_key_or_login(scope='mcp')
# @login_required
@require_permission(Permission.FINDING_UPDATE)
def verify(finding_id):
    """Verify remediation"""
    finding = Finding.query.get_or_404(finding_id)
    finding.verify_remediation()
    db.session.commit()

    return jsonify(finding.to_dict())


@findings_bp.route('/<uuid:finding_id>/evidence', methods=['POST'])
@require_api_key_or_login(scope='mcp')
# @login_required
@require_permission(Permission.FINDING_UPDATE)
def add_evidence(finding_id):
    """Upload evidence file for a finding"""
    import os
    import uuid as uuid_module
    import hashlib
    from werkzeug.utils import secure_filename
    from flask import current_app
    from app.models import Evidence, EvidenceType

    finding = Finding.query.get_or_404(finding_id)

    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({'success': False, 'error': 'No file selected'}), 400

    original_filename = secure_filename(file.filename)
    stored_filename = f"{uuid_module.uuid4()}{os.path.splitext(original_filename)[1]}"
    file_data = file.read()
    file_hash = hashlib.sha256(file_data).hexdigest()

    # Determine evidence type from mime type
    mime_type = file.content_type or 'application/octet-stream'
    if mime_type.startswith('image/'):
        etype = EvidenceType.SCREENSHOT
    elif 'text' in mime_type or 'json' in mime_type or 'xml' in mime_type:
        etype = EvidenceType.CODE_SNIPPET
    else:
        etype = EvidenceType.OTHER

    # Save file to upload directory
    upload_dir = current_app.config.get('UPLOAD_FOLDER', '/tmp/uploads')
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, stored_filename)
    with open(file_path, 'wb') as f:
        f.write(file_data)

    evidence = Evidence(
        original_filename=original_filename,
        stored_filename=stored_filename,
        mime_type=mime_type,
        file_size=len(file_data),
        file_hash=file_hash,
        evidence_type=etype,
        description=request.form.get('description', original_filename),
        finding_id=finding.id,
        uploaded_by_id=current_user.id,
        scan_status='clean',
    )

    db.session.add(evidence)
    db.session.commit()

    return jsonify({'success': True, 'data': evidence.to_dict()}), 201


@findings_bp.route('/<uuid:finding_id>/evidence/<uuid:evidence_id>', methods=['DELETE'])
@require_api_key_or_login(scope='mcp')
# @login_required
@require_permission(Permission.FINDING_UPDATE)
def delete_evidence(finding_id, evidence_id):
    """Delete evidence from a finding"""
    from app.models import Evidence
    evidence = Evidence.query.filter_by(id=evidence_id, finding_id=finding_id).first_or_404()

    db.session.delete(evidence)
    db.session.commit()

    return jsonify({'success': True})