"""
GAZE Security Platform - Reports API Routes
RESTful endpoints for report CRUD operations and async generation.
"""
import os
from uuid import UUID
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, send_file, current_app
from flask_login import login_required, current_user
from marshmallow import Schema, fields, validate, EXCLUDE

from app import db
from app.models.report import Report, ReportType, ReportStatus, ReportFormat
from app.security import require_permission, Permission, AuditLogger, AuditAction, require_api_key_or_login
from app.services.report_generator import ReportGenerator


reports_bp = Blueprint('reports', __name__, url_prefix='/api/reports')


# =============================================================================
# SCHEMAS
# =============================================================================

class GenerateReportSchema(Schema):
    """Schema for report generation request"""
    class Meta:
        unknown = EXCLUDE
    
    name = fields.Str(required=False, load_default=None)
    type = fields.Str(
        required=True,
        validate=validate.OneOf(["executive", "technical", "compliance", "full", "custom"])
    )
    format = fields.Str(
        required=True,
        validate=validate.OneOf(["pdf", "docx", "xlsx", "html"])
    )
    assessmentId = fields.Str(required=True, data_key="assessmentId")
    options = fields.Dict(required=False, load_default=dict)


class ReportQuerySchema(Schema):
    """Schema for report list query parameters"""
    class Meta:
        unknown = EXCLUDE
    
    page = fields.Int(required=False, load_default=1, validate=validate.Range(min=1))
    limit = fields.Int(required=False, load_default=20, validate=validate.Range(min=1, max=100))
    type = fields.Str(required=False, validate=validate.OneOf(["executive", "technical", "compliance", "full", "custom"]))
    status = fields.Str(required=False, validate=validate.OneOf(["pending", "generating", "completed", "failed"]))
    assessmentId = fields.Str(required=False, data_key="assessmentId")
    search = fields.Str(required=False)
    sortBy = fields.Str(required=False, load_default="createdAt", data_key="sortBy")
    sortOrder = fields.Str(required=False, load_default="desc", validate=validate.OneOf(["asc", "desc"]), data_key="sortOrder")


generate_schema = GenerateReportSchema()
query_schema = ReportQuerySchema()


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def paginate_query(query, page: int, limit: int):
    """Apply pagination to query and return PaginatedResponse-compatible structure"""
    total = query.count()
    total_pages = (total + limit - 1) // limit if limit > 0 else 0
    items = query.offset((page - 1) * limit).limit(limit).all()

    return {
        "items": [item.to_dict() for item in items],
        "meta": {
            "page": page,
            "perPage": limit,
            "totalPages": total_pages,
            "totalItems": total,
        }
    }


def generate_report_name(report_type: str, assessment_name: str) -> str:
    """Generate default report name"""
    type_labels = {
        "executive": "Executive Summary",
        "technical": "Technical Report",
        "compliance": "Compliance Report",
        "full": "Full Assessment Report",
        "custom": "Custom Report",
    }
    label = type_labels.get(report_type, "Security Report")
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return f"{label} - {assessment_name} ({date_str})"


# =============================================================================
# ROUTES
# =============================================================================

@reports_bp.route('', methods=['GET'])
@login_required
@require_permission(Permission.REPORT_READ)
def list_reports():
    """
    List reports with filtering and pagination.
    
    Query params:
        - page: Page number (default 1)
        - limit: Items per page (default 20, max 100)
        - type: Filter by report type
        - status: Filter by generation status
        - assessmentId: Filter by source assessment
        - search: Search in name
        - sortBy: Sort field (default createdAt)
        - sortOrder: asc or desc (default desc)
    """
    errors = query_schema.validate(request.args)
    if errors:
        return jsonify({"error": "Invalid query parameters", "details": errors}), 400
    
    params = query_schema.load(request.args)
    
    # Base query
    query = Report.query
    
    # Apply filters
    if params.get("type"):
        query = query.filter(Report.report_type == ReportType(params["type"]))
    
    if params.get("status"):
        query = query.filter(Report.status == ReportStatus(params["status"]))
    
    if params.get("assessmentId"):
        try:
            assessment_uuid = UUID(params["assessmentId"])
            query = query.filter(Report.assessment_id == assessment_uuid)
        except ValueError:
            return jsonify({"error": "Invalid assessmentId format"}), 400
    
    if params.get("search"):
        search_term = f"%{params['search']}%"
        query = query.filter(Report.name.ilike(search_term))
    
    # Apply sorting
    sort_field = params.get("sortBy", "createdAt")
    sort_order = params.get("sortOrder", "desc")
    
    # Map camelCase to snake_case for DB columns
    sort_map = {
        "createdAt": Report.created_at,
        "updatedAt": Report.updated_at,
        "name": Report.name,
        "type": Report.report_type,
        "status": Report.status,
    }
    
    sort_column = sort_map.get(sort_field, Report.created_at)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())
    
    # Paginate and return
    result = paginate_query(query, params["page"], params["limit"])
    return jsonify({"success": True, "data": result}), 200


@reports_bp.route('/<report_id>', methods=['GET'])
@login_required
@require_permission(Permission.REPORT_READ)
def get_report(report_id: str):
    """Get a single report by ID"""
    try:
        report_uuid = UUID(report_id)
    except ValueError:
        return jsonify({"error": "Invalid report ID format"}), 400
    
    report = Report.query.get(report_uuid)
    if not report:
        return jsonify({"success": False, "error": "Report not found"}), 404

    return jsonify({"success": True, "data": report.to_dict()}), 200


@reports_bp.route('/generate', methods=['POST'])
@require_api_key_or_login(scope='mcp')
# @login_required
@require_permission(Permission.REPORT_CREATE)
def generate_report():
    """
    Generate a new report asynchronously.
    
    Request body:
        - type: Report type (executive, technical, compliance, full, custom)
        - format: Output format (pdf, docx, xlsx, html)
        - assessmentId: Source assessment ID (required)
        - name: Optional custom report name
        - options: Optional generation options dict
    
    Returns the created report with status 'generating'.
    """
    json_data = request.get_json()
    if not json_data:
        return jsonify({"error": "Request body required"}), 400
    
    errors = generate_schema.validate(json_data)
    if errors:
        return jsonify({"error": "Validation failed", "details": errors}), 400
    
    data = generate_schema.load(json_data)
    
    # Validate assessment exists
    try:
        assessment_uuid = UUID(data["assessmentId"])
    except ValueError:
        return jsonify({"error": "Invalid assessmentId format"}), 400
    
    from app.models.assessment import Assessment
    assessment = Assessment.query.get(assessment_uuid)
    if not assessment:
        return jsonify({"error": "Assessment not found"}), 404
    
    # Generate name if not provided
    name = data.get("name") or generate_report_name(data["type"], assessment.name)
    
    # Create report record
    report = Report(
        name=name,
        report_type=ReportType(data["type"]),
        format=ReportFormat(data["format"]),
        assessment_id=assessment_uuid,
        options=data.get("options", {}),
        generated_by_id=current_user.id,
        status=ReportStatus.PENDING,
    )
    
    db.session.add(report)
    db.session.commit()
    
    # Log the action
    AuditLogger.log(
        action=AuditAction.REPORT_GENERATED,
        resource_type="report",
        resource_id=str(report.id),
        metadata={
            "type": data["type"],
            "format": data["format"],
            "assessment_id": str(assessment_uuid),
        }
    )
    
    # Trigger async generation
    # Option 1: Celery task (recommended for production)
    # generate_report_task.delay(str(report.id))
    
    # Option 2: Synchronous generation (simpler, for dev/small scale)
    _generate_report_sync(str(report.id))
    
    # Refresh and return
    db.session.refresh(report)
    return jsonify({"success": True, "data": report.to_dict()}), 201


@reports_bp.route('/<report_id>', methods=['DELETE'])
@login_required
@require_permission(Permission.REPORT_DELETE)
def delete_report(report_id: str):
    """Delete a report and its generated file"""
    try:
        report_uuid = UUID(report_id)
    except ValueError:
        return jsonify({"error": "Invalid report ID format"}), 400
    
    report = Report.query.get(report_uuid)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    
    # Delete file if exists
    if report.file_path and os.path.exists(report.file_path):
        try:
            os.remove(report.file_path)
        except OSError as e:
            current_app.logger.warning(f"Failed to delete report file: {e}")
    
    # Log deletion
    AuditLogger.log(
        action=AuditAction.REPORT_DELETED,
        resource_type="report",
        resource_id=str(report.id),
        metadata={"name": report.name, "type": report.report_type.value if report.report_type else None}
    )
    
    db.session.delete(report)
    db.session.commit()
    
    return jsonify({"message": "Report deleted"}), 200


@reports_bp.route('/<report_id>/download', methods=['GET'])
@login_required
@require_permission(Permission.REPORT_READ)
def download_report(report_id: str):
    """Download a completed report file"""
    try:
        report_uuid = UUID(report_id)
    except ValueError:
        return jsonify({"error": "Invalid report ID format"}), 400
    
    report = Report.query.get(report_uuid)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    
    if report.status != ReportStatus.COMPLETED:
        return jsonify({"error": "Report not ready for download", "status": report.status.value}), 400
    
    if not report.file_path or not os.path.exists(report.file_path):
        return jsonify({"error": "Report file not found"}), 404
    
    # Determine MIME type
    mime_types = {
        ReportFormat.PDF: "application/pdf",
        ReportFormat.DOCX: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ReportFormat.XLSX: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ReportFormat.HTML: "text/html",
    }
    
    mime_type = mime_types.get(report.format, "application/octet-stream")
    
    # Generate filename
    extension = report.format.value if report.format else "bin"
    safe_name = "".join(c if c.isalnum() or c in "._- " else "_" for c in report.name)
    filename = f"{safe_name}.{extension}"
    
    return send_file(
        report.file_path,
        as_attachment=True,
        download_name=filename,
        mimetype=mime_type
    )


@reports_bp.route('/<report_id>/retry', methods=['POST'])
@login_required
@require_permission(Permission.REPORT_CREATE)
def retry_report(report_id: str):
    """Retry generating a failed report"""
    try:
        report_uuid = UUID(report_id)
    except ValueError:
        return jsonify({"error": "Invalid report ID format"}), 400
    
    report = Report.query.get(report_uuid)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    
    if report.status not in [ReportStatus.FAILED, ReportStatus.PENDING]:
        return jsonify({"error": "Can only retry failed or pending reports"}), 400
    
    # Reset status and trigger regeneration
    report.status = ReportStatus.PENDING
    report.error_message = None
    report.file_path = None
    report.file_size = None
    report.generation_started_at = None
    report.generation_completed_at = None
    
    db.session.commit()
    
    # Trigger generation
    _generate_report_sync(str(report.id))

    db.session.refresh(report)
    return jsonify({"success": True, "data": report.to_dict()}), 200


@reports_bp.route('/<report_id>/status', methods=['GET'])
@login_required
@require_permission(Permission.REPORT_READ)
def get_report_status(report_id: str):
    """Get just the status of a report (for polling)"""
    try:
        report_uuid = UUID(report_id)
    except ValueError:
        return jsonify({"error": "Invalid report ID format"}), 400
    
    report = Report.query.get(report_uuid)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    
    return jsonify({
        "id": str(report.id),
        "status": report.status.value,
        "errorMessage": report.error_message,
        "downloadUrl": report.download_url,
    }), 200


# =============================================================================
# VIEW REPORT AS HTML (in-browser viewing)
# =============================================================================

@reports_bp.route('/<report_id>/view', methods=['GET'])
@require_api_key_or_login(scope='mcp')
@login_required
@require_permission(Permission.REPORT_READ)
def view_report(report_id: str):
    """
    View report as HTML in browser.
    For PDF/DOCX, generates an HTML preview.
    For HTML format, serves directly.
    """
    try:
        report_uuid = UUID(report_id)
    except ValueError:
        return jsonify({"error": "Invalid report ID format"}), 400
    
    report = Report.query.get(report_uuid)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    
    if report.status != ReportStatus.COMPLETED:
        return jsonify({"error": "Report not ready for viewing"}), 400
    
    # For HTML format, serve file directly
    if report.format == ReportFormat.HTML and report.file_path and os.path.exists(report.file_path):
        return send_file(report.file_path, mimetype="text/html")
    
    # For other formats, generate HTML preview
    try:
        html_content = ReportGenerator.generate_html_preview(
            assessment_id=str(report.assessment_id),
            report_type=report.report_type.value,
            options=report.options
        )
        return html_content, 200, {"Content-Type": "text/html"}
    except Exception as e:
        current_app.logger.error(f"Failed to generate preview: {e}")
        return jsonify({"error": "Failed to generate preview"}), 500


# =============================================================================
# SYNC GENERATION (Replace with Celery for production)
# =============================================================================

def _generate_report_sync(report_id: str) -> None:
    """
    Synchronous report generation.
    
    In production, replace this with a Celery task for async processing.
    """
    try:
        report_uuid = UUID(report_id)
    except ValueError:
        return
    
    report = Report.query.get(report_uuid)
    if not report:
        return
    
    report.start_generation()
    db.session.commit()
    
    try:
        assessment_id = str(report.assessment_id)
        report_type = report.report_type.value if report.report_type else "executive"
        
        # Call appropriate generator based on format
        if report.format == ReportFormat.PDF:
            file_path = ReportGenerator.generate_pdf_report(
                assessment_id=assessment_id,
                report_type=report_type,
                options=report.options
            )
        elif report.format == ReportFormat.DOCX:
            file_path = ReportGenerator.generate_word_report(
                assessment_id=assessment_id,
                report_type=report_type,
                options=report.options
            )
        elif report.format == ReportFormat.XLSX:
            from app.services.excel_export import ExcelExportService
            file_path = ExcelExportService.export_findings(
                assessment_id=assessment_id,
                options=report.options
            )
        elif report.format == ReportFormat.HTML:
            file_path = ReportGenerator.generate_html_report(
                assessment_id=assessment_id,
                report_type=report_type,
                options=report.options
            )
        else:
            raise ValueError(f"Unsupported format: {report.format}")
        
        # Get file size
        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        
        # Mark complete
        report.complete_generation(
            file_path=file_path,
            file_size=file_size,
            page_count=None  # Could be extracted for PDF
        )
        db.session.commit()
        
    except Exception as e:
        current_app.logger.error(f"Report generation failed: {e}")
        report.fail_generation(str(e))
        db.session.commit()


# =============================================================================
# LEGACY EXPORT ROUTES (Keep for backward compatibility)
# =============================================================================

@reports_bp.route('/export/excel', methods=['POST'])
@login_required
@require_permission(Permission.EXPORT_CREATE)
def export_excel_legacy():
    """Legacy endpoint: Direct Excel export"""
    from app.services.excel_export import ExcelExportService
    
    data = request.get_json() or request.form
    assessment_id = data.get('assessment_id') or data.get('assessmentId')
    
    filepath = ExcelExportService.export_findings(assessment_id)
    
    AuditLogger.log(
        action=AuditAction.EXPORT_CREATED,
        resource_type='export',
        metadata={'format': 'excel', 'assessment_id': assessment_id}
    )
    
    return send_file(
        filepath,
        as_attachment=True,
        download_name='security_findings.xlsx',
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )


@reports_bp.route('/export/word', methods=['POST'])
@login_required
@require_permission(Permission.REPORT_CREATE)
def export_word_legacy():
    """Legacy endpoint: Direct Word export"""
    data = request.get_json() or request.form
    assessment_id = data.get('assessment_id') or data.get('assessmentId')
    
    filepath = ReportGenerator.generate_word_report(assessment_id)
    
    AuditLogger.log(
        action=AuditAction.REPORT_GENERATED,
        resource_type='report',
        metadata={'format': 'word', 'assessment_id': assessment_id}
    )
    
    return send_file(
        filepath,
        as_attachment=True,
        download_name='security_assessment_report.docx',
        mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    )


@reports_bp.route('/export/pdf', methods=['POST'])
@login_required
@require_permission(Permission.REPORT_CREATE)
def export_pdf_legacy():
    """Legacy endpoint: Direct PDF export"""
    data = request.get_json() or request.form
    assessment_id = data.get('assessment_id') or data.get('assessmentId')
    
    filepath = ReportGenerator.generate_pdf_report(assessment_id)
    
    AuditLogger.log(
        action=AuditAction.REPORT_GENERATED,
        resource_type='report',
        metadata={'format': 'pdf', 'assessment_id': assessment_id}
    )
    
    return send_file(
        filepath,
        as_attachment=True,
        download_name='security_assessment_report.pdf',
        mimetype='application/pdf'
    )