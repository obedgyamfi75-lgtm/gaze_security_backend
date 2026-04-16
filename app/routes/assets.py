"""
GAZE Security Platform - Assets Routes
Updated to match Next.js frontend API expectations
"""
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
import structlog

from app import db
from app.models import Asset, AssetType, AssetCriticality
from app.security import require_permission, Permission, AuditLogger, AuditAction, Sanitizer, require_api_key_or_login


logger = structlog.get_logger()

# Blueprint without url_prefix - let app registration handle /api prefix
assets_bp = Blueprint('assets', __name__)


# =============================================================================
# TYPE MAPPING - Frontend to Backend
# =============================================================================

FRONTEND_TO_BACKEND_TYPE = {
    'web': 'web_application',
    'mobile': 'mobile_app',
    'api': 'api',
    'database': 'database',
    'cloud': 'cloud_infrastructure',
}

def normalize_asset_type(frontend_type: str) -> str:
    """Convert frontend type to backend AssetType enum value"""
    return FRONTEND_TO_BACKEND_TYPE.get(frontend_type, 'web_application')


# =============================================================================
# API ROUTES
# =============================================================================

@assets_bp.route('/assets', methods=['GET'])
@require_api_key_or_login(scope='mcp')
# @login_required
def list_assets():
    """
    GET /api/assets
    Returns paginated list of assets
    """
    try:
        # Pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('perPage', 20, type=int)
        
        # Filters
        search = request.args.get('search', '')
        asset_type = request.args.get('type', '')
        product_id = request.args.get('productId', '')
        status_filter = request.args.get('status', '')
        criticality = request.args.get('criticality', '')
        
        # Build query
        query = Asset.query
        
        # Apply search filter
        if search:
            search_term = Sanitizer.sanitize_sql_like(search)
            query = query.filter(Asset.name.ilike(f'%{search_term}%'))
        
        # Apply type filter
        if asset_type:
            backend_type = normalize_asset_type(asset_type)
            try:
                query = query.filter(Asset.asset_type == AssetType(backend_type))
            except ValueError:
                pass
        
        # Apply product filter
        if product_id:
            query = query.filter(Asset.product_id == product_id)
        
        # Apply criticality filter
        if criticality:
            try:
                query = query.filter(Asset.criticality == AssetCriticality(criticality.lower()))
            except ValueError:
                pass
        
        # Order by name
        query = query.order_by(Asset.name)
        
        # Paginate
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        # Convert to dict
        assets_data = [asset.to_dict() for asset in pagination.items]
        
        # Apply status filter (calculated field, so filter after fetch)
        if status_filter:
            assets_data = [a for a in assets_data if a.get('status') == status_filter]
        
        # Return response matching frontend expectations
        return jsonify({
            'success': True,
            'data': {
                'items': assets_data,
                'meta': {
                    'page': page,
                    'perPage': per_page,
                    'totalPages': pagination.pages,
                    'totalItems': pagination.total
                }
            }
        }), 200
        
    except Exception:
        logger.error("assets_list_error", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        }), 500


@assets_bp.route('/assets/<uuid:asset_id>', methods=['GET'])
@require_api_key_or_login(scope='mcp')
# @login_required
@require_permission(Permission.ASSET_READ)
def get_asset(asset_id):
    """
    GET /api/assets/{id}
    """
    try:
        asset = Asset.query.get_or_404(asset_id)
        
        return jsonify({
            'success': True,
            'data': asset.to_dict()
        }), 200
        
    except Exception:
        return jsonify({
            'success': False,
            'error': 'Asset not found'
        }), 404


@assets_bp.route('/assets/new', methods=['POST'])
@require_api_key_or_login(scope='mcp')
# @login_required
@require_permission(Permission.ASSET_CREATE)
def create_asset():
    """
    POST /api/assets/new
    Creates a new asset
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        # Validate required fields
        if not data.get('name'):
            return jsonify({
                'success': False,
                'error': 'Name is required'
            }), 400
        
        if not data.get('productId'):
            return jsonify({
                'success': False,
                'error': 'Product ID is required'
            }), 400
        
        # Normalize types
        backend_type = normalize_asset_type(data.get('type', 'web'))
        criticality = data.get('criticality', 'medium').lower()
        environment = data.get('environment', 'production').lower()
        
        # Create asset
        asset = Asset(
            name=Sanitizer.clean_text(data['name'], max_length=255),
            description=Sanitizer.clean_html(data.get('description', ''), allow_html=True),
            asset_type=AssetType(backend_type),
            criticality=AssetCriticality(criticality),
            environment=environment,
            url=Sanitizer.clean_text(data.get('url'), max_length=500) if data.get('url') else None,
            business_owner=Sanitizer.clean_text(data.get('owner'), max_length=255) if data.get('owner') else None,
            technical_owner=Sanitizer.clean_text(data.get('owner'), max_length=255) if data.get('owner') else None,
            product_id=data['productId'],
            created_by_id=current_user.id
        )
        
        # Handle technologies (store as JSON in tags field)
        if data.get('technologies'):
            import json
            asset.tags = json.dumps(data['technologies'])
        
        db.session.add(asset)
        db.session.commit()
        
        # Audit log
        AuditLogger.log(
            action=AuditAction.ASSET_CREATED,
            resource_type='asset',
            resource_id=asset.id,
            new_values=asset.to_dict()
        )
        
        return jsonify({
            'success': True,
            'data': asset.to_dict()
        }), 201
        
    except Exception:
        db.session.rollback()
        logger.error("asset_create_error", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        }), 500


@assets_bp.route('/assets/<uuid:asset_id>', methods=['PUT'])
@require_api_key_or_login(scope='mcp')
# @login_required
@require_permission(Permission.ASSET_UPDATE)
def update_asset(asset_id):
    """
    PUT /api/assets/{id}
    Updates an existing asset
    """
    try:
        asset = Asset.query.get_or_404(asset_id)
        old_values = asset.to_dict()
        
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        # Update fields if provided
        if 'name' in data:
            asset.name = Sanitizer.clean_text(data['name'], max_length=255)
        
        if 'description' in data:
            asset.description = Sanitizer.clean_html(data['description'], allow_html=True)
        
        if 'type' in data:
            backend_type = normalize_asset_type(data['type'])
            asset.asset_type = AssetType(backend_type)
        
        if 'criticality' in data:
            asset.criticality = AssetCriticality(data['criticality'].lower())
        
        if 'environment' in data:
            asset.environment = data['environment'].lower()
        
        if 'url' in data:
            asset.url = Sanitizer.clean_text(data['url'], max_length=500) if data['url'] else None
        
        if 'owner' in data:
            owner = Sanitizer.clean_text(data['owner'], max_length=255)
            asset.business_owner = owner
            asset.technical_owner = owner
        
        if 'productId' in data:
            asset.product_id = data['productId'] if data['productId'] else None
        
        # Handle technologies
        if 'technologies' in data:
            import json
            asset.tags = json.dumps(data['technologies']) if data['technologies'] else None
        
        db.session.commit()
        
        # Audit log
        AuditLogger.log_data_change(
            action=AuditAction.ASSET_UPDATED,
            resource_type='asset',
            resource_id=asset.id,
            old_obj=old_values,
            new_obj=asset.to_dict()
        )
        
        return jsonify({
            'success': True,
            'data': asset.to_dict()
        }), 200
        
    except Exception:
        db.session.rollback()
        logger.error("asset_update_error", asset_id=str(asset_id), exc_info=True)
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        }), 500


@assets_bp.route('/assets/<uuid:asset_id>', methods=['DELETE'])
@require_api_key_or_login(scope='mcp')
# @login_required
@require_permission(Permission.ASSET_DELETE)
def delete_asset(asset_id):
    """
    DELETE /api/assets/{id}
    Deletes an asset
    """
    try:
        asset = Asset.query.get_or_404(asset_id)
        old_values = asset.to_dict()
        
        db.session.delete(asset)
        db.session.commit()
        
        # Audit log
        AuditLogger.log(
            action=AuditAction.ASSET_DELETED,
            resource_type='asset',
            resource_id=asset_id,
            old_values=old_values
        )
        
        return jsonify({
            'success': True,
            'message': 'Asset deleted successfully'
        }), 200
        
    except Exception:
        db.session.rollback()
        logger.error("asset_delete_error", asset_id=str(asset_id), exc_info=True)
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        }), 500


@assets_bp.route('/assets/<uuid:asset_id>/findings', methods=['GET'])
@require_api_key_or_login(scope='mcp')
# @login_required
@require_permission(Permission.ASSET_READ)
def get_asset_findings(asset_id):
    """
    GET /api/assets/{id}/findings
    Returns all findings for an asset
    """
    try:
        asset = Asset.query.get_or_404(asset_id)
        
        # Get all findings from all assessments
        findings = []
        for assessment in asset.assessments:
            findings.extend([f.to_dict() for f in assessment.findings])
        
        return jsonify({
            'success': True,
            'data': findings
        }), 200
        
    except Exception:
        logger.error("asset_findings_error", asset_id=str(asset_id), exc_info=True)
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        }), 500