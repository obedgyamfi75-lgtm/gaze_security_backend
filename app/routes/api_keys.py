"""
GazeSec - API Keys Routes
Generate, list, and revoke scoped API keys
"""
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from sqlalchemy import any_


from app import db, limiter
from app.models import ApiKey, VALID_SCOPES, User

api_keys_bp = Blueprint('api_keys', __name__)


def api_response(data=None, error=None, status=200):
    response = {'success': error is None}
    if data is not None:
        response['data'] = data
    if error:
        response['error'] = error
    return jsonify(response), status


@api_keys_bp.route('', methods=['GET'])
@login_required
def list_keys():
    """List all API keys for the current user"""
    keys = ApiKey.query.filter_by(user_id=current_user.id, is_active=True).order_by(ApiKey.created_at.desc()).all()
    return api_response(data=[k.to_dict() for k in keys])


@api_keys_bp.route('', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def create_key():
    """Generate a new API key"""
    data = request.get_json() or {}
    name = data.get('name', 'API Key').strip()
    scopes = data.get('scopes', ['api'])

    if not name:
        return api_response(error='Name is required', status=400)

    if not isinstance(scopes, list) or not all(s in VALID_SCOPES for s in scopes):
        return api_response(error=f'Invalid scopes. Valid: {sorted(VALID_SCOPES)}', status=400)

    key_instance, raw_key = ApiKey.generate(name=name, scopes=scopes)
    key_instance.user_id = current_user.id
    db.session.add(key_instance)
    db.session.commit()

    return api_response(data={
        **key_instance.to_dict(),
        'key': raw_key,
    }, status=201)


@api_keys_bp.route('/mcp', methods=['GET'])
@login_required
def get_mcp_key():
    """Get the user's MCP key. Returns raw key from DB."""
    existing = ApiKey.query.filter(
        ApiKey.user_id == current_user.id,
        ApiKey.is_active == True,
        db.literal('mcp') == any_(ApiKey.scopes)
    ).first()

    if existing:
        return api_response(data={
            **existing.to_dict(),
            'key': existing.key_raw,
        })

    # No key exists — create one automatically
    key_instance, raw_key = ApiKey.generate(name='MCP Key', scopes=['mcp'])
    key_instance.user_id = current_user.id
    db.session.add(key_instance)
    db.session.commit()

    return api_response(data={
        **key_instance.to_dict(),
        'key': raw_key,
    }, status=201)


@api_keys_bp.route('/<uuid:key_id>', methods=['DELETE'])
@login_required
def revoke_key(key_id):
    """Revoke an API key"""
    key = ApiKey.query.filter_by(id=key_id, user_id=current_user.id).first_or_404()
    key.is_active = False
    db.session.commit()
    return api_response(data={'message': 'Key revoked'})


@api_keys_bp.route('/validate', methods=['POST'])
def validate_key():
    """Validate a raw API key and return scope info."""
    data = request.get_json() or {}
    raw_key = data.get('key', '')

    if not raw_key:
        return api_response(error='Key is required', status=400)

    key = ApiKey.verify(raw_key)
    if not key:
        return api_response(error='Invalid or revoked key', status=401)

    return api_response(data={
        'userId': str(key.user_id),
        'scopes': key.scopes,
        'keyId': str(key.id),
    })