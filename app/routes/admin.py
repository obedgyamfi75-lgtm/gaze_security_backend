"""
GAZE Security Platform - Admin Routes
"""
import secrets
import string
from flask import Blueprint, request, render_template, jsonify
from flask_login import login_required, current_user

from app import db
from app.models import User, AuditLog
from app.security import require_permission, require_role, Permission, AuditLogger, AuditAction, AuthService, Sanitizer

admin_bp = Blueprint('admin', __name__)


def _paginate(query, page, per_page):
    """Return standard paginated response structure"""
    result = query.paginate(page=page, per_page=per_page, error_out=False)
    return result, {
        'page': page,
        'perPage': per_page,
        'totalPages': result.pages,
        'totalItems': result.total,
    }


@admin_bp.route('/')
@login_required
@require_role('admin', 'superadmin')
def index():
    """Admin dashboard"""
    return jsonify({'success': True, 'message': 'Admin API'})


@admin_bp.route('/users')
@login_required
def users():
    """List all users"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('perPage', 20, type=int)
    search = request.args.get('search', '')
    role = request.args.get('role', '')

    query = User.query

    if search:
        search_term = f'%{search}%'
        query = query.filter(
            db.or_(
                User.email.ilike(search_term),
                User.first_name.ilike(search_term),
                User.last_name.ilike(search_term)
            )
        )

    if role:
        query = query.filter(User.role == role)

    query = query.order_by(User.email)
    result, meta = _paginate(query, page, per_page)

    return jsonify({
        'success': True,
        'data': {
            'items': [u.to_dict() for u in result.items],
            'meta': meta
        }
    })


@admin_bp.route('/users/new', methods=['POST'])
@login_required
@require_permission(Permission.USER_CREATE)
def create_user():
    """Create new user — accepts JSON with camelCase or snake_case"""
    data = request.get_json() if request.is_json else request.form.to_dict()

    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400

    # Accept camelCase or snake_case
    email = (data.get('email') or '').lower().strip()
    first_name = data.get('firstName') or data.get('first_name', '')
    last_name = data.get('lastName') or data.get('last_name', '')
    role = data.get('role', 'analyst')
    password = data.get('password')

    if not email:
        return jsonify({'success': False, 'error': 'Email is required'}), 400
    if not first_name or not last_name:
        return jsonify({'success': False, 'error': 'First and last name are required'}), 400

    # Check if user already exists
    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'error': 'Email already in use'}), 409

    # Auto-generate a secure password if not provided
    if not password:
        alphabet = string.ascii_letters + string.digits + '!@#$%^&*()'
        password = ''.join(secrets.choice(alphabet) for _ in range(16))

    # Check password strength
    is_strong, errors = AuthService.check_password_strength(password)
    if not is_strong:
        return jsonify({'success': False, 'errors': errors}), 400

    user = User(
        email=Sanitizer.clean_text(email, max_length=255),
        first_name=Sanitizer.clean_text(first_name, max_length=100),
        last_name=Sanitizer.clean_text(last_name, max_length=100),
        role=role,
    )
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    AuditLogger.log(
        action=AuditAction.USER_CREATED,
        resource_type='user',
        resource_id=user.id,
        new_values={'email': user.email, 'role': user.role}
    )

    response_data = user.to_dict()
    # Include temporary password in response so admin can share it
    response_data['temporaryPassword'] = password if not data.get('password') else None

    return jsonify({'success': True, 'data': response_data}), 201


@admin_bp.route('/users/<uuid:user_id>')
@login_required
@require_permission(Permission.USER_READ)
def view_user(user_id):
    """View user details"""
    user = User.query.get_or_404(user_id)
    return jsonify({
        'success': True,
        'data': user.to_dict(include_sensitive=current_user.role in ['admin', 'superadmin'])
    })


@admin_bp.route('/users/<uuid:user_id>', methods=['PUT'])
@login_required
@require_permission(Permission.USER_UPDATE)
def update_user(user_id):
    """Update user details"""
    user = User.query.get_or_404(user_id)
    data = request.get_json() or {}

    if 'email' in data:
        new_email = (data['email'] or '').lower().strip()
        existing = User.query.filter(User.email == new_email, User.id != user.id).first()
        if existing:
            return jsonify({'success': False, 'error': 'Email already in use'}), 409
        user.email = Sanitizer.clean_text(new_email, max_length=255)

    if 'firstName' in data or 'first_name' in data:
        user.first_name = Sanitizer.clean_text(
            data.get('firstName') or data.get('first_name', ''), max_length=100
        )
    if 'lastName' in data or 'last_name' in data:
        user.last_name = Sanitizer.clean_text(
            data.get('lastName') or data.get('last_name', ''), max_length=100
        )
    if 'role' in data:
        valid_roles = ['superadmin', 'admin', 'security_lead', 'analyst', 'developer']
        if data['role'] not in valid_roles:
            return jsonify({'success': False, 'error': 'Invalid role'}), 400
        if str(user.id) == str(current_user.id) and data['role'] != user.role:
            return jsonify({'success': False, 'error': 'Cannot change your own role'}), 400
        user.role = data['role']
    if 'isActive' in data or 'is_active' in data:
        new_active = data.get('isActive', data.get('is_active'))
        if str(user.id) == str(current_user.id) and not new_active:
            return jsonify({'success': False, 'error': 'Cannot deactivate yourself'}), 400
        user.is_active = bool(new_active)

    db.session.commit()

    AuditLogger.log(
        action=AuditAction.USER_UPDATED,
        resource_type='user',
        resource_id=user.id,
    )

    return jsonify({'success': True, 'data': user.to_dict()})


@admin_bp.route('/users/<uuid:user_id>', methods=['DELETE'])
@login_required
@require_permission(Permission.USER_DELETE)
def delete_user(user_id):
    """Delete a user account"""
    user = User.query.get_or_404(user_id)

    if str(user.id) == str(current_user.id):
        return jsonify({'success': False, 'error': 'Cannot delete your own account'}), 400

    email = user.email
    db.session.delete(user)
    db.session.commit()

    AuditLogger.log(
        action=AuditAction.USER_DELETED,
        resource_type='user',
        resource_id=user_id,
        metadata={'deleted_email': email}
    )

    return jsonify({'success': True})


@admin_bp.route('/users/<uuid:user_id>/role', methods=['POST'])
@login_required
@require_permission(Permission.USER_UPDATE)
def update_role(user_id):
    """Update user role"""
    user = User.query.get_or_404(user_id)
    old_role = user.role

    json_data = request.get_json() or {}
    new_role = request.form.get('role') or json_data.get('role')

    if new_role not in ['superadmin', 'admin', 'security_lead', 'analyst', 'developer']:
        return jsonify({'success': False, 'error': 'Invalid role'}), 400

    if str(user.id) == str(current_user.id) and new_role != old_role:
        return jsonify({'success': False, 'error': 'Cannot change your own role'}), 400

    user.role = new_role
    db.session.commit()

    AuditLogger.log(
        action=AuditAction.USER_ROLE_CHANGED,
        resource_type='user',
        resource_id=user.id,
        changes={'role': {'before': old_role, 'after': new_role}}
    )

    return jsonify({'success': True, 'data': user.to_dict()})


@admin_bp.route('/users/<uuid:user_id>/unlock', methods=['POST'])
@login_required
@require_permission(Permission.USER_UPDATE)
def unlock_user(user_id):
    """Unlock a locked user account"""
    user = User.query.get_or_404(user_id)

    user.failed_login_attempts = 0
    user.lockout_until = None
    db.session.commit()

    AuditLogger.log(
        action=AuditAction.ACCOUNT_UNLOCKED,
        resource_type='user',
        resource_id=user.id
    )

    return jsonify({'success': True, 'data': user.to_dict()})


@admin_bp.route('/users/<uuid:user_id>/deactivate', methods=['POST'])
@login_required
@require_permission(Permission.USER_DELETE)
def deactivate_user(user_id):
    """Deactivate user account"""
    user = User.query.get_or_404(user_id)

    if str(user.id) == str(current_user.id):
        return jsonify({'success': False, 'error': 'Cannot deactivate yourself'}), 400

    user.is_active = False
    db.session.commit()

    AuditLogger.log(
        action=AuditAction.USER_UPDATED,
        resource_type='user',
        resource_id=user.id,
        changes={'is_active': {'before': True, 'after': False}}
    )

    return jsonify({'success': True, 'data': user.to_dict()})


@admin_bp.route('/users/<uuid:user_id>/reset-password', methods=['POST'])
@login_required
@require_permission(Permission.USER_UPDATE)
def reset_password(user_id):
    """Reset user password to a secure auto-generated value"""
    user = User.query.get_or_404(user_id)

    alphabet = string.ascii_letters + string.digits + '!@#$%^&*()'
    new_password = ''.join(secrets.choice(alphabet) for _ in range(16))
    user.set_password(new_password)
    db.session.commit()

    AuditLogger.log(
        action=AuditAction.PASSWORD_CHANGED,
        resource_type='user',
        resource_id=user.id,
        metadata={'reset_by_admin': str(current_user.id)}
    )

    return jsonify({'success': True, 'data': {'temporaryPassword': new_password}})


@admin_bp.route('/audit-logs')
@login_required
def audit_logs():
    """View audit logs"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('perPage', 50, type=int)
    action_filter = request.args.get('action', '')
    user_filter = request.args.get('userId', '')
    entity_type = request.args.get('entityType', '')

    query = AuditLog.query

    if action_filter:
        # Frontend sends simplified actions (login, create, delete, etc.)
        # Backend stores dot-notation (auth.login.success, finding.created, etc.)
        action_patterns = {
            'login': ['auth.login%'],
            'logout': ['auth.logout%'],
            'create': ['%.created'],
            'update': ['%.updated', '%.changed'],
            'delete': ['%.deleted'],
            'export': ['export.%', '%.download%'],
            'status_change': ['%.status.%'],
        }
        patterns = action_patterns.get(action_filter)
        if patterns:
            query = query.filter(db.or_(*[AuditLog.action.like(p) for p in patterns]))
        else:
            query = query.filter(AuditLog.action.like(f'%{action_filter}%'))

    if user_filter:
        query = query.filter(AuditLog.user_id == user_filter)

    if entity_type:
        query = query.filter(AuditLog.resource_type == entity_type)

    query = query.order_by(AuditLog.created_at.desc())
    result, meta = _paginate(query, page, per_page)

    return jsonify({
        'success': True,
        'data': {
            'items': [log.to_dict() for log in result.items],
            'meta': meta
        }
    })


@admin_bp.route('/settings', methods=['GET', 'PUT'])
@login_required
@require_permission(Permission.SETTINGS_READ)
def settings():
    """View or update system settings"""
    from flask import current_app
    config = current_app.config

    if request.method == 'PUT':
        # Settings updates are informational-only in this deployment
        # (runtime config changes require restart); just echo back success
        AuditLogger.log(
            action=AuditAction.SETTINGS_UPDATED,
            resource_type='system',
        )
        return jsonify({'success': True, 'data': request.get_json() or {}})

    return jsonify({
        'success': True,
        'data': {
            'sessionTimeout': config.get('PERMANENT_SESSION_LIFETIME', 900),
            'maxUploadSize': config.get('MAX_CONTENT_LENGTH', 26214400),
            'environment': config.get('FLASK_ENV', 'production'),
            'mfaRequired': config.get('MFA_REQUIRED_ROLES', []),
        }
    })


@admin_bp.route('/settings/branding', methods=['GET', 'PUT'])
@login_required
@require_permission(Permission.SETTINGS_READ)
def settings_branding():
    """View or update branding settings"""
    if request.method == 'PUT':
        AuditLogger.log(
            action=AuditAction.SETTINGS_UPDATED,
            resource_type='system',
        )
        return jsonify({'success': True, 'data': request.get_json() or {}})

    return jsonify({
        'success': True,
        'data': {
            'platformName': 'GAZE Security',
            'logoUrl': None,
            'primaryColor': '#7c3aed',
        }
    })
