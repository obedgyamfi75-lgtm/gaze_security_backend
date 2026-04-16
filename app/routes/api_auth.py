"""
GAZE Security Platform - API Authentication Routes
JSON-based authentication for frontend integration
"""
from datetime import datetime, timezone
from functools import wraps

from flask import Blueprint, request, session, jsonify, g
from flask_login import login_user, logout_user, login_required, current_user
import structlog

from app import db, login_manager, limiter
from app.models import User
from app.security import AuthService, AuditLogger, AuditAction

logger = structlog.get_logger()

api_auth_bp = Blueprint('api_auth', __name__)


def api_response(data=None, error=None, status=200, meta=None):
    """Standardized API response format"""
    response = {'success': error is None}
    if data is not None:
        response['data'] = data
    if error:
        response['error'] = error
    if meta:
        response['meta'] = meta
    return jsonify(response), status


def api_login_required(f):
    """Custom login required that returns JSON for API routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return api_response(error='Authentication required', status=401)
        return f(*args, **kwargs)
    return decorated_function


@api_auth_bp.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def api_login():
    """API Login endpoint"""
    if current_user.is_authenticated:
        return api_response(data={
            'user': current_user.to_dict(),
            'requires_mfa': False
        })
    
    data = request.get_json()
    if not data:
        return api_response(error='Invalid request body', status=400)
    
    email = data.get('email', '').lower().strip()
    password = data.get('password', '')
    
    if not email or not password:
        return api_response(error='Email and password are required', status=400)
    
    user = User.query.filter_by(email=email).first()
    
    if not user:
        logger.warning("api_login_failed_unknown_user", email=email)
        return api_response(error='Invalid email or password', status=401)
    
    # Check lockout
    is_locked, lockout_until = AuthService.check_account_lockout(user)
    if is_locked:
        logger.warning("api_login_blocked_lockout", user_id=str(user.id))
        return api_response(
            error=f'Account locked until {lockout_until.strftime("%H:%M")}',
            status=423  # Locked
        )
    
    # Verify password
    if not user.check_password(password):
        AuthService.record_failed_login(user)
        AuditLogger.log(
            action=AuditAction.LOGIN_FAILED,
            resource_type='user',
            resource_id=user.id,
            metadata={'reason': 'invalid_password', 'source': 'api'}
        )
        return api_response(error='Invalid email or password', status=401)
    
    # Check if MFA is required
    if user.mfa_enabled:
        session['pending_mfa_user_id'] = str(user.id)
        session['_session_ip'] = request.remote_addr
        return api_response(data={
            'requires_mfa': True,
            'user': None
        })
    
    # Login successful - no MFA
    _complete_api_login(user)
    return api_response(data={
        'user': user.to_dict(),
        'requires_mfa': False
    })


@api_auth_bp.route('/mfa/verify', methods=['POST'])
@limiter.limit("5 per minute")
def api_mfa_verify():
    """API MFA verification endpoint"""
    user_id = session.get('pending_mfa_user_id')
    if not user_id:
        return api_response(error='No pending MFA verification', status=400)
    
    user = User.query.get(user_id)
    if not user:
        session.pop('pending_mfa_user_id', None)
        return api_response(error='User not found', status=404)
    
    data = request.get_json()
    if not data:
        return api_response(error='Invalid request body', status=400)
    
    code = data.get('code', '').strip()
    use_backup = data.get('use_backup', False)
    
    if not code:
        return api_response(error='Verification code is required', status=400)
    
    if use_backup:
        if user.use_backup_code(code):
            db.session.commit()
            session.pop('pending_mfa_user_id', None)
            session['mfa_verified'] = True
            _complete_api_login(user)
            return api_response(data={
                'user': user.to_dict(),
                'warning': 'Backup code used. Consider generating new codes.'
            })
    else:
        if user.verify_totp(code):
            session.pop('pending_mfa_user_id', None)
            session['mfa_verified'] = True
            _complete_api_login(user)
            return api_response(data={
                'user': user.to_dict()
            })
    
    AuditLogger.log(
        action=AuditAction.LOGIN_FAILED,
        resource_type='user',
        resource_id=user.id,
        metadata={'reason': 'invalid_mfa_code', 'source': 'api'}
    )
    return api_response(error='Invalid verification code', status=401)


@api_auth_bp.route('/me', methods=['GET'])
@api_login_required
def api_me():
    """Get current authenticated user"""
    return api_response(data=current_user.to_dict())


@api_auth_bp.route('/logout', methods=['POST'])
@api_login_required
def api_logout():
    """API Logout endpoint"""
    AuditLogger.log(action=AuditAction.LOGOUT, metadata={'source': 'api'})
    logout_user()
    session.clear()
    return api_response(data={'message': 'Logged out successfully'})


@api_auth_bp.route('/change-password', methods=['POST'])
@api_login_required
@limiter.limit("3 per minute")
def api_change_password():
    """API Change password endpoint"""
    data = request.get_json()
    if not data:
        return api_response(error='Invalid request body', status=400)
    
    # Accept both camelCase (from frontend) and snake_case
    current_password = data.get('currentPassword') or data.get('current_password', '')
    new_password = data.get('newPassword') or data.get('new_password', '')
    
    if not current_password or not new_password:
        return api_response(error='Current and new password are required', status=400)
    
    if not current_user.check_password(current_password):
        return api_response(error='Current password is incorrect', status=401)
    
    # Check password strength
    is_strong, errors = AuthService.check_password_strength(new_password)
    if not is_strong:
        return api_response(error=errors[0] if errors else 'Password too weak', status=400)
    
    # Check breached passwords
    if AuthService.check_breached_password(new_password):
        return api_response(
            error='This password has been found in data breaches. Please choose another.',
            status=400
        )
    
    current_user.set_password(new_password)
    db.session.commit()
    
    AuditLogger.log(
        action=AuditAction.PASSWORD_CHANGED,
        resource_type='user',
        resource_id=current_user.id,
        metadata={'source': 'api'}
    )
    
    return api_response(data={'message': 'Password changed successfully'})


@api_auth_bp.route('/mfa/setup', methods=['POST'])
@api_login_required
def api_mfa_setup():
    """API MFA setup - generate QR code and secret"""
    if current_user.mfa_enabled:
        return api_response(error='MFA is already enabled', status=400)
    
    # Generate new secret and QR code
    secret, qr_svg, backup_codes = current_user.setup_mfa()
    db.session.commit()
    
    return api_response(data={
        'qr_code': qr_svg,  # SVG as string
        'backup_codes': backup_codes,
        'secret': secret  # For manual entry
    })


@api_auth_bp.route('/mfa/enable', methods=['POST'])
@api_login_required
def api_mfa_enable():
    """API MFA enable - verify code and enable MFA"""
    data = request.get_json()
    if not data:
        return api_response(error='Invalid request body', status=400)
    
    code = data.get('code', '').strip()
    if not code:
        return api_response(error='Verification code is required', status=400)
    
    if current_user.verify_totp(code):
        current_user.enable_mfa()
        db.session.commit()
        
        AuditLogger.log(
            action=AuditAction.MFA_ENABLED,
            resource_type='user',
            resource_id=current_user.id,
            metadata={'source': 'api'}
        )
        
        return api_response(data={'message': 'MFA enabled successfully'})
    
    return api_response(error='Invalid verification code', status=400)


@api_auth_bp.route('/mfa/disable', methods=['POST'])
@api_login_required
def api_mfa_disable():
    """API MFA disable"""
    data = request.get_json()
    if not data:
        return api_response(error='Invalid request body', status=400)
    
    password = data.get('password', '')
    if not password:
        return api_response(error='Password is required', status=400)
    
    if not current_user.check_password(password):
        return api_response(error='Invalid password', status=401)
    
    current_user.disable_mfa()
    db.session.commit()
    
    AuditLogger.log(
        action=AuditAction.MFA_DISABLED,
        resource_type='user',
        resource_id=current_user.id,
        metadata={'source': 'api'}
    )
    
    return api_response(data={'message': 'MFA disabled'})


def _complete_api_login(user: User) -> None:
    """Complete the API login process"""
    login_user(user)
    AuthService.record_successful_login(user)
    
    # Set session metadata
    session['_session_start'] = datetime.now(timezone.utc).isoformat()
    session['_session_ip'] = request.remote_addr
    session.permanent = False
    
    AuditLogger.log(
        action=AuditAction.LOGIN_SUCCESS,
        resource_type='user',
        resource_id=user.id,
        metadata={'source': 'api'}
    )
