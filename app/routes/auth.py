"""
GAZE Security Platform - Authentication Routes
"""
from datetime import datetime, timezone

from flask import Blueprint, request, session, redirect, url_for, render_template, flash
from flask_login import login_user, logout_user, login_required, current_user
import structlog

from app import db, login_manager, limiter
from app.models import User
from app.security import AuthService, AuditLogger, AuditAction

logger = structlog.get_logger()

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    return User.query.get(user_id)


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    """User login with MFA support"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').lower().strip()
        password = request.form.get('password', '')
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            logger.warning("login_failed_unknown_user", email=email)
            flash('Invalid email or password', 'error')
            return render_template('auth/login.html')
        
        # Check lockout
        is_locked, lockout_until = AuthService.check_account_lockout(user)
        if is_locked:
            logger.warning("login_blocked_lockout", user_id=str(user.id))
            flash(f'Account locked until {lockout_until.strftime("%H:%M")}', 'error')
            return render_template('auth/login.html')
        
        # Verify password
        if not user.check_password(password):
            AuthService.record_failed_login(user)
            AuditLogger.log(
                action=AuditAction.LOGIN_FAILED,
                resource_type='user',
                resource_id=user.id,
                metadata={'reason': 'invalid_password'}
            )
            flash('Invalid email or password', 'error')
            return render_template('auth/login.html')
        
        # Check if MFA is required
        if user.mfa_enabled:
            session['pending_mfa_user_id'] = str(user.id)
            session['_session_ip'] = request.remote_addr
            return redirect(url_for('auth.mfa_verify'))
        
        # Login successful
        _complete_login(user)
        return redirect(url_for('dashboard.index'))
    
    return render_template('auth/login.html')


@auth_bp.route('/mfa/verify', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def mfa_verify():
    """MFA verification step"""
    user_id = session.get('pending_mfa_user_id')
    if not user_id:
        return redirect(url_for('auth.login'))
    
    user = User.query.get(user_id)
    if not user:
        session.pop('pending_mfa_user_id', None)
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        use_backup = request.form.get('use_backup') == 'true'
        
        if use_backup:
            if user.use_backup_code(code):
                db.session.commit()
                session.pop('pending_mfa_user_id', None)
                _complete_login(user)
                flash('Backup code used. Consider generating new codes.', 'warning')
                return redirect(url_for('dashboard.index'))
        else:
            if user.verify_totp(code):
                session.pop('pending_mfa_user_id', None)
                session['mfa_verified'] = True
                _complete_login(user)
                return redirect(url_for('dashboard.index'))
        
        AuditLogger.log(
            action=AuditAction.LOGIN_FAILED,
            resource_type='user',
            resource_id=user.id,
            metadata={'reason': 'invalid_mfa_code'}
        )
        flash('Invalid verification code', 'error')
    
    return render_template('auth/mfa_verify.html')


@auth_bp.route('/mfa/setup', methods=['GET', 'POST'])
@login_required
def mfa_setup():
    """Setup MFA for user"""
    if current_user.mfa_enabled:
        flash('MFA is already enabled', 'info')
        return redirect(url_for('dashboard.index'))
    
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        
        if current_user.verify_totp(code):
            current_user.enable_mfa()
            db.session.commit()
            
            AuditLogger.log(
                action=AuditAction.MFA_ENABLED,
                resource_type='user',
                resource_id=current_user.id
            )
            
            flash('MFA enabled successfully', 'success')
            return redirect(url_for('dashboard.index'))
        
        flash('Invalid verification code', 'error')
    
    # Generate new secret and QR code
    secret, qr_svg, backup_codes = current_user.setup_mfa()
    db.session.commit()
    
    return render_template('auth/mfa_setup.html', qr_svg=qr_svg, backup_codes=backup_codes)


@auth_bp.route('/mfa/disable', methods=['POST'])
@login_required
def mfa_disable():
    """Disable MFA"""
    password = request.form.get('password', '')
    
    if not current_user.check_password(password):
        flash('Invalid password', 'error')
        return redirect(url_for('auth.profile'))
    
    current_user.disable_mfa()
    db.session.commit()
    
    AuditLogger.log(
        action=AuditAction.MFA_DISABLED,
        resource_type='user',
        resource_id=current_user.id
    )
    
    flash('MFA disabled', 'warning')
    return redirect(url_for('auth.profile'))


@auth_bp.route('/logout')
@login_required
def logout():
    """User logout"""
    AuditLogger.log(action=AuditAction.LOGOUT)
    logout_user()
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/profile')
@login_required
def profile():
    """User profile"""
    return render_template('auth/profile.html')


@auth_bp.route('/change-password', methods=['POST'])
@login_required
@limiter.limit("3 per minute")
def change_password():
    """Change user password"""
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    if not current_user.check_password(current_password):
        flash('Current password is incorrect', 'error')
        return redirect(url_for('auth.profile'))
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'error')
        return redirect(url_for('auth.profile'))
    
    # Check password strength
    is_strong, errors = AuthService.check_password_strength(new_password)
    if not is_strong:
        for error in errors:
            flash(error, 'error')
        return redirect(url_for('auth.profile'))
    
    # Check breached passwords
    if AuthService.check_breached_password(new_password):
        flash('This password has been found in data breaches. Please choose another.', 'error')
        return redirect(url_for('auth.profile'))
    
    current_user.set_password(new_password)
    db.session.commit()
    
    AuditLogger.log(
        action=AuditAction.PASSWORD_CHANGED,
        resource_type='user',
        resource_id=current_user.id
    )
    
    flash('Password changed successfully', 'success')
    return redirect(url_for('auth.profile'))


def _complete_login(user: User) -> None:
    """Complete the login process"""
    login_user(user)
    AuthService.record_successful_login(user)
    
    # Set session metadata
    session['_session_start'] = datetime.now(timezone.utc).isoformat()
    session['_session_ip'] = request.remote_addr
    session.permanent = False
    
    AuditLogger.log(
        action=AuditAction.LOGIN_SUCCESS,
        resource_type='user',
        resource_id=user.id
    )
