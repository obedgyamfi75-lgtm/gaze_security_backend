"""
GAZE Security Platform - Authentication Module
Secure authentication with Argon2id, TOTP MFA, and account lockout
"""
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple
from functools import wraps

import pyotp
import qrcode
import qrcode.image.svg
from argon2 import PasswordHasher, exceptions as argon2_exceptions
from flask import current_app, request, abort, session
from flask_login import current_user
import structlog

from app import db

logger = structlog.get_logger()

# Argon2id configuration (OWASP recommended)
ph = PasswordHasher(
    time_cost=3,        # Number of iterations
    memory_cost=65536,  # 64 MB
    parallelism=4,      # Number of threads
    hash_len=32,        # Output hash length
    salt_len=16,        # Salt length
)


class AuthService:
    """Authentication service with security controls"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using Argon2id"""
        return ph.hash(password)
    
    @staticmethod
    def verify_password(password: str, hash: str) -> bool:
        """Verify password against hash (timing-safe)"""
        try:
            ph.verify(hash, password)
            
            # Check if rehash is needed (params changed)
            if ph.check_needs_rehash(hash):
                return True  # Signal to rehash
            return True
        except argon2_exceptions.VerifyMismatchError:
            return False
        except argon2_exceptions.InvalidHash:
            logger.error("invalid_password_hash")
            return False
    
    @staticmethod
    def check_password_strength(password: str) -> Tuple[bool, list]:
        """
        Check password against policy requirements.
        Returns (is_valid, list of failed requirements)
        """
        from zxcvbn import zxcvbn
        
        # Get security config - it's a Pydantic model, not a dict
        security_config = current_app.config.get('SECURITY')
        errors = []
        
        # Use getattr for Pydantic model or default values
        min_length = getattr(security_config, 'password_min_length', 12) if security_config else 12
        require_uppercase = getattr(security_config, 'password_require_uppercase', True) if security_config else True
        require_lowercase = getattr(security_config, 'password_require_lowercase', True) if security_config else True
        require_digit = getattr(security_config, 'password_require_digit', True) if security_config else True
        require_special = getattr(security_config, 'password_require_special', True) if security_config else True
        min_score = getattr(security_config, 'password_min_zxcvbn_score', 3) if security_config else 3
        
        # Length check
        if len(password) < min_length:
            errors.append(f"Password must be at least {min_length} characters")
        
        # Character requirements
        if require_uppercase and not any(c.isupper() for c in password):
            errors.append("Password must contain an uppercase letter")
        
        if require_lowercase and not any(c.islower() for c in password):
            errors.append("Password must contain a lowercase letter")
        
        if require_digit and not any(c.isdigit() for c in password):
            errors.append("Password must contain a digit")
        
        if require_special:
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if not any(c in special_chars for c in password):
                errors.append("Password must contain a special character")
        
        # zxcvbn strength check
        result = zxcvbn(password)
        if result['score'] < min_score:
            errors.append(f"Password is too weak. {result['feedback'].get('warning', '')}")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def check_breached_password(password: str) -> bool:
        """
        Check if password appears in known breaches using k-anonymity.
        Returns True if password is breached.
        """
        import requests
        
        # SHA-1 hash the password
        sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        
        try:
            # Query HIBP API with k-anonymity
            response = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                timeout=5,
                headers={'Add-Padding': 'true'}
            )
            
            if response.status_code == 200:
                hashes = response.text.splitlines()
                for line in hashes:
                    hash_suffix, count = line.split(':')
                    if hash_suffix == suffix:
                        logger.warning("breached_password_detected", count=count)
                        return True
            return False
        except Exception as e:
            logger.warning("hibp_check_failed", error=str(e))
            return False  # Fail open, don't block registration
    
    @staticmethod
    def generate_totp_secret() -> str:
        """Generate a new TOTP secret"""
        return pyotp.random_base32()
    
    @staticmethod
    def get_totp_uri(secret: str, email: str) -> str:
        """Get TOTP provisioning URI for QR code"""
        security_config = current_app.config.get('SECURITY')
        issuer = getattr(security_config, 'totp_issuer', 'GAZESecurity') if security_config else 'GAZESecurity'
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=email, issuer_name=issuer)
    
    @staticmethod
    def generate_totp_qr(secret: str, email: str) -> str:
        """Generate QR code SVG for TOTP setup"""
        uri = AuthService.get_totp_uri(secret, email)
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(image_factory=qrcode.image.svg.SvgImage)
        return img.to_string().decode('utf-8')
    
    @staticmethod
    def verify_totp(secret: str, code: str) -> bool:
        """Verify TOTP code with clock drift tolerance"""
        totp = pyotp.TOTP(secret)
        # Allow 1 period of clock drift
        return totp.verify(code, valid_window=1)
    
    @staticmethod
    def generate_backup_codes(count: int = 10) -> list:
        """Generate backup codes for MFA recovery"""
        codes = []
        for _ in range(count):
            code = secrets.token_hex(4).upper()  # 8 character hex codes
            codes.append(code)
        return codes
    
    @staticmethod
    def hash_backup_code(code: str) -> str:
        """Hash a backup code for storage"""
        return hashlib.sha256(code.encode()).hexdigest()
    
    @staticmethod
    def check_account_lockout(user) -> Tuple[bool, Optional[datetime]]:
        """
        Check if account is locked out.
        Returns (is_locked, lockout_expires_at)
        """
        security_config = current_app.config.get('SECURITY')
        max_attempts = getattr(security_config, 'max_login_attempts', 5) if security_config else 5
        lockout_minutes = getattr(security_config, 'lockout_duration_minutes', 30) if security_config else 30
        
        if user.failed_login_attempts >= max_attempts:
            if user.lockout_until and user.lockout_until > datetime.now(timezone.utc):
                return True, user.lockout_until
            else:
                # Lockout expired, reset
                user.failed_login_attempts = 0
                user.lockout_until = None
                db.session.commit()
        
        return False, None
    
    @staticmethod
    def record_failed_login(user) -> None:
        """Record a failed login attempt"""
        security_config = current_app.config.get('SECURITY')
        max_attempts = getattr(security_config, 'max_login_attempts', 5) if security_config else 5
        lockout_minutes = getattr(security_config, 'lockout_duration_minutes', 30) if security_config else 30
        
        user.failed_login_attempts += 1
        user.last_failed_login = datetime.now(timezone.utc)
        
        if user.failed_login_attempts >= max_attempts:
            user.lockout_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
            logger.warning(
                "account_locked",
                user_id=str(user.id),
                attempts=user.failed_login_attempts,
                lockout_until=user.lockout_until.isoformat()
            )
        
        db.session.commit()
    
    @staticmethod
    def record_successful_login(user) -> None:
        """Record a successful login"""
        user.failed_login_attempts = 0
        user.lockout_until = None
        user.last_login = datetime.now(timezone.utc)
        user.last_login_ip = request.remote_addr
        db.session.commit()
        
        logger.info("login_success", user_id=str(user.id))
    
    @staticmethod
    def validate_session() -> bool:
        """Validate current session security"""
        # Check session age
        session_start = session.get('_session_start')
        if session_start:
            security_config = current_app.config.get('SECURITY')
            max_age_hours = getattr(security_config, 'session_absolute_timeout_hours', 8) if security_config else 8
            
            if datetime.fromisoformat(session_start) + timedelta(hours=max_age_hours) < datetime.now(timezone.utc):
                logger.info("session_expired_absolute_timeout")
                return False
        
        # Check IP consistency (optional, can break with mobile)
        stored_ip = session.get('_session_ip')
        if stored_ip and stored_ip != request.remote_addr:
            logger.warning(
                "session_ip_mismatch",
                stored_ip=stored_ip,
                current_ip=request.remote_addr
            )
            # Don't invalidate, just log (mobile users change IPs)
        
        return True


def require_mfa(f):
    """Decorator to require MFA verification for sensitive operations"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        
        if current_user.mfa_enabled and not session.get('mfa_verified'):
            abort(403, description="MFA verification required")
        
        return f(*args, **kwargs)
    return decorated_function


def require_role(*roles):
    """Decorator to require specific role(s)"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            
            if current_user.role not in roles:
                logger.warning(
                    "unauthorized_role_access",
                    user_id=str(current_user.id),
                    required_roles=roles,
                    user_role=current_user.role
                )
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def log_security_event(event_type: str, **kwargs) -> None:
    """Log a security-relevant event"""
    logger.info(
        event_type,
        user_id=str(current_user.id) if current_user.is_authenticated else None,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string[:100] if request.user_agent else None,
        **kwargs
    )