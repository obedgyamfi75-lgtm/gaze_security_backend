from functools import wraps
from flask import request, jsonify, g
from flask_login import login_user, current_user


def require_api_key_or_login(scope=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get('Authorization', '')

            # Try API key first
            if auth_header.startswith('Bearer '):
                raw_key = auth_header[7:]

                from app.models.api_key import ApiKey
                from app.models.user import User

                key = ApiKey.verify(raw_key)

                if not key:
                    return jsonify({'success': False, 'error': 'Invalid or revoked API key'}), 401

                if scope and not key.has_scope(scope):
                    return jsonify({'success': False, 'error': f'Key missing required scope: {scope}'}), 403

                user = User.query.get(key.user_id)
                if not user or not user.is_active:
                    return jsonify({'success': False, 'error': 'User not found or inactive'}), 401

                login_user(user)
                g.api_key = key
                return f(*args, **kwargs)

            # Try session auth
            if current_user.is_authenticated:
                return f(*args, **kwargs)

            # Neither — reject
            return jsonify({'success': False, 'error': 'Authentication required'}), 401

        return decorated
    return decorator