"""
GAZE Security Platform - Input Sanitization
Secure input validation and sanitization
"""
import re
import html
from typing import Any, Optional, List
from functools import wraps

import bleach
from flask import request, abort
import structlog

logger = structlog.get_logger()

# Allowed HTML tags and attributes for rich text fields
ALLOWED_TAGS = [
    'p', 'br', 'strong', 'em', 'u', 's', 'code', 'pre',
    'ul', 'ol', 'li', 'blockquote', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'a', 'table', 'thead', 'tbody', 'tr', 'th', 'td'
]

ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title', 'rel'],
    'th': ['scope'],
    'td': ['colspan', 'rowspan'],
}

# Patterns for validation
PATTERNS = {
    'uuid': re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I),
    'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
    'alphanumeric': re.compile(r'^[a-zA-Z0-9]+$'),
    'alphanumeric_dash': re.compile(r'^[a-zA-Z0-9_-]+$'),
    'ip_address': re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'),
    'hostname': re.compile(r'^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)*(?!-)[A-Za-z0-9-]{1,63}(?<!-)$'),
    'url': re.compile(r'^https?://[^\s<>\"{}|\\^`\[\]]+$'),
    'cvss': re.compile(r'^(?:10\.0|[0-9]\.[0-9])$'),
}


class Sanitizer:
    """Input sanitization utilities"""
    
    @staticmethod
    def clean_html(text: str, allow_html: bool = False) -> str:
        """
        Sanitize HTML content.
        
        Args:
            text: Input text
            allow_html: If True, allows safe HTML tags. If False, escapes all HTML.
        
        Returns:
            Sanitized text
        """
        if not text:
            return ""
        
        if allow_html:
            cleaned = bleach.clean(
                text,
                tags=ALLOWED_TAGS,
                attributes=ALLOWED_ATTRIBUTES,
                strip=True
            )
            return cleaned
        else:
            return html.escape(text)
    
    @staticmethod
    def clean_text(text: str, max_length: Optional[int] = None) -> str:
        """
        Clean plain text input.
        Removes control characters and optionally truncates.
        """
        if not text:
            return ""
        
        # Remove control characters except newline and tab
        cleaned = ''.join(
            char for char in text 
            if char in '\n\t' or (ord(char) >= 32 and ord(char) != 127)
        )
        
        # Normalize whitespace
        cleaned = ' '.join(cleaned.split())
        
        if max_length and len(cleaned) > max_length:
            cleaned = cleaned[:max_length]
        
        return cleaned
    
    @staticmethod
    def validate_pattern(value: str, pattern_name: str) -> bool:
        """Validate value against a named pattern"""
        pattern = PATTERNS.get(pattern_name)
        if not pattern:
            raise ValueError(f"Unknown pattern: {pattern_name}")
        return bool(pattern.match(value))
    
    @staticmethod
    def validate_uuid(value: str) -> bool:
        """Validate UUID format"""
        return Sanitizer.validate_pattern(value, 'uuid')
    
    @staticmethod
    def validate_email(value: str) -> bool:
        """Validate email format"""
        return Sanitizer.validate_pattern(value, 'email')
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize a filename to prevent path traversal."""
        if not filename:
            return ""
        
        filename = filename.replace('\\', '/').split('/')[-1]
        filename = filename.replace('\x00', '')
        
        safe_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_')
        filename = ''.join(c if c in safe_chars else '_' for c in filename)
        
        while filename.startswith('.'):
            filename = filename[1:]
        
        if len(filename) > 255:
            name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
            filename = name[:250] + ('.' + ext if ext else '')
        
        return filename or 'unnamed'
    
    @staticmethod
    def sanitize_sql_like(value: str) -> str:
        """Escape special characters for SQL LIKE queries."""
        return value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


def validate_request_json(*required_fields: str, **field_validators):
    """Decorator to validate JSON request body."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                abort(400, description="Content-Type must be application/json")
            
            data = request.get_json()
            if not data:
                abort(400, description="Request body is empty")
            
            errors = []
            
            for field in required_fields:
                if field not in data or data[field] is None:
                    errors.append(f"Field '{field}' is required")
            
            for field, validators in field_validators.items():
                if field not in data:
                    continue
                
                value = data[field]
                
                if 'max_length' in validators:
                    if len(str(value)) > validators['max_length']:
                        errors.append(f"Field '{field}' exceeds maximum length")
                
                if 'pattern' in validators:
                    if not Sanitizer.validate_pattern(str(value), validators['pattern']):
                        errors.append(f"Field '{field}' has invalid format")
                
                if 'choices' in validators:
                    if value not in validators['choices']:
                        errors.append(f"Field '{field}' must be one of: {validators['choices']}")
            
            if errors:
                logger.warning("validation_failed", errors=errors)
                abort(400, description="; ".join(errors))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def sanitize_output(obj: Any, sensitive_fields: Optional[List[str]] = None) -> Any:
    """Sanitize an object for output, removing sensitive fields."""
    default_sensitive = {'password', 'password_hash', 'totp_secret', 'backup_codes', 'api_key'}
    sensitive = default_sensitive | set(sensitive_fields or [])
    
    if isinstance(obj, dict):
        return {k: sanitize_output(v, sensitive_fields) for k, v in obj.items() if k not in sensitive}
    elif isinstance(obj, list):
        return [sanitize_output(item, sensitive_fields) for item in obj]
    elif hasattr(obj, '__dict__'):
        return {k: sanitize_output(v, sensitive_fields) for k, v in obj.__dict__.items() if not k.startswith('_') and k not in sensitive}
    return obj
