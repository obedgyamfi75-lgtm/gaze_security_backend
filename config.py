"""
GAZE Security Platform - Configuration
Security-first configuration with validation
"""
import os
from datetime import timedelta
from typing import Optional
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings


class SecurityConfig(BaseModel):
    """Security-specific configuration (policy only, not Flask wiring)"""

    password_min_length: int = 12
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_digit: bool = True
    password_require_special: bool = True
    password_min_zxcvbn_score: int = 3

    max_login_attempts: int = 5
    lockout_duration_minutes: int = 30

    session_lifetime_minutes: int = 15
    session_absolute_timeout_hours: int = 8
    session_cookie_httponly: bool = True
    session_cookie_samesite: str = "Strict"

    mfa_required_roles: list = ["superadmin", "admin", "security_lead"]
    totp_issuer: str = "GAZESecurity"
    backup_codes_count: int = 10


class Config(BaseSettings):
    """Main application configuration"""

    # Flask core
    SECRET_KEY: str = Field(..., min_length=32)
    FLASK_ENV: Optional[str] = None
    DEBUG: bool = False
    TESTING: bool = False

    # --- HTTP / HTTPS behavior (DEFAULT: HTTPS required) ---
    # Override in DevelopmentConfig / TestingConfig for local HTTP
    SESSION_COOKIE_SECURE: bool = True
    PREFERRED_URL_SCHEME: str = "https"

    # Database (credential inputs)
    DB_USER: Optional[str] = None
    DB_PASS: Optional[str] = None
    DB_NAME: Optional[str] = None
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432

    # Database (assembled)
    DATABASE_URL: Optional[str] = None
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ENGINE_OPTIONS: dict = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
        "pool_size": 10,
        "max_overflow": 20,
    }

    # Redis (credential inputs)
    REDIS_PASS: Optional[str] = None
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379

    # Redis (assembled)
    REDIS_URL: Optional[str] = None

    # Session
    SESSION_TYPE: str = "redis"
    SESSION_PERMANENT: bool = False
    SESSION_USE_SIGNER: bool = True
    SESSION_KEY_PREFIX: str = "secops:session:"
    PERMANENT_SESSION_LIFETIME: timedelta = timedelta(minutes=15)

    # Security policy
    SECURITY: SecurityConfig = SecurityConfig()
    WTF_CSRF_ENABLED: bool = True
    WTF_CSRF_TIME_LIMIT: int = 3600

    # File uploads
    MAX_CONTENT_LENGTH: int = 25 * 1024 * 1024
    EVIDENCE_PATH: str = "/app/evidence"
    ALLOWED_EXTENSIONS: set = {
        "png", "jpg", "jpeg", "gif", "pdf",
        "txt", "md", "json", "xml", "html"
    }

    # Rate limiting
    RATELIMIT_ENABLED: bool = True
    RATELIMIT_STORAGE_URL: Optional[str] = None
    RATELIMIT_DEFAULT: str = "200 per minute"
    RATELIMIT_HEADERS_ENABLED: bool = True

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"

    # ClamAV
    CLAMAV_HOST: str = "clamav"
    CLAMAV_PORT: int = 3310

    # PDF Sandbox
    PDF_SANDBOX_HOST: str = "pdf-sandbox"
    PDF_SANDBOX_PORT: int = 8001

    # Hosts / CORS
    ALLOWED_HOSTS: str = "localhost"
    CORS_ORIGINS: str = "http://localhost:3000"

    # PII
    PII_ENCRYPTION_KEY: Optional[str] = None

    # -------------------------
    # Validators
    # -------------------------

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v):
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        if v in {"changeme", "development"}:
            raise ValueError("SECRET_KEY must not be a default value")
        return v

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_database_url(cls, v, info):
        if v:
            return v
        data = info.data
        if not all([data.get("DB_USER"), data.get("DB_PASS"), data.get("DB_NAME")]):
            raise ValueError("DATABASE_URL or DB_* credentials must be provided")
        return (
            f"postgresql://{data['DB_USER']}:{data['DB_PASS']}"
            f"@{data['DB_HOST']}:{data['DB_PORT']}/{data['DB_NAME']}"
        )

    @field_validator("REDIS_URL", mode="before")
    @classmethod
    def assemble_redis_url(cls, v, info):
        if v:
            return v
        data = info.data
        if not data.get("REDIS_PASS"):
            raise ValueError("REDIS_URL or REDIS_PASS must be provided")
        return (
            f"redis://:{data['REDIS_PASS']}"
            f"@{data['REDIS_HOST']}:{data['REDIS_PORT']}/0"
        )

    @property
    def SQLALCHEMY_DATABASE_URI(self) -> str:
        return self.DATABASE_URL

    model_config = {
        "env_file": ".env",
        "case_sensitive": True,
    }


class DevelopmentConfig(Config):
    LOG_LEVEL: str = "DEBUG"
    SESSION_COOKIE_SECURE: bool = False
    PREFERRED_URL_SCHEME: str = "http"

    model_config = {
        "env_file": ".env.dev",
        "case_sensitive": True,
    }


class TestingConfig(Config):
    TESTING: bool = True
    WTF_CSRF_ENABLED: bool = False
    RATELIMIT_ENABLED: bool = False
    SESSION_COOKIE_SECURE: bool = False
    PREFERRED_URL_SCHEME: str = "http"

    model_config = {
        "env_file": ".env.test",
        "case_sensitive": True,
    }


class ProductionConfig(Config):
    SESSION_COOKIE_SECURE: bool = True
    PREFERRED_URL_SCHEME: str = "https"

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_production_secret(cls, v):
        if len(v) < 64:
            raise ValueError("Production SECRET_KEY must be at least 64 characters")
        return v


def get_config() -> Config:
    env = os.getenv("FLASK_ENV", "production")
    configs = {
        "development": DevelopmentConfig,
        "testing": TestingConfig,
        "production": ProductionConfig,
    }
    return configs.get(env, ProductionConfig)()
