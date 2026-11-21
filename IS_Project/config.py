import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Base configuration for SecureVault Document Management System."""
    # Security: Secret key for signing sessions and CSRF tokens
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-vault-secret-key-3f8a912e84c172b5')

    # Database: SQLite database location
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        f"sqlite:///{os.path.join(BASE_DIR, 'database', 'app.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session and Cookie Security
    # Mitigate XSS attacks by preventing client-side scripts from reading session cookies
    SESSION_COOKIE_HTTPONLY = True
    # Mitigate CSRF by restricting when cookies are sent in cross-site requests
    SESSION_COOKIE_SAMESITE = 'Lax'
    # Enable Secure flag only over HTTPS in production
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() in ('true', '1')
    # Session expiration lifetime
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)

    # Remember Me cookie settings
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    REMEMBER_COOKIE_DURATION = timedelta(days=7)

    # Form and CSRF Security
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # CSRF token expires after 1 hour

    # Rate Limiting configuration
    RATELIMIT_DEFAULT = "200 per day; 50 per hour"
    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_STRATEGY = "fixed-window"


class TestConfig(Config):
    """Configuration for automated test suite."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = True
    RATELIMIT_ENABLED = False
