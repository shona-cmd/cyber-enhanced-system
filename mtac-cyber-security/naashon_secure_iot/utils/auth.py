"""
Authentication and Authorization utilities for NaashonSecureIoT.

Implements JWT tokens, MFA, RBAC, and secure session management.
"""

import os
import jwt
import hashlib
import hmac
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import logging
from functools import wraps
from flask import request, g, session, abort
import pyotp
import qrcode
import io
import base64

logger = logging.getLogger(__name__)

class UserManager:
    """User management with secure password handling."""

    def __init__(self, config):
        self.config = config
        self.users = {}  # In production, use database
        self.roles = {
            'admin': ['read', 'write', 'delete', 'admin'],
            'operator': ['read', 'write'],
            'viewer': ['read']
        }

    def create_user(self, username: str, password: str, role: str = 'viewer') -> bool:
        """Create a new user with secure password hashing."""
        if username in self.users:
            return False

        salt = os.urandom(32)
        hashed_password = self._hash_password(password, salt)

        self.users[username] = {
            'password_hash': hashed_password,
            'salt': salt,
            'role': role,
            'mfa_secret': None,
            'mfa_enabled': False,
            'created_at': datetime.now(),
            'last_login': None,
            'failed_attempts': 0,
            'locked_until': None
        }
        logger.info(f"User {username} created with role {role}")
        return True

    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user with account lockout protection."""
        if username not in self.users:
            return None

        user = self.users[username]

        # Check if account is locked
        if user['locked_until'] and datetime.now() < user['locked_until']:
            logger.warning(f"Account {username} is locked")
            return None

        # Verify password
        if not self._verify_password(password, user['password_hash'], user['salt']):
            user['failed_attempts'] += 1
            if user['failed_attempts'] >= 5:
                user['locked_until'] = datetime.now() + timedelta(minutes=30)
                logger.warning(f"Account {username} locked due to failed attempts")
            return None

        # Reset failed attempts on successful login
        user['failed_attempts'] = 0
        user['last_login'] = datetime.now()

        return {
            'username': username,
            'role': user['role'],
            'mfa_required': user['mfa_enabled']
        }

    def _hash_password(self, password: str, salt: bytes) -> bytes:
        """Hash password using PBKDF2."""
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

    def _verify_password(self, password: str, hash: bytes, salt: bytes) -> bool:
        """Verify password against hash."""
        return hmac.compare_digest(hash, self._hash_password(password, salt))

    def setup_mfa(self, username: str) -> Optional[str]:
        """Setup MFA for user and return QR code."""
        if username not in self.users:
            return None

        user = self.users[username]
        secret = pyotp.random_base32()
        user['mfa_secret'] = secret

        # Generate QR code
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(username, issuer_name=self.config.mfa_issuer)

        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_code = base64.b64encode(buffer.getvalue()).decode()

        return qr_code

    def verify_mfa(self, username: str, code: str) -> bool:
        """Verify MFA code."""
        if username not in self.users or not self.users[username]['mfa_secret']:
            return False

        totp = pyotp.TOTP(self.users[username]['mfa_secret'])
        return totp.verify(code)

    def enable_mfa(self, username: str) -> bool:
        """Enable MFA for user."""
        if username in self.users:
            self.users[username]['mfa_enabled'] = True
            logger.info(f"MFA enabled for user {username}")
            return True
        return False

    def get_user_permissions(self, username: str) -> List[str]:
        """Get user permissions based on role."""
        if username not in self.users:
            return []
        role = self.users[username]['role']
        return self.roles.get(role, [])


class JWTManager:
    """JWT token management with refresh tokens."""

    def __init__(self, config):
        self.config = config

    def create_access_token(self, identity: Dict[str, Any]) -> str:
        """Create JWT access token."""
        payload = {
            'identity': identity,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(minutes=self.config.jwt_access_token_expire_minutes),
            'type': 'access'
        }
        return jwt.encode(payload, self.config.jwt_secret_key, algorithm='HS256')

    def create_refresh_token(self, identity: Dict[str, Any]) -> str:
        """Create JWT refresh token."""
        payload = {
            'identity': identity,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(days=self.config.jwt_refresh_token_expire_days),
            'type': 'refresh'
        }
        return jwt.encode(payload, self.config.jwt_secret_key, algorithm='HS256')

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token."""
        try:
            payload = jwt.decode(token, self.config.jwt_secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return None

    def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """Create new access token from refresh token."""
        payload = self.verify_token(refresh_token)
        if not payload or payload.get('type') != 'refresh':
            return None

        identity = payload['identity']
        return self.create_access_token(identity)


class AuthMiddleware:
    """Flask middleware for authentication and authorization."""

    def __init__(self, app, user_manager: UserManager, jwt_manager: JWTManager, config):
        self.app = app
        self.user_manager = user_manager
        self.jwt_manager = jwt_manager
        self.config = config

        # Register middleware
        app.before_request(self.authenticate_request)
        app.after_request(self.add_security_headers)

    def authenticate_request(self):
        """Authenticate incoming requests."""
        # Skip authentication for certain routes
        if request.endpoint in ['login', 'register', 'static', 'health']:
            return

        # Check for API key if required
        if self.config.api_key_required:
            api_key = request.headers.get('X-API-Key')
            if not api_key or not self._verify_api_key(api_key):
                abort(401, "Invalid API key")

        # Check for JWT token
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            payload = self.jwt_manager.verify_token(token)
            if payload:
                g.user = payload['identity']
                g.permissions = self.user_manager.get_user_permissions(g.user['username'])
            else:
                abort(401, "Invalid token")

    def add_security_headers(self, response):
        """Add security headers to response."""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response

    def _verify_api_key(self, api_key: str) -> bool:
        """Verify API key (placeholder - implement proper key storage)."""
        # In production, check against database
        return api_key == os.getenv('API_KEY', 'default-api-key')


def require_permission(permission: str):
    """Decorator to require specific permission."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'permissions') or permission not in g.permissions:
                abort(403, f"Permission '{permission}' required")
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_role(role: str):
    """Decorator to require specific role."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'user') or g.user.get('role') != role:
                abort(403, f"Role '{role}' required")
            return f(*args, **kwargs)
        return decorated_function
    return decorator


class SessionManager:
    """Secure session management."""

    def __init__(self, config):
        self.config = config
        self.sessions = {}  # In production, use Redis or database

    def create_session(self, user_identity: Dict[str, Any]) -> str:
        """Create a new secure session."""
        session_id = os.urandom(32).hex()
        self.sessions[session_id] = {
            'user': user_identity,
            'created_at': datetime.now(),
            'last_activity': datetime.now(),
            'ip_address': request.remote_addr if request else None,
            'user_agent': request.headers.get('User-Agent') if request else None
        }
        return session_id

    def validate_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Validate session and check for expiration."""
        if session_id not in self.sessions:
            return None

        session_data = self.sessions[session_id]
        now = datetime.now()

        # Check session timeout
        if (now - session_data['last_activity']) > self.config.permanent_session_lifetime:
            del self.sessions[session_id]
            return None

        # Update last activity
        session_data['last_activity'] = now
        return session_data

    def destroy_session(self, session_id: str):
        """Destroy a session."""
        if session_id in self.sessions:
            del self.sessions[session_id]

    def cleanup_expired_sessions(self):
        """Clean up expired sessions."""
        now = datetime.now()
        expired = [
            sid for sid, data in self.sessions.items()
            if (now - data['last_activity']) > self.config.permanent_session_lifetime
        ]
        for sid in expired:
            del self.sessions[sid]
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired sessions")
