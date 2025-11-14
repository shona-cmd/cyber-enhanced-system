"""
API Security utilities for NaashonSecureIoT.

Implements rate limiting, input validation, CSRF protection, and API gateway features.
"""

import os
import logging
import time
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable
from functools import wraps
from flask import request, g, abort, jsonify
import re
import bleach

logger = logging.getLogger(__name__)

class RateLimiter:
    """Rate limiting for API endpoints."""

    def __init__(self, config):
        self.config = config
        self.requests = {}  # In production, use Redis
        self.windows = {
            'second': 1,
            'minute': 60,
            'hour': 3600
        }

    def is_allowed(self, identifier: str, limit: int = None, window: str = 'minute') -> bool:
        """Check if request is within rate limit."""
        if limit is None:
            limit = self.config.api_rate_limit

        current_time = time.time()
        window_seconds = self.windows.get(window, 60)

        if identifier not in self.requests:
            self.requests[identifier] = []

        # Clean old requests
        self.requests[identifier] = [
            req_time for req_time in self.requests[identifier]
            if current_time - req_time < window_seconds
        ]

        # Check limit
        if len(self.requests[identifier]) >= limit:
            return False

        # Add current request
        self.requests[identifier].append(current_time)
        return True

    def get_remaining_requests(self, identifier: str, limit: int = None, window: str = 'minute') -> int:
        """Get remaining requests for identifier."""
        if limit is None:
            limit = self.config.api_rate_limit

        if identifier not in self.requests:
            return limit

        current_time = time.time()
        window_seconds = self.windows.get(window, 60)

        # Clean old requests
        self.requests[identifier] = [
            req_time for req_time in self.requests[identifier]
            if current_time - req_time < window_seconds
        ]

        return max(0, limit - len(self.requests[identifier]))


class InputValidator:
    """Input validation and sanitization."""

    def __init__(self, config):
        self.config = config
        self.validation_rules = self.load_validation_rules()

    def load_validation_rules(self) -> Dict[str, Dict[str, Any]]:
        """Load input validation rules."""
        return {
            'username': {
                'pattern': r'^[a-zA-Z0-9_-]{3,20}$',
                'max_length': 20,
                'required': True
            },
            'password': {
                'min_length': 8,
                'max_length': 128,
                'require_uppercase': True,
                'require_lowercase': True,
                'require_digits': True,
                'required': True
            },
            'email': {
                'pattern': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
                'max_length': 254,
                'required': True
            },
            'device_id': {
                'pattern': r'^[a-zA-Z0-9_-]{1,50}$',
                'max_length': 50,
                'required': True
            },
            'ip_address': {
                'pattern': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
                'required': False
            }
        }

    def validate_input(self, data: Dict[str, Any], fields: List[str] = None) -> Dict[str, List[str]]:
        """Validate input data against rules."""
        errors = {}

        if fields is None:
            fields = data.keys()

        for field in fields:
            if field not in data and self.validation_rules.get(field, {}).get('required', False):
                errors[field] = ['Field is required']
                continue

            if field in data:
                field_errors = self._validate_field(field, data[field])
                if field_errors:
                    errors[field] = field_errors

        return errors

    def _validate_field(self, field: str, value: Any) -> List[str]:
        """Validate a single field."""
        errors = []
        rules = self.validation_rules.get(field, {})

        if not isinstance(value, str):
            value = str(value)

        # Length checks
        if 'max_length' in rules and len(value) > rules['max_length']:
            errors.append(f'Maximum length is {rules["max_length"]}')

        if 'min_length' in rules and len(value) < rules['min_length']:
            errors.append(f'Minimum length is {rules["min_length"]}')

        # Pattern check
        if 'pattern' in rules:
            if not re.match(rules['pattern'], value):
                errors.append('Invalid format')

        # Password complexity
        if field == 'password':
            if rules.get('require_uppercase') and not re.search(r'[A-Z]', value):
                errors.append('Must contain uppercase letter')
            if rules.get('require_lowercase') and not re.search(r'[a-z]', value):
                errors.append('Must contain lowercase letter')
            if rules.get('require_digits') and not re.search(r'[0-9]', value):
                errors.append('Must contain digit')

        return errors

    def sanitize_input(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize input data to prevent XSS and injection attacks."""
        sanitized = {}

        for key, value in data.items():
            if isinstance(value, str):
                # HTML sanitization
                sanitized[key] = bleach.clean(value, strip=True)
                # Additional SQL injection prevention (basic)
                sanitized[key] = re.sub(r'[;\'\"\\]', '', sanitized[key])
            elif isinstance(value, dict):
                sanitized[key] = self.sanitize_input(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self.sanitize_input({'item': item})['item'] if isinstance(item, (str, dict))
                    else item for item in value
                ]
            else:
                sanitized[key] = value

        return sanitized


class CSRFProtection:
    """CSRF protection for web forms and API endpoints."""

    def __init__(self, config):
        self.config = config
        self.tokens = {}  # In production, use secure storage

    def generate_token(self, session_id: str) -> str:
        """Generate CSRF token for session."""
        token = os.urandom(32).hex()
        self.tokens[session_id] = {
            'token': token,
            'created_at': datetime.now()
        }
        return token

    def validate_token(self, session_id: str, token: str) -> bool:
        """Validate CSRF token."""
        if session_id not in self.tokens:
            return False

        token_data = self.tokens[session_id]

        # Check expiration (30 minutes)
        if datetime.now() - token_data['created_at'] > timedelta(minutes=30):
            del self.tokens[session_id]
            return False

        # Validate token
        if token_data['token'] == token:
            # Token used, remove it
            del self.tokens[session_id]
            return True

        return False

    def cleanup_expired_tokens(self):
        """Clean up expired CSRF tokens."""
        now = datetime.now()
        expired = [
            sid for sid, data in self.tokens.items()
            if now - data['created_at'] > timedelta(minutes=30)
        ]
        for sid in expired:
            del self.tokens[sid]


class APIGateway:
    """API Gateway with routing, authentication, and monitoring."""

    def __init__(self, config):
        self.config = config
        self.routes = {}
        self.middlewares = []
        self.rate_limiter = RateLimiter(config)
        self.validator = InputValidator(config)
        self.csrf_protection = CSRFProtection(config)

    def add_route(self, path: str, methods: List[str], handler: Callable,
                  auth_required: bool = True, rate_limit: int = None):
        """Add a route to the API gateway."""
        self.routes[path] = {
            'methods': methods,
            'handler': handler,
            'auth_required': auth_required,
            'rate_limit': rate_limit or self.config.api_rate_limit
        }

    def add_middleware(self, middleware: Callable):
        """Add middleware to the request pipeline."""
        self.middlewares.append(middleware)

    def process_request(self, path: str, method: str, data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Process an API request through the gateway."""
        # Find route
        route = self.routes.get(path)
        if not route:
            return {'error': 'Route not found', 'status_code': 404}

        if method not in route['methods']:
            return {'error': 'Method not allowed', 'status_code': 405}

        # Apply middlewares
        for middleware in self.middlewares:
            result = middleware(path, method, data)
            if result:
                return result

        # Rate limiting
        client_ip = getattr(request, 'remote_addr', 'unknown') if 'request' in globals() else 'unknown'
        if not self.rate_limiter.is_allowed(client_ip, route['rate_limit']):
            return {'error': 'Rate limit exceeded', 'status_code': 429}

        # Input validation and sanitization
        if data and self.config.input_validation_strict:
            validation_errors = self.validator.validate_input(data)
            if validation_errors:
                return {'error': 'Validation failed', 'details': validation_errors, 'status_code': 400}

            data = self.validator.sanitize_input(data)

        # CSRF protection for state-changing operations
        if method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            csrf_token = data.get('csrf_token') if data else None
            session_id = getattr(g, 'session_id', None) if 'g' in globals() else None
            if session_id and not self.csrf_protection.validate_token(session_id, csrf_token):
                return {'error': 'CSRF token invalid', 'status_code': 403}

        # Call handler
        try:
            result = route['handler'](data or {})
            return {'data': result, 'status_code': 200}
        except Exception as e:
            logger.error(f"API handler error: {e}")
            return {'error': 'Internal server error', 'status_code': 500}

    def get_metrics(self) -> Dict[str, Any]:
        """Get API gateway metrics."""
        return {
            'routes_count': len(self.routes),
            'middlewares_count': len(self.middlewares),
            'rate_limiter_stats': {
                'tracked_clients': len(self.rate_limiter.requests)
            }
        }


class APISecurityManager:
    """Central manager for API security features."""

    def __init__(self, config):
        self.config = config
        self.rate_limiter = RateLimiter(config)
        self.validator = InputValidator(config)
        self.csrf_protection = CSRFProtection(config)
        self.gateway = APIGateway(config)

    def initialize(self):
        """Initialize API security components."""
        logger.info("Initializing API security components")

        # Add default middlewares
        self.gateway.add_middleware(self._auth_middleware)
        self.gateway.add_middleware(self._logging_middleware)

        logger.info("API security components initialized")

    def _auth_middleware(self, path: str, method: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Authentication middleware."""
        route = self.gateway.routes.get(path)
        if route and route.get('auth_required', True):
            # Check authentication (would integrate with auth system)
            if not getattr(g, 'user', None):
                return {'error': 'Authentication required', 'status_code': 401}
        return None

    def _logging_middleware(self, path: str, method: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Logging middleware."""
        client_ip = getattr(request, 'remote_addr', 'unknown') if 'request' in globals() else 'unknown'
        logger.info(f"API Request: {method} {path} from {client_ip}")
        return None

    def get_status(self) -> Dict[str, Any]:
        """Get status of API security components."""
        return {
            'rate_limiting': {
                'enabled': True,
                'default_limit': self.config.api_rate_limit
            },
            'input_validation': {
                'enabled': self.config.input_validation_strict,
                'rules_count': len(self.validator.validation_rules)
            },
            'csrf_protection': {
                'enabled': self.config.csrf_protection_enabled,
                'active_tokens': len(self.csrf_protection.tokens)
            },
            'api_gateway': self.gateway.get_metrics()
        }


# Decorators for Flask routes
def require_api_key(f):
    """Decorator to require API key."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        # In production, validate against stored keys
        return f(*args, **kwargs)
    return decorated_function


def rate_limit(limit: int = None, window: str = 'minute'):
    """Decorator for rate limiting."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import current_app
            config = current_app.config.get('NAASHON_CONFIG')
            if config:
                rate_limiter = RateLimiter(config)
                client_ip = request.remote_addr
                if not rate_limiter.is_allowed(client_ip, limit, window):
                    return jsonify({'error': 'Rate limit exceeded'}), 429
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def validate_input(fields: List[str] = None):
    """Decorator for input validation."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import current_app
            config = current_app.config.get('NAASHON_CONFIG')
            if config and config.input_validation_strict:
                validator = InputValidator(config)
                data = request.get_json() or {}
                errors = validator.validate_input(data, fields)
                if errors:
                    return jsonify({'error': 'Validation failed', 'details': errors}), 400
            return f(*args, **kwargs)
        return decorated_function
    return decorator
