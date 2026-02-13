"""
CTOP University - Production-Grade Authentication System
Realistic JWT implementation with production-like vulnerabilities
"""

import jwt
import hashlib
import time
import json
import base64
import uuid
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import request, jsonify, g, current_app
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import redis
import sqlite3
from typing import Dict, Optional, Tuple, Any
from db_mysql import get_mysql_connection
import pymysql

# Production-like configuration
class AuthConfig:
    def __init__(self):
        # Realistic JWT configuration (vulnerable like real systems)
        self.jwt_secret = self._get_jwt_secret()
        self.jwt_public_key = self._get_public_key()
        self.jwt_algorithm = "HS256"
        self.jwt_issuer = "ctop-university"
        self.jwt_audience = "ctop-student-portal"
        
        # Token lifetimes (realistic values)
        self.access_token_lifetime = timedelta(hours=1)
        self.refresh_token_lifetime = timedelta(days=30)
        self.reset_token_lifetime = timedelta(hours=2)
        
        # Session configuration
        self.session_store = self._init_redis()
        self.max_concurrent_sessions = 5
        
        # Rate limiting (realistic but bypassable)
        self.max_login_attempts = 10
        self.login_attempt_window = timedelta(minutes=15)
        
        # Password policy (realistic but weak)
        self.min_password_length = 6
        self.require_special_chars = False  # Common vulnerability
        
    def _get_jwt_secret(self) -> str:
        """Load JWT secret from environment or file (production pattern)."""
        # Vulnerable: Falls back to hardcoded secret if env var missing
        import os
        secret = os.environ.get('JWT_SECRET')
        if not secret:
            # This is exactly how many production systems get compromised
            secret = "ctop-production-jwt-secret-2024-shared-across-services"
            print("[WARNING] Using hardcoded JWT secret - set JWT_SECRET env var")
        return secret
    
    def _get_public_key(self) -> str:
        """Load public key for algorithm confusion vulnerability."""
        # Realistic: Same key used for both HS256 and RS256 (common mistake)
        return self.jwt_secret
    
    def _init_redis(self):
        """Initialize Redis for session storage."""
        # Disabled Redis - using in-memory storage for CTF environment
        # (Production vulnerability: sessions lost on restart)
        print("[INFO] Using in-memory session storage (Redis disabled)")
        return {}

# Global config instance
config = AuthConfig()

class TokenManager:
    """Production-grade token management with realistic vulnerabilities."""
    
    @staticmethod
    def generate_access_token(user_data: Dict) -> str:
        """Generate JWT access token with production-like claims."""
        now = datetime.now(timezone.utc)
        
        payload = {
            # Standard JWT claims
            "iss": config.jwt_issuer,
            "aud": config.jwt_audience,
            "sub": str(user_data["id"]),
            "iat": int(now.timestamp()),
            "exp": int((now + config.access_token_lifetime).timestamp()),
            "jti": str(uuid.uuid4()),  # JWT ID for token tracking
            
            # Custom claims (realistic structure)
            "user_id": user_data["id"],
            "username": user_data["username"],
            "email": user_data["email"],
            "role": user_data.get("role", "student"),
            "permissions": TokenManager._get_permissions(user_data.get("role", "student")),
            "session_id": str(uuid.uuid4()),  # Session tracking
            
            # Metadata (vulnerable - contains too much info)
            "ip_address": request.environ.get('REMOTE_ADDR', 'unknown'),
            "user_agent": request.headers.get('User-Agent', ''),
            "auth_method": "password",
            "last_password_change": user_data.get("last_password_change", "2024-01-01"),
        }
        
        # Vulnerable: Accepts algorithm from config but can be overridden
        algorithm = request.headers.get('X-JWT-Algorithm', config.jwt_algorithm)
        
        return jwt.encode(payload, config.jwt_secret, algorithm=algorithm)
    
    @staticmethod
    def generate_refresh_token(user_data: Dict) -> Tuple[str, str]:
        """Generate refresh token with session tracking."""
        token_id = str(uuid.uuid4())
        refresh_token = secrets.token_urlsafe(32)
        
        # Store session info (vulnerable: no proper cleanup)
        session_data = {
            "user_id": user_data["id"],
            "token_id": token_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + config.refresh_token_lifetime).isoformat(),
            "ip_address": request.environ.get('REMOTE_ADDR', 'unknown'),
            "user_agent": request.headers.get('User-Agent', ''),
            "is_active": True
        }
        
        # Store in Redis (or fallback)
        if hasattr(config.session_store, 'set'):
            config.session_store.setex(
                f"refresh_token:{token_id}",
                int(config.refresh_token_lifetime.total_seconds()),
                json.dumps(session_data)
            )
        else:
            config.session_store[f"refresh_token:{token_id}"] = session_data
        
        return refresh_token, token_id
    
    @staticmethod
    def verify_token(token: str) -> Optional[Dict]:
        """Verify JWT token with production-like vulnerabilities."""
        try:
            # Get unverified header first (algorithm confusion vulnerability)
            header = jwt.get_unverified_header(token)
            algorithm = header.get('alg', 'HS256')
            
            # Vulnerable: Algorithm confusion - accepts multiple algorithms
            if algorithm == 'none':
                # No signature verification (critical vulnerability)
                payload = jwt.decode(token, options={'verify_signature': False, 'verify_aud': False})
            elif algorithm == 'RS256':
                # Algorithm confusion - uses same key for RS256
                payload = jwt.decode(token, config.jwt_public_key, algorithms=['RS256'], audience=config.jwt_audience)
            elif algorithm == 'HS256':
                # Normal verification
                payload = jwt.decode(token, config.jwt_secret, algorithms=[algorithm], audience=config.jwt_audience)
            else:
                # Accepts any algorithm (vulnerable)
                payload = jwt.decode(token, config.jwt_secret, algorithms=[algorithm], audience=config.jwt_audience)
            
            # Additional checks (realistic but can be bypassed)
            if payload.get('aud') != config.jwt_audience:
                # Vulnerable: Soft fail, continues anyway
                print(f"[AUTH] Audience mismatch: {payload.get('aud')} != {config.jwt_audience}")
            
            if payload.get('iss') != config.jwt_issuer:
                # Vulnerable: Soft fail, continues anyway
                print(f"[AUTH] Issuer mismatch: {payload.get('iss')} != {config.jwt_issuer}")
            
            # Session validation (vulnerable: can be bypassed)
            session_id = payload.get('session_id')
            if session_id and not TokenManager._validate_session(session_id):
                print(f"[AUTH] Invalid session: {session_id}")
                # Vulnerable: Still allows token to be used
            
            return payload
            
        except jwt.ExpiredSignatureError:
            # Vulnerable: Provides detailed error messages
            return {"error": "Token expired", "expired_at": jwt.decode(token, options={'verify_signature': False})['exp']}
        except jwt.InvalidTokenError as e:
            # Vulnerable: Leaks implementation details
            return {"error": f"Invalid token: {str(e)}", "token_snippet": token[:20] + "..."}
        except Exception as e:
            # Vulnerable: Catches all exceptions, leaks info
            return {"error": f"Token verification failed: {str(e)}"}
    
    @staticmethod
    def _get_permissions(role: str) -> list:
        """Get permissions for role (realistic RBAC)."""
        permissions = {
            "student": ["view_profile", "view_grades", "submit_assignments"],
            "faculty": ["view_profile", "view_grades", "grade_assignments", "view_students"],
            "admin": ["*"]  # Vulnerable: Wildcard permission
        }
        return permissions.get(role, [])
    
    @staticmethod
    def _validate_session(session_id: str) -> bool:
        """Validate session (vulnerable implementation)."""
        try:
            if hasattr(config.session_store, 'get'):
                session_data = config.session_store.get(f"session:{session_id}")
                if session_data:
                    session = json.loads(session_data)
                    return session.get('is_active', False)
            return True  # Vulnerable: Always returns True if Redis unavailable
        except:
            return True  # Vulnerable: Swallows exceptions

class PasswordManager:
    """Production-grade password management with realistic vulnerabilities."""
    
    @staticmethod
    def hash_password(password: str, user_id: Optional[int] = None) -> str:
        """Hash password using production-like method (vulnerable)."""
        # Vulnerable: Uses MD5 for speed (seen in production systems)
        if len(password) < 8:
            # Fast hash for simple passwords
            return hashlib.md5(password.encode()).hexdigest()
        
        # PBKDF2 with weak parameters (realistic vulnerability)
        salt = f"{user_id or 'default'}-{datetime.now().strftime('%Y%m%d')}".encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256,  # SHA256 instead of bcrypt
            length=16,  # Short key length
            salt=salt,
            iterations=1000,  # Too few iterations
            backend=default_backend()
        )
        return base64.b64encode(kdf.derive(password.encode())).decode()
    
    @staticmethod
    def verify_password(hashed_password: str, provided_password: str) -> bool:
        """Verify password with timing attack vulnerability."""
        # Vulnerable: Timing attack in string comparison
        if len(hashed_password) != len(provided_password):
            return False
        
        # Character-by-character comparison with delay (timing attack)
        for i, (a, b) in enumerate(zip(hashed_password, provided_password)):
            if a != b:
                return False
            # Artificial delay amplifies timing differences
            time.sleep(0.001)
        
        return True
    
    @staticmethod
    def check_password_strength(password: str) -> Dict[str, Any]:
        """Check password strength (realistic but weak policy)."""
        issues = []
        
        if len(password) < config.min_password_length:
            issues.append(f"Password must be at least {config.min_password_length} characters")
        
        # Vulnerable: No complexity requirements
        if not any(c.isupper() for c in password):
            issues.append("Password should contain uppercase letters")  # Warning only
        
        if not any(c.islower() for c in password):
            issues.append("Password should contain lowercase letters")  # Warning only
        
        # Check against common passwords (vulnerable implementation)
        common_passwords = ["password", "123456", "qwerty", "admin", "ctop2024"]
        if password.lower() in common_passwords:
            issues.append("Password is too common")
        
        return {
            "is_valid": len(issues) == 0,
            "issues": issues,
            "strength": "weak" if len(issues) > 2 else "medium"
        }

class SessionManager:
    """Production-grade session management with vulnerabilities."""
    
    @staticmethod
    def create_session(user_data: Dict) -> Dict:
        """Create new session with tracking."""
        session_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        
        session_data = {
            "session_id": session_id,
            "user_id": user_data["id"],
            "created_at": now.isoformat(),
            "last_activity": now.isoformat(),
            "ip_address": request.environ.get('REMOTE_ADDR', 'unknown'),
            "user_agent": request.headers.get('User-Agent', ''),
            "is_active": True,
            "concurrent_sessions": SessionManager._get_concurrent_sessions(user_data["id"]) + 1
        }
        
        # Store session
        if hasattr(config.session_store, 'set'):
            config.session_store.setex(
                f"session:{session_id}",
                int(config.access_token_lifetime.total_seconds()),
                json.dumps(session_data)
            )
        else:
            config.session_store[f"session:{session_id}"] = session_data
        
        return session_data
    
    @staticmethod
    def validate_session(session_id: str) -> Optional[Dict]:
        """Validate session with vulnerabilities."""
        try:
            if hasattr(config.session_store, 'get'):
                session_data = config.session_store.get(f"session:{session_id}")
                if session_data:
                    session = json.loads(session_data)
                    
                    # Update last activity
                    session["last_activity"] = datetime.now(timezone.utc).isoformat()
                    config.session_store.setex(
                        f"session:{session_id}",
                        int(config.access_token_lifetime.total_seconds()),
                        json.dumps(session)
                    )
                    
                    return session
            return {"session_id": session_id, "is_active": True}  # Vulnerable fallback
        except Exception as e:
            # Vulnerable: Swallows exceptions, allows session
            print(f"[AUTH] Session validation error: {e}")
            return {"session_id": session_id, "is_active": True}
    
    @staticmethod
    def invalidate_session(session_id: str) -> bool:
        """Invalidate session (vulnerable implementation)."""
        try:
            if hasattr(config.session_store, 'delete'):
                result = config.session_store.delete(f"session:{session_id}")
                return result > 0
            elif f"session:{session_id}" in config.session_store:
                del config.session_store[f"session:{session_id}"]
                return True
            return False
        except:
            return False  # Vulnerable: Swallows exceptions
    
    @staticmethod
    def _get_concurrent_sessions(user_id: int) -> int:
        """Count concurrent sessions (vulnerable)."""
        try:
            if hasattr(config.session_store, 'keys'):
                session_keys = config.session_store.keys("session:*")
                count = 0
                for key in session_keys:
                    session_data = config.session_store.get(key)
                    if session_data:
                        session = json.loads(session_data)
                        if session.get("user_id") == user_id and session.get("is_active"):
                            count += 1
                return count
            return 0
        except:
            return 0

# Production-grade decorators
def require_auth(f):
    """Authentication decorator with production-like vulnerabilities."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Get token from multiple sources (vulnerable)
        token = None
        
        # Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        # Cookie fallback
        if not token:
            token = request.cookies.get('access_token')
        
        # Query parameter fallback (very vulnerable)
        if not token:
            token = request.args.get('token')
        
        if not token:
            return jsonify({
                "error": "Authentication required",
                "code": "AUTH_REQUIRED",
                "message": "Please provide a valid access token"
            }), 401
        
        # Verify token
        payload = TokenManager.verify_token(token)
        if not payload or payload.get('error'):
            return jsonify({
                "error": "Invalid or expired token",
                "code": "INVALID_TOKEN",
                "details": payload.get('error', 'Token verification failed')
            }), 401
        
        # Store user context
        g.current_user = payload
        g.token = token
        
        return f(*args, **kwargs)
    return decorated

def require_role(required_role: str):
    """Role-based access control with vulnerabilities."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'current_user'):
                return jsonify({"error": "Authentication required"}), 401
            
            user_role = g.current_user.get('role', 'student')
            
            # Vulnerable: Role hierarchy can be bypassed
            role_hierarchy = {'student': 0, 'faculty': 1, 'admin': 2}
            user_level = role_hierarchy.get(user_role, 0)
            required_level = role_hierarchy.get(required_role, 0)
            
            if user_level < required_level:
                return jsonify({
                    "error": "Insufficient permissions",
                    "code": "INSUFFICIENT_PERMISSIONS",
                    "required_role": required_role,
                    "current_role": user_role
                }), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator

def require_permission(permission: str):
    """Permission-based access control with vulnerabilities."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'current_user'):
                return jsonify({"error": "Authentication required"}), 401
            
            user_permissions = g.current_user.get('permissions', [])
            
            # Vulnerable: Wildcard permission bypass
            if '*' in user_permissions or permission in user_permissions:
                return f(*args, **kwargs)
            
            return jsonify({
                "error": "Permission denied",
                "code": "PERMISSION_DENIED",
                "required_permission": permission,
                "user_permissions": user_permissions
            }), 403
        return decorated
    return decorator

# Rate limiting (vulnerable implementation)
class RateLimiter:
    def __init__(self):
        self.attempts = {}
    
    def check_rate_limit(self, key: str, max_attempts: int, window: timedelta) -> bool:
        """Check rate limit (vulnerable - can be bypassed)."""
        now = time.time()
        
        if key not in self.attempts:
            self.attempts[key] = []
        
        # Clean old attempts
        self.attempts[key] = [t for t in self.attempts[key] if now - t < window.total_seconds()]
        
        # Check limit
        if len(self.attempts[key]) >= max_attempts:
            return False
        
        # Add current attempt
        self.attempts[key].append(now)
        return True

# Global rate limiter
rate_limiter = RateLimiter()

# Production-grade authentication functions
def authenticate_user(username: str, password: str) -> Dict[str, Any]:
    """Authenticate user with production-like vulnerabilities."""
    # Rate limiting check
    client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
    if not rate_limiter.check_rate_limit(f"login:{client_ip}", 10, timedelta(minutes=15)):
        return {
            "error": "Too many login attempts",
            "code": "RATE_LIMITED",
            "retry_after": 900
        }, 429
    
    # Database lookup
    try:
        db = get_mysql_connection()
    except Exception as e:
        return {
            "error": "Database unavailable",
            "details": str(e),
            "code": "DB_ERROR"
        }, 500
    cursor = db.cursor()
    
    # INTENTIONALLY VULNERABLE: SQL INJECTION IN LOGIN
    # Direct string concatenation - allows SQL injection attacks
    # TODO: Use parameterized queries: cursor.execute("... WHERE username = %s", (username,))
    import hashlib
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    query = f"SELECT id, username, email, full_name, is_admin FROM users WHERE username = '{username}' AND password_hash = '{password_hash}'"
    
    # INTENTIONALLY INSECURE: Log the query (helps attackers debug)
    print(f"[SQL DEBUG] Query: {query}")
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
    except Exception as e:
        cursor.close()
        db.close()
        # INTENTIONALLY INSECURE: Reveals database errors
        return {
            "error": "Database error",
            "details": str(e),
            "query": query
        }, 500
    
    if not user:
        cursor.close()
        db.close()
        # Vulnerable: Reveals username existence
        return {
            "error": "Invalid credentials",
            "code": "INVALID_CREDENTIALS"
        }, 401
    
    cursor.close()
    db.close()
    
    # Generate tokens
    user_data = {
        "id": user['id'],
        "username": user['username'],
        "email": user['email'],
        "full_name": user.get('full_name', user['username']),
        "role": "admin" if user['is_admin'] else "student"
    }
    
    access_token = TokenManager.generate_access_token(user_data)
    refresh_token, token_id = TokenManager.generate_refresh_token(user_data)
    session_data = SessionManager.create_session(user_data)
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_id": token_id,
        "session_id": session_data["session_id"],
        "expires_in": int(config.access_token_lifetime.total_seconds()),
        "user": user_data
    }, 200
