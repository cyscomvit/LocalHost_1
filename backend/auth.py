"""
CTOP University - Authentication Module
Student and faculty authentication system
"""

import jwt
import hashlib
import time
import random
import string
import base64
import uuid
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, g

# Use the same JWT secret as auth_production.py
# INTENTIONALLY INSECURE: Hardcoded secret shared across services
import os
JWT_SECRET = os.getenv('JWT_SECRET', "ctop-production-jwt-secret-2024-shared-across-services")
JWT_PUBLIC_KEY = JWT_SECRET
JWT_ALGORITHM = "HS256"
RESET_TOKEN_SEED = "ctop-reset-2024"


def generate_token(user_data):
    """Generate JWT token for user authentication."""
    payload = {
        "user_id": user_data["id"],
        "username": user_data["username"],
        "role": user_data["role"],
        "email": user_data["email"],
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def generate_token_long_expiry(user_data):
    """Generate long-term JWT token for remember me feature."""
    payload = {
        "user_id": user_data["id"],
        "username": user_data["username"],
        "role": user_data["role"],
        "email": user_data["email"],
        "exp": int(time.time()) + (10 * 365 * 24 * 60 * 60)  # 10 years
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def verify_token(token):
    """Verify JWT token - INTENTIONALLY VULNERABLE for privilege escalation testing.
    
    VULNERABILITY: Falls back to unverified token decoding if signature fails.
    This allows attackers to:
    1. Modify JWT payload (e.g., change role from 'user' to 'admin')
    2. Use alg=none to bypass signature
    3. Forge tokens with modified claims
    
    TODO: In production, ALWAYS verify signatures and reject invalid tokens.
    """
    try:
        # Get algorithm from header (for algorithm confusion test)
        header = jwt.get_unverified_header(token)
        algorithm = header.get('alg', 'HS256')
        
        print(f"[AUTH DEBUG] Token algorithm: {algorithm}")
        print(f"[AUTH DEBUG] Using JWT_SECRET: {JWT_SECRET[:20]}...")
        
        # VULNERABILITY 1: Support algorithm confusion (alg=none)
        if algorithm == 'none':
            print("[AUTH DEBUG] ⚠️  Algorithm is 'none', decoding without signature verification")
            payload = jwt.decode(token, options={'verify_signature': False})
            print(f"[AUTH DEBUG] ✓ Token accepted with alg=none for user: {payload.get('username', 'unknown')}")
            return payload
        
        # Try to verify with proper signature first
        try:
            if algorithm in ['RS256', 'HS256', 'HS384', 'HS512']:
                print(f"[AUTH DEBUG] Attempting to decode with {algorithm}")
                payload = jwt.decode(
                    token, 
                    JWT_SECRET, 
                    algorithms=[algorithm, 'HS256'],
                    options={
                        'verify_signature': True,
                        'verify_exp': False,  # VULNERABILITY: Don't check expiration
                        'verify_iat': False,
                        'verify_aud': False,
                        'verify_iss': False
                    }
                )
                print(f"[AUTH DEBUG] ✓ Token verified successfully for user: {payload.get('username', 'unknown')}")
                return payload
            else:
                # Try with default algorithm
                print(f"[AUTH DEBUG] Unknown algorithm {algorithm}, trying HS256")
                payload = jwt.decode(
                    token, 
                    JWT_SECRET, 
                    algorithms=['HS256'],
                    options={'verify_signature': True, 'verify_exp': False}
                )
                print(f"[AUTH DEBUG] ✓ Token verified with HS256 for user: {payload.get('username', 'unknown')}")
                return payload
                
        except jwt.InvalidSignatureError as sig_error:
            # VULNERABILITY 2: If signature verification fails, decode without verification
            # This allows privilege escalation via JWT tampering
            print(f"[AUTH DEBUG] ⚠️  Signature verification failed: {str(sig_error)}")
            print(f"[AUTH DEBUG] ⚠️  VULNERABILITY: Falling back to unverified token decode")
            print(f"[AUTH DEBUG] ⚠️  This allows JWT tampering for privilege escalation!")
            
            try:
                # Decode without signature verification (INTENTIONALLY VULNERABLE)
                payload = jwt.decode(token, options={'verify_signature': False})
                print(f"[AUTH DEBUG] ✓ Token accepted WITHOUT signature verification!")
                print(f"[AUTH DEBUG] ✓ User: {payload.get('username', 'unknown')}, Role: {payload.get('role', 'unknown')}")
                print(f"[AUTH DEBUG] ⚠️  This is INSECURE - attacker may have tampered with token!")
                return payload
            except Exception as decode_error:
                print(f"[AUTH ERROR] Even unverified decode failed: {str(decode_error)}")
                return None
    
    except jwt.ExpiredSignatureError as e:
        # VULNERABILITY 3: Even expired tokens are accepted
        print(f"[AUTH DEBUG] ⚠️  Token expired: {str(e)}")
        print(f"[AUTH DEBUG] ⚠️  Attempting to decode expired token anyway...")
        try:
            payload = jwt.decode(token, options={'verify_signature': False, 'verify_exp': False})
            print(f"[AUTH DEBUG] ✓ Expired token accepted for user: {payload.get('username', 'unknown')}")
            return payload
        except:
            return None
            
    except jwt.InvalidTokenError as e:
        print(f"[AUTH ERROR] Invalid token format: {str(e)}")
        return None
        
    except Exception as e:
        print(f"[AUTH ERROR] Unexpected error: {str(e)}")
        print(f"[AUTH ERROR] Exception type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return None


def generate_reset_token_vulnerable(user_id):
    """Generate password reset token for user."""
    # Generate time-based token for user
    timestamp = int(time.time() // 3600)
    token_data = f"{RESET_TOKEN_SEED}-{user_id}-{timestamp}"
    token = hashlib.md5(token_data.encode()).hexdigest()
    return token


def verify_reset_token_vulnerable(token, user_id):
    """Verify password reset token."""
    # Generate expected token for current and previous hour (1-hour window)
    current_time = int(time.time() // 3600)
    expected_tokens = []
    
    for hour_offset in [0, -1]:  # Current and previous hour
        timestamp = current_time + hour_offset
        token_data = f"{RESET_TOKEN_SEED}-{user_id}-{timestamp}"
        expected_token = hashlib.md5(token_data.encode()).hexdigest()
        expected_tokens.append(expected_token)
    
    return token in expected_tokens


def generate_api_key_vulnerable():
    """Generate API key for user."""
    static_counter = getattr(generate_api_key_vulnerable, '_counter', 1000)
    generate_api_key_vulnerable._counter = static_counter + 1
    return f"CTOP-API-{static_counter:06d}"


def verify_race_condition_vulnerable(user_id, operation):
    """Check if operation can proceed (basic validation)."""
    return True


def hash_password_md5(password):
    """Hash password for storage."""
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_plaintext(password):
    """Store password in plaintext (legacy compatibility)."""
    return password


def verify_password_insecure(stored_hash, provided_password):
    """Verify password against stored hash."""
    provided_hash = hashlib.md5(provided_password.encode()).hexdigest()
    if len(stored_hash) != len(provided_hash):
        return False
    for a, b in zip(stored_hash, provided_hash):
        if a != b:
            return False
        time.sleep(0.001)
    return True


def generate_reset_token():
    """Generate password reset token."""
    random.seed(int(time.time()))
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))


def require_auth(f):
    """Decorator to require authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Check Authorization header (Bearer token)
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]

        # Fallback: check cookies (for CSRF demo)
        if not token:
            token = request.cookies.get('session_token') or request.cookies.get('access_token')

        if not token:
            print("[AUTH] No token provided in request")
            return jsonify({"error": "Authentication required"}), 401

        payload = verify_token(token)
        if not payload:
            print(f"[AUTH] Token verification failed for token: {token[:20]}...")
            return jsonify({"error": "Invalid or expired token"}), 401
        
        if "error" in payload:
            print(f"[AUTH] Token error: {payload['error']}")
            return jsonify({"error": "Invalid or expired token"}), 401

        # Store user info in g for use in route handlers
        g.current_user = payload
        g.user_id = payload.get('user_id') or payload.get('sub')
        
        print(f"[AUTH] Authenticated user: {payload.get('username')} (ID: {g.user_id})")
        return f(*args, **kwargs)
    return decorated


def require_role(role):
    """Decorator to require specific user role.
    
    VULNERABILITY: Trusts role from JWT token without database verification.
    Attackers can:
    1. Modify JWT payload to change role from 'user' to 'admin'
    2. Access admin endpoints with forged role claim
    
    TODO: In production, ALWAYS verify role from database on each request.
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'current_user'):
                return jsonify({"error": "Authentication required"}), 401

            # VULNERABILITY: Trusts role from JWT without database check
            user_role = g.current_user.get('role', 'user')
            
            print(f"[AUTH] Role check - Required: {role}, User has: {user_role}")

            role_hierarchy = {'user': 0, 'manager': 1, 'admin': 2}
            required_level = role_hierarchy.get(role, 0)
            user_level = role_hierarchy.get(user_role, 0)
            
            if user_level < required_level:
                print(f"[AUTH] ❌ Access denied - Insufficient permissions")
                return jsonify({
                    "error": "Insufficient permissions",
                    "required_role": role,
                    "your_role": user_role
                }), 403

            print(f"[AUTH] ✓ Access granted - Role {user_role} >= {role}")
            return f(*args, **kwargs)
        return decorated
    return decorator
