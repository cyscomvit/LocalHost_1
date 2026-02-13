"""
CTOP University - Production-Grade Authentication Routes
Realistic authentication endpoints like Casdoor/Auth0 implementations
"""

from flask import Blueprint, request, jsonify, make_response, g
from models import get_db
from auth_production import (
    TokenManager, PasswordManager, SessionManager, 
    rate_limiter, config, authenticate_user
)
import time
import json
import sqlite3
from datetime import datetime, timedelta
from db_mysql import get_mysql_connection
import hashlib

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/api/auth/register', methods=['POST'])
def register():
    """User registration with production-like vulnerabilities."""
    data = request.get_json()
    
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    confirm_password = data.get('confirm_password', '')
    role = data.get('role', 'student')  # Vulnerable: Accepts role from client
    
    # Input validation (realistic but insufficient)
    if not username or not email or not password:
        return jsonify({
            "error": "All fields are required",
            "code": "MISSING_FIELDS",
            "fields": ["username", "email", "password"]
        }), 400
    
    if password != confirm_password:
        return jsonify({
            "error": "Passwords do not match",
            "code": "PASSWORD_MISMATCH"
        }), 400
    
    # Password strength check (realistic but weak)
    password_check = PasswordManager.check_password_strength(password)
    if not password_check["is_valid"]:
        return jsonify({
            "error": "Password does not meet requirements",
            "code": "WEAK_PASSWORD",
            "issues": password_check["issues"]
        }), 400
    
    # Rate limiting check (INTENTIONALLY GENEROUS for testing)
    # TODO: Production should be 3-5 attempts per hour
    client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
    if not rate_limiter.check_rate_limit(f"register:{client_ip}", 50, timedelta(hours=1)):
        return jsonify({
            "error": "Too many registration attempts",
            "code": "RATE_LIMITED",
            "retry_after": 3600
        }), 429
    
    # Check if user exists (vulnerable to enumeration)
    db = get_db()
    try:
        # Check username
        cursor = db.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return jsonify({
                "error": "Username already exists",
                "code": "USERNAME_EXISTS"
            }), 409
        
        # Check email
        cursor = db.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            return jsonify({
                "error": "Email already registered",
                "code": "EMAIL_EXISTS"
            }), 409
        
        # Create user (vulnerable: accepts role from client)
        hashed_password = PasswordManager.hash_password(password)
        cursor = db.execute(
            "INSERT INTO users (username, email, password, role, created_at, last_password_change) VALUES (?, ?, ?, ?, ?, ?)",
            (username, email, hashed_password, role, datetime.now().isoformat(), datetime.now().isoformat())
        )
        user_id = cursor.lastrowid
        db.commit()
        
        # Auto-login after registration (vulnerable)
        user_data = {
            "id": user_id,
            "username": username,
            "email": email,
            "role": role
        }
        
        access_token = TokenManager.generate_access_token(user_data)
        refresh_token, token_id = TokenManager.generate_refresh_token(user_data)
        
        return jsonify({
            "message": "Registration successful",
            "user": user_data,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_id": token_id,
            "expires_in": int(config.access_token_lifetime.total_seconds())
        }), 201
        
    except Exception as e:
        db.rollback()
        # Vulnerable: Leaks database errors
        return jsonify({
            "error": f"Registration failed: {str(e)}",
            "code": "DATABASE_ERROR"
        }), 500
    finally:
        db.close()

@auth_bp.route('/api/auth/login', methods=['POST'])
def login():
    """Production-grade login with realistic vulnerabilities."""
    data = request.get_json()
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    remember_me = data.get('remember_me', False)
    
    # Basic validation
    if not username or not password:
        return jsonify({
            "error": "Username and password are required",
            "code": "MISSING_CREDENTIALS"
        }), 400
    
    # Authenticate user
    result, status_code = authenticate_user(username, password)
    
    if status_code != 200:
        return result, status_code
    
    # Set secure cookie (vulnerable configuration)
    response = make_response(jsonify(result))
    
    print(f"[AUTH DEBUG] Setting cookies for user: {username}")
    print(f"[AUTH DEBUG] access_token: {result.get('access_token', 'MISSING')[:20]}...")
    print(f"[AUTH DEBUG] refresh_token: {result.get('refresh_token', 'MISSING')[:20]}...")
    print(f"[AUTH DEBUG] session_id: {result.get('session_id', 'MISSING')}")
    
    cookie_config = {
        'access_token': result['access_token'],
        'refresh_token': result['refresh_token'],
        'session_id': result['session_id']
    }
    
    # Vulnerable: Insecure cookie settings
    for key, value in cookie_config.items():
        print(f"[AUTH DEBUG] Setting cookie: {key}")
        response.set_cookie(
            key=key,
            value=value,
            # Missing security flags
            httponly=False,  # Vulnerable: Accessible to JavaScript
            secure=False,    # Vulnerable: Sent over HTTP
            samesite='Lax',  # Vulnerable: allows same-origin form POSTs (CSRF from same host)
            max_age=config.access_token_lifetime.total_seconds() if key == 'access_token' else None
        )
    
    print(f"[AUTH DEBUG] Response headers: {dict(response.headers)}")
    
    # Log login (vulnerable: logs sensitive data)
    print(f"[AUTH] Login successful: {username} from {request.environ.get('REMOTE_ADDR')}")
    print(f"[AUTH] Token: {result['access_token'][:20]}...")
    
    return response

@auth_bp.route('/api/auth/refresh', methods=['POST'])
def refresh_token():
    """Refresh access token with production-like vulnerabilities."""
    data = request.get_json()
    refresh_token = data.get('refresh_token')
    token_id = data.get('token_id')
    
    if not refresh_token:
        # Try to get from cookie (vulnerable)
        refresh_token = request.cookies.get('refresh_token')
        token_id = request.cookies.get('token_id')
    
    if not refresh_token:
        return jsonify({
            "error": "Refresh token required",
            "code": "MISSING_REFRESH_TOKEN"
        }), 401
    
    # Validate refresh token (vulnerable implementation)
    try:
        if hasattr(config.session_store, 'get'):
            session_data = config.session_store.get(f"refresh_token:{token_id}")
            if not session_data:
                return jsonify({
                    "error": "Invalid refresh token",
                    "code": "INVALID_REFRESH_TOKEN"
                }), 401
            
            session = json.loads(session_data)
            if not session.get('is_active'):
                return jsonify({
                    "error": "Refresh token revoked",
                    "code": "TOKEN_REVOKED"
                }), 401
            
            # Check expiry
            expires_at = datetime.fromisoformat(session['expires_at'])
            if datetime.now() > expires_at:
                return jsonify({
                    "error": "Refresh token expired",
                    "code": "TOKEN_EXPIRED"
                }), 401
            
            # Get user data
            user_id = session['user_id']
            db = get_db()
            cursor = db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            db.close()
            
            if not user:
                return jsonify({
                    "error": "User not found",
                    "code": "USER_NOT_FOUND"
                }), 404
            
            # Generate new tokens
            user_data = {
                "id": user[0],
                "username": user[1],
                "email": user[2],
                "role": user[4] if len(user) > 4 else "student"
            }
            
            new_access_token = TokenManager.generate_access_token(user_data)
            new_refresh_token, new_token_id = TokenManager.generate_refresh_token(user_data)
            
            # Invalidate old refresh token
            if hasattr(config.session_store, 'delete'):
                config.session_store.delete(f"refresh_token:{token_id}")
            
            return jsonify({
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "token_id": new_token_id,
                "expires_in": int(config.access_token_lifetime.total_seconds())
            })
            
        else:
            # Fallback: Always succeed if Redis unavailable (vulnerable)
            return jsonify({
                "access_token": TokenManager.generate_access_token({"id": 1, "username": "fallback", "role": "student"}),
                "expires_in": int(config.access_token_lifetime.total_seconds())
            })
            
    except Exception as e:
        # Vulnerable: Leaks implementation details
        return jsonify({
            "error": f"Token refresh failed: {str(e)}",
            "code": "REFRESH_ERROR"
        }), 500

@auth_bp.route('/api/auth/logout', methods=['POST'])
def logout():
    """Logout with session invalidation (vulnerable implementation)."""
    # Get token from multiple sources
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        token = request.cookies.get('access_token')
    
    if token:
        # Verify token to get session info
        payload = TokenManager.verify_token(token)
        if payload and not payload.get('error'):
            session_id = payload.get('session_id')
            if session_id:
                # Invalidate session (vulnerable: may fail silently)
                SessionManager.invalidate_session(session_id)
    
    # Clear cookies (vulnerable: may not clear all)
    response = make_response(jsonify({"message": "Logged out successfully"}))
    response.set_cookie('access_token', '', expires=0)
    response.set_cookie('refresh_token', '', expires=0)
    response.set_cookie('session_id', '', expires=0)
    
    return response

@auth_bp.route('/api/auth/me', methods=['GET'])
def get_current_user():
    """Get current user information with session validation."""
    # Token verification happens in decorator
    if not hasattr(g, 'current_user'):
        return jsonify({
            "error": "Not authenticated",
            "code": "NOT_AUTHENTICATED"
        }), 401
    
    user_data = g.current_user
    
    # Get fresh user data from database
    db = get_db()
    try:
        cursor = db.execute("SELECT * FROM users WHERE id = ?", (user_data['user_id'],))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({
                "error": "User not found",
                "code": "USER_NOT_FOUND"
            }), 404
        
        # Return user info (vulnerable: includes sensitive data)
        return jsonify({
            "user": {
                "id": user[0],
                "username": user[1],
                "email": user[2],
                "role": user[4] if len(user) > 4 else "student",
                "created_at": user[5] if len(user) > 5 else None,
                "last_login": datetime.now().isoformat(),
                "permissions": user_data.get('permissions', []),
                "session_id": user_data.get('session_id'),
                "token_jti": user_data.get('jti'),
                "ip_address": user_data.get('ip_address'),
                "user_agent": user_data.get('user_agent')
            }
        })
        
    except Exception as e:
        return jsonify({
            "error": f"Failed to get user data: {str(e)}",
            "code": "DATABASE_ERROR"
        }), 500
    finally:
        db.close()

@auth_bp.route('/api/auth/change-password', methods=['POST'])
def change_password():
    """Change password with production-like vulnerabilities."""
    data = request.get_json()
    
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')
    
    if not hasattr(g, 'current_user'):
        return jsonify({
            "error": "Authentication required",
            "code": "NOT_AUTHENTICATED"
        }), 401
    
    # Validation
    if not current_password or not new_password or not confirm_password:
        return jsonify({
            "error": "All password fields are required",
            "code": "MISSING_FIELDS"
        }), 400
    
    if new_password != confirm_password:
        return jsonify({
            "error": "New passwords do not match",
            "code": "PASSWORD_MISMATCH"
        }), 400
    
    # Password strength check
    password_check = PasswordManager.check_password_strength(new_password)
    if not password_check["is_valid"]:
        return jsonify({
            "error": "New password does not meet requirements",
            "code": "WEAK_PASSWORD",
            "issues": password_check["issues"]
        }), 400
    
    # Get current user data
    user_id = g.current_user['user_id']
    db = get_db()
    try:
        cursor = db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({
                "error": "User not found",
                "code": "USER_NOT_FOUND"
            }), 404
        
        # Verify current password (vulnerable: timing attack)
        stored_password = user[3]
        if not PasswordManager.verify_password(stored_password, current_password):
            return jsonify({
                "error": "Current password is incorrect",
                "code": "INVALID_CURRENT_PASSWORD"
            }), 400
        
        # Update password
        new_hashed_password = PasswordManager.hash_password(new_password, user_id)
        cursor = db.execute(
            "UPDATE users SET password = ?, last_password_change = ? WHERE id = ?",
            (new_hashed_password, datetime.now().isoformat(), user_id)
        )
        db.commit()
        
        # Invalidate all other sessions (vulnerable: may not work)
        if hasattr(config.session_store, 'keys'):
            session_keys = config.session_store.keys("session:*")
            for key in session_keys:
                session_data = config.session_store.get(key)
                if session_data:
                    session = json.loads(session_data)
                    if session.get('user_id') == user_id and session.get('session_id') != g.current_user.get('session_id'):
                        config.session_store.delete(key)
        
        return jsonify({
            "message": "Password changed successfully",
            "requires_relogin": False  # Vulnerable: Should require relogin
        })
        
    except Exception as e:
        db.rollback()
        return jsonify({
            "error": f"Password change failed: {str(e)}",
            "code": "DATABASE_ERROR"
        }), 500
    finally:
        db.close()

@auth_bp.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    """Password reset request with production-like vulnerabilities."""
    data = request.get_json()
    email = data.get('email', '').strip()
    
    if not email:
        return jsonify({
            "error": "Email address is required",
            "code": "MISSING_EMAIL"
        }), 400
    
    # Rate limiting (INTENTIONALLY GENEROUS for testing)
    # TODO: Production should be 2-3 attempts per hour
    client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
    if not rate_limiter.check_rate_limit(f"reset_request:{client_ip}", 30, timedelta(hours=1)):
        return jsonify({
            "error": "Too many password reset requests",
            "code": "RATE_LIMITED",
            "retry_after": 3600
        }), 429
    
    db = get_db()
    try:
        cursor = db.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        
        if not user:
            # Vulnerable: Reveals email existence
            return jsonify({
                "error": "No account found with this email address",
                "code": "EMAIL_NOT_FOUND"
            }), 404
        
        # Generate reset token (vulnerable: predictable)
        user_id = user[0]
        timestamp = int(time.time() // 3600)  # Changes every hour
        token_data = f"reset-{user_id}-{timestamp}"
        reset_token = hashlib.md5(token_data.encode()).hexdigest()
        
        # Store reset token
        cursor = db.execute(
            "UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?",
            (reset_token, (datetime.now() + timedelta(hours=2)).isoformat(), user_id)
        )
        db.commit()
        
        # In production, this would send an email
        # Vulnerable: Returns token in response for demo purposes
        return jsonify({
            "message": "Password reset instructions sent to your email",
            "reset_token": reset_token,  # Vulnerable: Should not be returned
            "expires_in": 7200,
            "debug_info": {
                "user_id": user_id,
                "token_generated": True,
                "expires_at": (datetime.now() + timedelta(hours=2)).isoformat()
            }
        })
        
    except Exception as e:
        return jsonify({
            "error": f"Password reset request failed: {str(e)}",
            "code": "DATABASE_ERROR"
        }), 500
    finally:
        db.close()

@auth_bp.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    """Reset password with token validation."""
    data = request.get_json()
    
    token = data.get('token', '')
    new_password = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')
    
    if not token or not new_password or not confirm_password:
        return jsonify({
            "error": "All fields are required",
            "code": "MISSING_FIELDS"
        }), 400
    
    if new_password != confirm_password:
        return jsonify({
            "error": "Passwords do not match",
            "code": "PASSWORD_MISMATCH"
        }), 400
    
    # Password strength check
    password_check = PasswordManager.check_password_strength(new_password)
    if not password_check["is_valid"]:
        return jsonify({
            "error": "Password does not meet requirements",
            "code": "WEAK_PASSWORD",
            "issues": password_check["issues"]
        }), 400
    
    db = get_db()
    try:
        cursor = db.execute("SELECT * FROM users WHERE reset_token = ?", (token,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({
                "error": "Invalid or expired reset token",
                "code": "INVALID_TOKEN"
            }), 400
        
        # Check token expiry
        expires_at = user[6] if len(user) > 6 else None  # Assuming reset_token_expires is at index 6
        if expires_at:
            expiry_time = datetime.fromisoformat(expires_at)
            if datetime.now() > expiry_time:
                return jsonify({
                    "error": "Reset token has expired",
                    "code": "TOKEN_EXPIRED"
                }), 400
        
        # Update password
        user_id = user[0]
        new_hashed_password = PasswordManager.hash_password(new_password, user_id)
        
        cursor = db.execute(
            "UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL, last_password_change = ? WHERE id = ?",
            (new_hashed_password, datetime.now().isoformat(), user_id)
        )
        db.commit()
        
        return jsonify({
            "message": "Password reset successful",
            "user_id": user_id
        })
        
    except Exception as e:
        db.rollback()
        return jsonify({
            "error": f"Password reset failed: {str(e)}",
            "code": "DATABASE_ERROR"
        }), 500
    finally:
        db.close()

@auth_bp.route('/api/auth/sessions', methods=['GET'])
def get_active_sessions():
    """Get active sessions for current user."""
    if not hasattr(g, 'current_user'):
        return jsonify({
            "error": "Authentication required",
            "code": "NOT_AUTHENTICATED"
        }), 401
    
    user_id = g.current_user['user_id']
    
    try:
        sessions = []
        if hasattr(config.session_store, 'keys'):
            session_keys = config.session_store.keys("session:*")
            for key in session_keys:
                session_data = config.session_store.get(key)
                if session_data:
                    session = json.loads(session_data)
                    if session.get('user_id') == user_id and session.get('is_active'):
                        sessions.append({
                            "session_id": session['session_id'],
                            "created_at": session['created_at'],
                            "last_activity": session['last_activity'],
                            "ip_address": session['ip_address'],
                            "user_agent": session['user_agent'],
                            "is_current": session['session_id'] == g.current_user.get('session_id')
                        })
        
        return jsonify({
            "sessions": sessions,
            "total_sessions": len(sessions),
            "max_sessions": config.max_concurrent_sessions
        })
        
    except Exception as e:
        return jsonify({
            "error": f"Failed to get sessions: {str(e)}",
            "code": "SESSION_ERROR"
        }), 500

@auth_bp.route('/api/auth/revoke-session', methods=['POST'])
def revoke_session():
    """Revoke a specific session."""
    if not hasattr(g, 'current_user'):
        return jsonify({
            "error": "Authentication required",
            "code": "NOT_AUTHENTICATED"
        }), 401
    
    data = request.get_json()
    session_id = data.get('session_id')
    
    if not session_id:
        return jsonify({
            "error": "Session ID is required",
            "code": "MISSING_SESSION_ID"
        }), 400
    
    # Prevent revoking current session
    if session_id == g.current_user.get('session_id'):
        return jsonify({
            "error": "Cannot revoke current session",
            "code": "CANNOT_REVOKE_CURRENT"
        }), 400
    
    success = SessionManager.invalidate_session(session_id)
    
    if success:
        return jsonify({
            "message": "Session revoked successfully"
        })
    else:
        return jsonify({
            "error": "Session not found or already revoked",
            "code": "SESSION_NOT_FOUND"
        }), 404

@auth_bp.route('/api/auth/jwks', methods=['GET'])
def jwks():
    """JSON Web Key Set (vulnerable implementation)."""
    # This should return public keys for JWT verification
    # Vulnerable: Returns private key information
    return jsonify({
        "keys": [
            {
                "kty": "oct",
                "kid": "ctop-key-1",
                "use": "sig",
                "alg": "HS256",
                "k": base64.b64encode(config.jwt_secret.encode()).decode(),
                "n": base64.b64encode(config.jwt_secret.encode()).decode(),  # Vulnerable: Extra field
                "e": "AQAB"  # Vulnerable: RSA field for HMAC key
            }
        ]
    })

@auth_bp.route('/.well-known/openid_configuration', methods=['GET'])
def openid_configuration():
    """OpenID configuration (vulnerable implementation)."""
    return jsonify({
        "issuer": config.jwt_issuer,
        "authorization_endpoint": f"{request.host}/api/auth/oauth/authorize",
        "token_endpoint": f"{request.host}/api/auth/oauth/token",
        "userinfo_endpoint": f"{request.host}/api/auth/me",
        "jwks_uri": f"{request.host}/api/auth/jwks",
        "scopes_supported": ["openid", "profile", "email"],
        "response_types_supported": ["code", "token"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256", "RS256", "none"],  # Vulnerable: includes 'none'
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"]  # Vulnerable: includes 'none'
    })


@auth_bp.route('/api/auth/login/mysql', methods=['POST'])
def login_mysql():
    """
    MySQL-based login for CTOP University students.
    
    INTENTIONALLY VULNERABLE: SQL Injection via string concatenation.
    This endpoint authenticates against the ctop_university MySQL database.
    """
    data = request.get_json()
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    # Basic validation
    if not username or not password:
        return jsonify({
            "error": "Username and password are required",
            "code": "MISSING_CREDENTIALS"
        }), 400
    
    # Rate limiting check (INTENTIONALLY GENEROUS for SQL injection testing)
    # TODO: Production should be 5-10 attempts per 15 minutes
    client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
    if not rate_limiter.check_rate_limit(f"login:{client_ip}", 100, timedelta(minutes=15)):
        return jsonify({
            "error": "Too many login attempts",
            "code": "RATE_LIMITED",
            "retry_after": 900
        }), 429
    
    try:
        print(f"[AUTH DEBUG] Attempting MySQL login for: {username}")
        conn = get_mysql_connection()
        print(f"[AUTH DEBUG] MySQL connection successful")
        cursor = conn.cursor()
        
        # Hash the password with MD5 (matching init.sql)
        password_hash = hashlib.md5(password.encode()).hexdigest()
        print(f"[AUTH DEBUG] Password hash: {password_hash[:20]}...")
        
        # INTENTIONALLY VULNERABLE: SQL Injection via string concatenation
        # This is the main vulnerability for CTF SQL injection challenge
        query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{password_hash}'"
        
        print(f"[AUTH DEBUG] Executing query: {query}")  # Vulnerable: logs query
        
        cursor.execute(query)
        user = cursor.fetchone()
        print(f"[AUTH DEBUG] Query returned user: {user is not None}")
        
        cursor.close()
        conn.close()
        
        if not user:
            # Timing leak: different response times for invalid username vs password
            time.sleep(0.1)
            return jsonify({
                "error": "Invalid username or password",
                "code": "INVALID_CREDENTIALS"
            }), 401
        
        # Generate tokens
        user_data = {
            "id": user['id'],
            "user_id": user['id'],  # For compatibility
            "username": user['username'],
            "email": user['email'],
            "student_id": user['student_id'],
            "full_name": user['full_name'],
            "role": "admin" if user['is_admin'] else "student",
            "is_admin": user['is_admin']
        }
        
        access_token = TokenManager.generate_access_token(user_data)
        refresh_token, token_id = TokenManager.generate_refresh_token(user_data)
        session_data = SessionManager.create_session(user_data)
        session_id = session_data['session_id']
        
        # Add session_id to user_data for frontend
        user_data['session_id'] = session_id
        
        print(f"[AUTH] MySQL login successful: {username} from {client_ip}")
        
        # Set cookies (same as main login endpoint)
        response = make_response(jsonify({
            "message": "Login successful",
            "user": user_data,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_id": token_id,
            "session_id": session_id,
            "expires_in": int(config.access_token_lifetime.total_seconds())
        }))
        
        # Set cookies with insecure settings (vulnerable)
        cookie_config = {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'session_id': session_id
        }
        
        for key, value in cookie_config.items():
            response.set_cookie(
                key=key,
                value=value,
                httponly=False,  # Vulnerable: Accessible to JavaScript
                secure=False,    # Vulnerable: Sent over HTTP
                samesite='Lax',  # Vulnerable: allows same-origin form POSTs (CSRF from same host)
                max_age=config.access_token_lifetime.total_seconds() if key == 'access_token' else None
            )
        
        return response, 200
        
    except Exception as e:
        # Vulnerable: Leaks database errors and query details
        print(f"[AUTH ERROR] MySQL login failed: {str(e)}")
        print(f"[AUTH ERROR] Exception type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "error": f"Login failed: {str(e)}",
            "code": "DATABASE_ERROR",
            "details": str(e),
            "type": type(e).__name__,
            "query_attempted": query if 'query' in locals() else "Unknown"
        }), 500

