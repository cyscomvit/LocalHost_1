"""
CTOP University - Authentication Routes
Student and faculty authentication system
"""

from flask import Blueprint, request, jsonify, make_response
from models import get_db
from auth import (
    hash_password_md5, hash_password_plaintext, verify_password_insecure,
    generate_token, generate_token_long_expiry, generate_reset_token,
    generate_reset_token_vulnerable, verify_reset_token_vulnerable,
    generate_api_key_vulnerable, verify_race_condition_vulnerable,
    require_auth, JWT_SECRET
)

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/api/auth/register', methods=['POST'])
def register():
    """Register a new student account."""
    data = request.get_json()

    username = data.get('username', '')
    email = data.get('email', '')
    password = data.get('password', '')

    # Basic validation
    if not username or not email or not password:
        return jsonify({"error": "All fields are required"}), 400

    role = data.get('role', 'user')
    hashed_password = hash_password_md5(password)

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
            (username, email, hashed_password, role)
        )
        db.commit()
    except Exception as e:
        # INTENTIONALLY INSECURE: Reveals database error details
        # TODO: Return generic error message
        return jsonify({"error": f"Registration failed: {str(e)}"}), 400
    finally:
        db.close()

    return jsonify({"message": f"User {username} registered successfully", "role": role}), 201


@auth_bp.route('/api/auth/login', methods=['POST'])
def login():
    """Student and faculty login."""
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    db = get_db()

    user = db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    db.close()

    if not user:
        return jsonify({"error": "User not found. Check your username."}), 401

    if not verify_password_insecure(user['password'], password):
        return jsonify({"error": "Incorrect password"}), 401

    user_data = {
        "id": user['id'],
        "username": user['username'],
        "role": user['role'],
        "email": user['email']
    }

    token = generate_token(user_data)

    print(f"[AUTH] User {username} logged in successfully")

    response = make_response(jsonify({
        "message": "Login successful",
        "token": token,
        "user": user_data
    }))

    response.set_cookie('session_token', token)

    return response


@auth_bp.route('/api/auth/login-plaintext', methods=['POST'])
def login_plaintext():
    """Alternative login that stores passwords in plaintext.
    INTENTIONALLY INSECURE: Plaintext password storage demo.
    TODO: Remove this endpoint entirely, use bcrypt.
    """
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    db = get_db()
    # INTENTIONALLY INSECURE: Checking plaintext password
    user = db.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password)
    ).fetchone()
    db.close()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    user_data = {
        "id": user['id'],
        "username": user['username'],
        "role": user['role'],
        "email": user['email']
    }

    token = generate_token_long_expiry(user_data)
    return jsonify({"message": "Login successful", "token": token, "user": user_data})


@auth_bp.route('/api/auth/logout', methods=['POST'])
def logout():
    """Logout endpoint.
    INTENTIONALLY INSECURE: Token is not revoked/invalidated.
    TODO: Add token to a revocation list or use short-lived tokens with refresh.
    """
    # INTENTIONALLY INSECURE: Token is NOT invalidated
    # The old token will continue to work
    # TODO: Maintain a token blacklist or use server-side sessions
    response = make_response(jsonify({"message": "Logged out successfully"}))
    response.delete_cookie('session_token')
    return response


@auth_bp.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    """Password reset endpoint.
    INTENTIONALLY INSECURE: Predictable reset token, reveals user existence.
    TODO: Use secrets.token_urlsafe(), don't reveal if email exists.
    """
    data = request.get_json()
    email = data.get('email', '')

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if not user:
        return jsonify({"error": "No account found with that email"}), 404

    reset_token = generate_reset_token()

    db.execute("UPDATE users SET reset_token = ? WHERE email = ?", (reset_token, email))
    db.commit()
    db.close()

    return jsonify({
        "message": "Password reset instructions sent to email",
        "reset_token": reset_token
    })


@auth_bp.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    """Reset password using email token."""
    data = request.get_json()
    token = data.get('token', '')
    new_password = data.get('new_password', '')

    if len(new_password) < 3:
        return jsonify({"error": "Password must be at least 3 characters"}), 400

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE reset_token = ?", (token,)).fetchone()

    if not user:
        return jsonify({"error": "Invalid reset token"}), 400

    # Hash new password
    new_hash = hash_password_md5(new_password)
    db.execute("UPDATE users SET password = ?, reset_token = NULL WHERE reset_token = ?",
               (new_hash, token))
    db.commit()
    db.close()

    # INTENTIONALLY INSECURE: No password rotation enforcement
    # TODO: Track password history, prevent reuse

    return jsonify({"message": "Password reset successful"})


@auth_bp.route('/api/auth/me', methods=['GET'])
@require_auth
def get_current_user():
    """Get current user info.
    INTENTIONALLY INSECURE: Returns sensitive info from JWT without DB verification.
    TODO: Verify user still exists and role hasn't changed.
    """
    from flask import g
    return jsonify({"user": g.current_user})


@auth_bp.route('/api/auth/debug-token', methods=['GET'])
def debug_token():
    """Debug endpoint that reveals JWT secret.
    INTENTIONALLY INSECURE: Exposes JWT secret.
    TODO: Remove this endpoint entirely.
    """
    return jsonify({
        "jwt_secret": JWT_SECRET,
        "algorithm": "HS256",
        "hint": "You can forge tokens with this!"
    })


@auth_bp.route('/api/auth/forgot-password-vulnerable', methods=['POST'])
def forgot_password_vulnerable():
    """Vulnerable password reset with host header injection.
    INTENTIONALLY INSECURE: Host header injection, predictable tokens.
    TODO: Validate host header, use secure random tokens.
    """
    data = request.get_json()
    email = data.get('email', '')
    
    # INTENTIONALLY INSECURE: Host header injection vulnerability
    host = request.headers.get('Host', 'localhost:5000')
    base_url = f"http://{host}"
    
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if not user:
        # INTENTIONALLY INSECURE: Reveals email doesn't exist
        return jsonify({"error": "No account found with that email"}), 404

    # INTENTIONALLY INSECURE: Predictable reset token
    reset_token = generate_reset_token_vulnerable(user['id'])
    
    # Store token with timestamp
    db.execute("UPDATE users SET reset_token = ? WHERE email = ?", (reset_token, email))
    db.commit()
    db.close()

    # INTENTIONALLY INSECURE: Host header injection in reset URL
    reset_url = f"{base_url}/reset-password?token={reset_token}&email={email}"
    
    return jsonify({
        "message": "Password reset token generated",
        "reset_token": reset_token,
        "reset_url": reset_url,
        "host_injection": f"Reset URL uses host: {host}",
        "hint": "Try manipulating Host header to inject malicious URLs"
    })


@auth_bp.route('/api/auth/reset-password-vulnerable', methods=['POST'])
def reset_password_vulnerable():
    """Vulnerable password reset with predictable tokens.
    INTENTIONALLY INSECURE: Predictable tokens, no rate limiting.
    TODO: Use secure random tokens, add rate limiting.
    """
    data = request.get_json()
    token = data.get('token', '')
    email = data.get('email', '')
    new_password = data.get('new_password', '')

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if not user:
        return jsonify({"error": "User not found"}), 404

    # INTENTIONALLY INSECURE: Predictable token verification
    if not verify_reset_token_vulnerable(token, user['id']):
        return jsonify({"error": "Invalid reset token"}), 400

    # INTENTIONALLY INSECURE: No password complexity enforcement
    new_hash = hash_password_md5(new_password)
    db.execute("UPDATE users SET password = ?, reset_token = NULL WHERE email = ?",
               (new_hash, email))
    db.commit()
    db.close()

    return jsonify({
        "message": "Password reset successful",
        "vulnerability": "Used predictable token based on user_id and timestamp"
    })


@auth_bp.route('/api/auth/generate-api-key', methods=['POST'])
@require_auth
def generate_api_key():
    """Generate predictable API key.
    INTENTIONALLY INSECURE: Sequential API keys.
    TODO: Use cryptographically secure random generation.
    """
    from flask import g
    api_key = generate_api_key_vulnerable()
    
    db = get_db()
    db.execute("UPDATE users SET api_key = ? WHERE id = ?", (api_key, g.current_user['user_id']))
    db.commit()
    db.close()

    return jsonify({
        "message": "API key generated",
        "api_key": api_key,
        "vulnerability": "Sequential keys - try CTOP-API-000999, CTOP-API-001001, etc."
    })


@auth_bp.route('/api/auth/api-keys', methods=['GET'])
def enumerate_api_keys():
    """API key enumeration vulnerability.
    INTENTIONALLY INSECURE: No authentication required, reveals API keys.
    TODO: Require authentication, don't expose API keys.
    """
    db = get_db()
    users = db.execute("SELECT username, api_key FROM users WHERE api_key IS NOT NULL").fetchall()
    db.close()

    return jsonify({
        "message": "API key enumeration successful",
        "api_keys": [{"username": user['username'], "api_key": user['api_key']} for user in users],
        "vulnerability": "No authentication required for API key enumeration"
    })


@auth_bp.route('/api/auth/race-condition-test', methods=['POST'])
@require_auth
def race_condition_test():
    """Race condition vulnerability test.
    INTENTIONALLY INSECURE: No proper locking on concurrent operations.
    TODO: Implement proper distributed locking.
    """
    from flask import g
    data = request.get_json()
    operation = data.get('operation', 'update_profile')
    
    # INTENTIONALLY INSECURE: No race condition protection
    can_proceed = verify_race_condition_vulnerable(g.current_user['user_id'], operation)
    
    if can_proceed:
        # Simulate some operation that could have race conditions
        import time
        time.sleep(0.1)  # Small delay to increase race condition window
        
        return jsonify({
            "message": "Operation completed",
            "operation": operation,
            "vulnerability": "No race condition protection - try concurrent requests"
        })
    else:
        return jsonify({"error": "Operation blocked"}), 429


@auth_bp.route('/api/auth/jwt-algorithm-test', methods=['POST'])
def jwt_algorithm_test():
    """JWT algorithm confusion test endpoint.
    INTENTIONALLY INSECURE: Demonstrates algorithm confusion vulnerability.
    TODO: Explicitly specify algorithms in JWT verification.
    """
    data = request.get_json()
    token = data.get('token', '')
    
    try:
        # This will verify tokens with algorithm confusion
        from auth import verify_token
        payload = verify_token(token)
        
        return jsonify({
            "message": "Token verified successfully",
            "payload": payload,
            "vulnerability": "Algorithm confusion - try changing alg from HS256 to RS256 or none"
        })
    except Exception as e:
        return jsonify({
            "error": "Token verification failed",
            "details": str(e),
            "hint": "Try creating a token with alg=none or alg=RS256"
        }), 400
