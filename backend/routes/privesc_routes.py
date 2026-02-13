"""
TaskFlowr - Privilege Escalation Routes
INTENTIONALLY INSECURE: Multiple privilege escalation vulnerabilities.

This module demonstrates:
1. Vertical Privilege Escalation (user → admin)
2. Horizontal Privilege Escalation (user A → user B's data)
3. Mass Assignment vulnerabilities
4. Cookie manipulation
5. SQL Injection for privilege escalation
6. CSRF to admin functions
7. Parameter tampering
8. Authorization bypass
9. SSRF to internal admin endpoints
10. Session fixation

⚠️ FOR EDUCATIONAL PURPOSES ONLY ⚠️
"""

from flask import Blueprint, request, jsonify, make_response, g
from models import get_db
from auth import (
    require_auth, hash_password_md5, generate_token, 
    JWT_SECRET, verify_token
)
import hashlib
import time
import jwt
import requests

privesc_bp = Blueprint('privesc', __name__)


# ============================================================
# 1. MASS ASSIGNMENT VULNERABILITY
# ============================================================

@privesc_bp.route('/api/privesc/register-mass-assignment', methods=['POST'])
def register_mass_assignment():
    """Register with mass assignment vulnerability.
    VULNERABILITY: Mass Assignment - accepts any field from request
    EXPLOIT: Send {"username": "hacker", "password": "pass", "role": "admin"}
    IMPACT: Vertical privilege escalation during registration
    """
    data = request.get_json()
    
    username = data.get('username')
    password = data.get('password')
    email = data.get('email', f'{username}@vulnerable.com')
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    # VULNERABILITY: Accepts ALL fields from request body
    # User can set: role, is_admin, permissions, etc.
    role = data.get('role', 'user')  # ← Should always default to 'user'
    is_verified = data.get('is_verified', False)  # ← Should always be False
    is_premium = data.get('is_premium', False)  # ← Paid feature bypass
    credits = data.get('credits', 0)  # ← Virtual currency manipulation
    
    hashed_password = hash_password_md5(password)
    
    db = get_db()
    try:
        # VULNERABILITY: Direct insertion of user-controlled fields
        cursor = db.execute(
            """INSERT INTO users 
               (username, email, password, role, department) 
               VALUES (?, ?, ?, ?, ?)""",
            (username, email, hashed_password, role, 'engineering')
        )
        user_id = cursor.lastrowid
        db.commit()
        
        return jsonify({
            "message": "Registration successful",
            "user_id": user_id,
            "username": username,
            "role": role,
            "exploit_hint": "Try adding 'role': 'admin' to registration payload"
        }), 201
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    finally:
        db.close()


@privesc_bp.route('/api/privesc/profile-mass-assignment', methods=['PUT'])
@require_auth
def update_profile_mass_assignment():
    """Update profile with mass assignment vulnerability.
    VULNERABILITY: Mass Assignment - accepts role, permissions from request
    EXPLOIT: Send {"role": "admin"} in update payload
    IMPACT: Vertical privilege escalation for existing users
    """
    data = request.get_json()
    user_id = g.current_user['user_id']
    
    db = get_db()
    
    # VULNERABILITY: Builds UPDATE query from ALL request fields
    allowed_updates = ['username', 'email', 'role', 'department']
    updates = []
    values = []
    
    for field in allowed_updates:
        if field in data:
            updates.append(f"{field} = ?")
            values.append(data[field])
    
    if not updates:
        return jsonify({"error": "No fields to update"}), 400
    
    query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
    values.append(user_id)
    
    db.execute(query, tuple(values))
    db.commit()
    
    updated_user = db.execute(
        "SELECT id, username, email, role, department FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    db.close()
    
    return jsonify({
        "message": "Profile updated",
        "user": dict(updated_user),
        "exploit_hint": "Try adding 'role': 'admin' to update payload"
    })


# ============================================================
# 2. COOKIE-BASED ROLE MANIPULATION
# ============================================================

@privesc_bp.route('/api/privesc/login-insecure-cookie', methods=['POST'])
def login_insecure_cookie():
    """Login that stores role in client-side cookie.
    VULNERABILITY: Security-sensitive data in client-controlled cookie
    EXPLOIT: Modify 'user_role' cookie value from 'user' to 'admin'
    IMPACT: Vertical privilege escalation via cookie manipulation
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    db.close()
    
    if not user or user['password'] != hash_password_md5(password):
        return jsonify({"error": "Invalid credentials"}), 401
    
    token = generate_token(dict(user))
    
    response = make_response(jsonify({
        "message": "Login successful",
        "token": token,
        "exploit_hint": "Check your cookies - user_role is client-controlled!"
    }))
    
    # VULNERABILITY: Role stored in unprotected cookie
    response.set_cookie('auth_token', token, httponly=True)
    response.set_cookie('user_role', user['role'])  # ← NOT httponly, easily modified!
    response.set_cookie('user_id', str(user['id']))
    response.set_cookie('username', user['username'])
    
    return response


@privesc_bp.route('/api/privesc/admin-panel-cookie', methods=['GET'])
def admin_panel_cookie():
    """Admin panel that checks role from cookie.
    VULNERABILITY: Authorization from client-controlled cookie
    EXPLOIT: Set 'user_role' cookie to 'admin' manually
    IMPACT: Access to admin functionality
    """
    # VULNERABILITY: Trusts client-side cookie for authorization
    user_role = request.cookies.get('user_role', 'guest')
    username = request.cookies.get('username', 'anonymous')
    
    if user_role != 'admin':
        return jsonify({
            "error": "Admin access required",
            "your_role": user_role,
            "exploit_hint": "Try setting 'user_role' cookie to 'admin'"
        }), 403
    
    db = get_db()
    users = db.execute("SELECT id, username, email, role FROM users").fetchall()
    db.close()
    
    return jsonify({
        "message": f"Welcome to admin panel, {username}",
        "users": [dict(u) for u in users],
        "secret_admin_data": "FLAG{cookie_manipulation_works}"
    })


# ============================================================
# 3. SQL INJECTION FOR PRIVILEGE ESCALATION
# ============================================================

@privesc_bp.route('/api/privesc/update-profile-sqli', methods=['POST'])
@require_auth
def update_profile_sqli():
    """Update profile with SQL injection vulnerability.
    VULNERABILITY: SQL Injection in UPDATE statement
    EXPLOIT: Set display_name to: john', role='admin' WHERE '1'='1
    IMPACT: Vertical privilege escalation via SQL injection
    """
    data = request.get_json()
    user_id = g.current_user['user_id']
    display_name = data.get('display_name', '')
    
    db = get_db()
    
    # VULNERABILITY: String concatenation in SQL query
    # TODO: Use parameterized queries
    query = f"UPDATE users SET department = '{display_name}' WHERE id = {user_id}"
    
    try:
        db.execute(query)
        db.commit()
        
        updated_user = db.execute(
            "SELECT id, username, role, department FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
        db.close()
        
        return jsonify({
            "message": "Profile updated",
            "user": dict(updated_user),
            "exploit_hint": "Try display_name: hacker', role='admin' WHERE '1'='1"
        })
        
    except Exception as e:
        db.close()
        return jsonify({"error": str(e)}), 400


@privesc_bp.route('/api/privesc/search-users-sqli', methods=['GET'])
def search_users_sqli():
    """Search users with SQL injection.
    VULNERABILITY: SQL Injection in WHERE clause
    EXPLOIT: ?search=admin' UNION SELECT 1,2,3,4,'admin',5,6,7--
    IMPACT: Data exfiltration + privilege escalation
    """
    search = request.args.get('search', '')
    
    db = get_db()
    
    # VULNERABILITY: String concatenation in SQL
    query = f"SELECT id, username, email, role FROM users WHERE username LIKE '%{search}%'"
    
    try:
        users = db.execute(query).fetchall()
        db.close()
        
        return jsonify({
            "users": [dict(u) for u in users],
            "query_executed": query,
            "exploit_hint": "Try: ?search=' UNION SELECT 1,'admin_leaked','admin@corp.com','admin'--"
        })
    except Exception as e:
        db.close()
        return jsonify({"error": str(e), "query": query}), 400


# ============================================================
# 4. PARAMETER TAMPERING
# ============================================================

@privesc_bp.route('/api/privesc/promote-user-tampering', methods=['POST'])
@require_auth
def promote_user_tampering():
    """Promote user with hidden parameter vulnerability.
    VULNERABILITY: Hidden 'target_user_id' parameter allows IDOR
    EXPLOIT: Change target_user_id to another user's ID
    IMPACT: Horizontal + vertical privilege escalation
    """
    data = request.get_json()
    
    # Frontend sends current user's ID, but doesn't validate
    target_user_id = data.get('target_user_id', g.current_user['user_id'])
    new_role = data.get('new_role', 'premium_user')
    
    # VULNERABILITY: No check if target_user_id == current user
    db = get_db()
    db.execute(
        "UPDATE users SET role = ? WHERE id = ?",
        (new_role, target_user_id)
    )
    db.commit()
    
    updated_user = db.execute(
        "SELECT id, username, role FROM users WHERE id = ?",
        (target_user_id,)
    ).fetchone()
    db.close()
    
    return jsonify({
        "message": "User promoted successfully",
        "user": dict(updated_user),
        "exploit_hint": "Try changing 'target_user_id' to escalate OTHER users"
    })


# ============================================================
# 5. JWT MANIPULATION & ALGORITHM CONFUSION
# ============================================================

@privesc_bp.route('/api/privesc/verify-token-weak', methods=['POST'])
def verify_token_weak():
    """Verify JWT with weak validation.
    VULNERABILITY: Accepts 'none' algorithm, weak secret
    EXPLOIT 1: Change alg to 'none' and remove signature
    EXPLOIT 2: Brute force weak secret
    IMPACT: Token forgery → privilege escalation
    """
    data = request.get_json()
    token = data.get('token', '')
    
    try:
        # VULNERABILITY: Accepts 'none' algorithm
        header = jwt.get_unverified_header(token)
        algorithm = header.get('alg', 'HS256')
        
        if algorithm == 'none':
            # VULNERABILITY: No signature verification
            payload = jwt.decode(token, options={'verify_signature': False})
        else:
            # VULNERABILITY: Weak secret (easily brute-forced)
            payload = jwt.decode(token, JWT_SECRET, algorithms=[algorithm])
        
        return jsonify({
            "valid": True,
            "payload": payload,
            "exploit_hint": "Try alg='none' or brute-force the secret: " + JWT_SECRET[:20] + "..."
        })
        
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)}), 401


@privesc_bp.route('/api/privesc/admin-with-jwt', methods=['GET'])
def admin_with_jwt():
    """Admin endpoint checking JWT role claim.
    VULNERABILITY: Trusts role from JWT without DB verification
    EXPLOIT: Forge JWT with "role": "admin"
    IMPACT: Vertical privilege escalation
    """
    auth_header = request.headers.get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return jsonify({"error": "Token required"}), 401
    
    token = auth_header.replace('Bearer ', '')
    
    try:
        payload = verify_token(token)
        if not payload:
            return jsonify({"error": "Invalid token"}), 401
        
        # VULNERABILITY: Trusts role from token, doesn't check database
        if payload.get('role') != 'admin':
            return jsonify({
                "error": "Admin role required",
                "your_role": payload.get('role'),
                "exploit_hint": "Forge a JWT with 'role': 'admin'"
            }), 403
        
        return jsonify({
            "message": "Admin access granted",
            "secret_data": "FLAG{jwt_role_manipulation}",
            "jwt_secret_hint": JWT_SECRET[:20] + "..."
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 401


# ============================================================
# 6. CSRF TO ADMIN FUNCTIONS
# ============================================================

@privesc_bp.route('/api/privesc/admin-delete-user', methods=['POST'])
@require_auth
def admin_delete_user_no_csrf():
    """Delete user without CSRF protection.
    VULNERABILITY: No CSRF token validation + permissive CORS
    EXPLOIT: Craft malicious page that POSTs to this endpoint
    IMPACT: CSRF → delete users if victim is admin
    """
    data = request.get_json()
    target_user_id = data.get('user_id')
    
    # VULNERABILITY: No CSRF token check
    # VULNERABILITY: Only checks role from JWT (forgeable)
    if g.current_user['role'] != 'admin':
        return jsonify({"error": "Admin required"}), 403
    
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (target_user_id,))
    db.commit()
    db.close()
    
    return jsonify({
        "message": f"User {target_user_id} deleted",
        "exploit_hint": "No CSRF token! Attacker can create malicious page"
    })


@privesc_bp.route('/api/privesc/admin-change-password', methods=['POST'])
def admin_change_password_no_csrf():
    """Change any user's password (CSRF vulnerable).
    VULNERABILITY: No CSRF protection + no current password check
    EXPLOIT: Lure admin to malicious page that submits form
    IMPACT: Account takeover via CSRF
    """
    data = request.get_json()
    target_user_id = data.get('user_id')
    new_password = data.get('new_password')
    
    # VULNERABILITY: No CSRF token
    # VULNERABILITY: No current password verification
    
    db = get_db()
    hashed = hash_password_md5(new_password)
    db.execute(
        "UPDATE users SET password = ? WHERE id = ?",
        (hashed, target_user_id)
    )
    db.commit()
    db.close()
    
    return jsonify({
        "message": f"Password changed for user {target_user_id}",
        "exploit_hint": "Create CSRF PoC: <form action=this-url><input name=user_id value=1>"
    })


# ============================================================
# 7. SSRF TO INTERNAL ADMIN API
# ============================================================

@privesc_bp.route('/api/privesc/fetch-profile-ssrf', methods=['POST'])
@require_auth
def fetch_profile_ssrf():
    """Fetch user profile from URL (SSRF vulnerable).
    VULNERABILITY: SSRF - can access localhost endpoints
    EXPLOIT: Set url to http://localhost:5000/api/admin/system-info
    IMPACT: Access internal admin APIs bypassing authentication
    """
    data = request.get_json()
    profile_url = data.get('url', '')
    
    if not profile_url:
        return jsonify({"error": "URL required"}), 400
    
    # VULNERABILITY: No URL validation, can access localhost
    try:
        response = requests.get(profile_url, timeout=5)
        
        return jsonify({
            "profile_data": response.text,
            "status_code": response.status_code,
            "exploit_hint": "Try url: http://localhost:5000/api/admin/system-info"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@privesc_bp.route('/api/privesc/import-users-ssrf', methods=['POST'])
@require_auth
def import_users_ssrf():
    """Import users from remote URL (SSRF vulnerable).
    VULNERABILITY: SSRF to internal network
    EXPLOIT: Access AWS metadata, internal services
    IMPACT: Credential theft, internal network scanning
    """
    data = request.get_json()
    import_url = data.get('url', '')
    
    # VULNERABILITY: No URL whitelist/validation
    try:
        response = requests.get(import_url, timeout=5)
        
        return jsonify({
            "imported_data": response.text[:500],
            "exploit_hint": "Try: http://169.254.169.254/latest/meta-data/ (AWS metadata)"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ============================================================
# 8. AUTHORIZATION BYPASS
# ============================================================

@privesc_bp.route('/api/privesc/admin-stats', methods=['GET'])
def admin_stats_no_auth():
    """Admin statistics with missing authentication.
    VULNERABILITY: No @require_auth decorator
    EXPLOIT: Access without any token
    IMPACT: Information disclosure
    """
    # VULNERABILITY: No authentication check at all!
    
    db = get_db()
    stats = {
        "total_users": db.execute("SELECT COUNT(*) as c FROM users").fetchone()['c'],
        "admin_users": db.execute("SELECT username FROM users WHERE role='admin'").fetchall(),
        "recent_logins": "All user sessions data...",
        "exploit_hint": "No authentication required for this endpoint!"
    }
    db.close()
    
    return jsonify(stats)


@privesc_bp.route('/api/privesc/admin-promote', methods=['POST'])
def admin_promote_broken_auth():
    """Promote user with broken authorization check.
    VULNERABILITY: Commented-out authorization check
    EXPLOIT: Access without proper authentication
    IMPACT: Privilege escalation
    """
    data = request.get_json()
    user_id = data.get('user_id')
    
    # VULNERABILITY: Authorization check commented out (simulating bad code commit)
    # TODO: Uncomment this before production!
    # if not check_is_admin():
    #     return jsonify({"error": "Admin required"}), 403
    
    db = get_db()
    db.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user_id,))
    db.commit()
    db.close()
    
    return jsonify({
        "message": f"User {user_id} promoted to admin",
        "exploit_hint": "Authorization check is commented out!"
    })


# ============================================================
# 9. SESSION FIXATION
# ============================================================

@privesc_bp.route('/api/privesc/login-session-fixation', methods=['POST'])
def login_session_fixation():
    """Login with session fixation vulnerability.
    VULNERABILITY: Accepts session_id from client
    EXPLOIT: Pre-set victim's session ID, then wait for login
    IMPACT: Session hijacking
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # VULNERABILITY: Client can specify their session ID
    preferred_session = data.get('session_id', None)
    
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    
    if not user or user['password'] != hash_password_md5(password):
        db.close()
        return jsonify({"error": "Invalid credentials"}), 401
    
    # VULNERABILITY: Uses client-provided session ID
    if preferred_session:
        session_id = preferred_session
    else:
        session_id = hashlib.md5(f"{username}{time.time()}".encode()).hexdigest()
    
    db.execute(
        "UPDATE users SET session_token = ? WHERE id = ?",
        (session_id, user['id'])
    )
    db.commit()
    db.close()
    
    token = generate_token(dict(user))
    
    response = make_response(jsonify({
        "message": "Login successful",
        "token": token,
        "session_id": session_id,
        "exploit_hint": "Attacker can pre-set session_id and hijack after login"
    }))
    
    response.set_cookie('session_id', session_id)
    
    return response


# ============================================================
# 10. IDOR WITH PRIVILEGE ESCALATION
# ============================================================

@privesc_bp.route('/api/privesc/user/<int:user_id>/permissions', methods=['GET'])
def get_user_permissions_idor(user_id):
    """Get user permissions (IDOR + information disclosure).
    VULNERABILITY: No authentication, direct object reference
    EXPLOIT: Enumerate user_id values to find admins
    IMPACT: User enumeration + privilege information disclosure
    """
    # VULNERABILITY: No authentication required
    
    db = get_db()
    user = db.execute(
        "SELECT id, username, role, email FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    db.close()
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({
        "user": dict(user),
        "permissions": {
            "can_delete": user['role'] == 'admin',
            "can_promote": user['role'] == 'admin',
            "api_access_level": "full" if user['role'] == 'admin' else "limited"
        },
        "exploit_hint": "Enumerate user_id 1-100 to find all admins"
    })


@privesc_bp.route('/api/privesc/user/<int:user_id>/upgrade', methods=['POST'])
def upgrade_user_idor(user_id):
    """Upgrade user account (IDOR).
    VULNERABILITY: Can upgrade any user's account
    EXPLOIT: Change user_id to target different users
    IMPACT: Horizontal privilege escalation
    """
    data = request.get_json()
    upgrade_type = data.get('upgrade_type', 'premium')
    
    # VULNERABILITY: No check if requesting user owns this account
    
    db = get_db()
    
    # Upgrade mapping
    role_map = {
        'premium': 'premium_user',
        'pro': 'pro_user',
        'admin': 'admin'  # ← Shouldn't be accessible!
    }
    
    new_role = role_map.get(upgrade_type, 'premium_user')
    
    db.execute(
        "UPDATE users SET role = ? WHERE id = ?",
        (new_role, user_id)
    )
    db.commit()
    
    updated_user = db.execute(
        "SELECT id, username, role FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    db.close()
    
    return jsonify({
        "message": "User upgraded",
        "user": dict(updated_user),
        "exploit_hint": "Try upgrade_type: 'admin' on different user_id values"
    })


# ============================================================
# HELPER ENDPOINT - Test Your Exploits
# ============================================================

@privesc_bp.route('/api/privesc/check-privilege', methods=['GET'])
def check_privilege():
    """Check current user's privilege level.
    Use this to verify if your privilege escalation worked.
    """
    auth_header = request.headers.get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return jsonify({
            "authenticated": False,
            "message": "No token provided"
        })
    
    token = auth_header.replace('Bearer ', '')
    
    try:
        from auth import verify_token
        payload = verify_token(token)
        
        if not payload:
            return jsonify({"authenticated": False, "message": "Invalid token"})
        
        user_id = payload['user_id']
        
        # Check actual database role
        db = get_db()
        user = db.execute(
            "SELECT id, username, role, department FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
        db.close()
        
        if not user:
            return jsonify({"authenticated": False, "message": "User not found"})
        
        return jsonify({
            "authenticated": True,
            "jwt_claims": payload,
            "database_role": user['role'],
            "is_admin": user['role'] == 'admin',
            "privilege_escalation_success": user['role'] != payload.get('role', user['role']),
            "user_info": dict(user)
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 401


@privesc_bp.route('/api/privesc/vulnerabilities', methods=['GET'])
def list_vulnerabilities():
    """List all privilege escalation vulnerabilities in this module."""
    return jsonify({
        "vulnerabilities": [
            {
                "id": 1,
                "name": "Mass Assignment",
                "endpoints": [
                    "POST /api/privesc/register-mass-assignment",
                    "PUT /api/privesc/profile-mass-assignment"
                ],
                "exploit": "Add 'role': 'admin' to request body",
                "impact": "Vertical privilege escalation"
            },
            {
                "id": 2,
                "name": "Cookie Manipulation",
                "endpoints": [
                    "POST /api/privesc/login-insecure-cookie",
                    "GET /api/privesc/admin-panel-cookie"
                ],
                "exploit": "Modify 'user_role' cookie to 'admin'",
                "impact": "Vertical privilege escalation"
            },
            {
                "id": 3,
                "name": "SQL Injection for Privilege Escalation",
                "endpoints": [
                    "POST /api/privesc/update-profile-sqli",
                    "GET /api/privesc/search-users-sqli"
                ],
                "exploit": "Inject SQL to UPDATE role column",
                "impact": "Vertical privilege escalation + data exfiltration"
            },
            {
                "id": 4,
                "name": "Parameter Tampering",
                "endpoints": ["POST /api/privesc/promote-user-tampering"],
                "exploit": "Change 'target_user_id' parameter",
                "impact": "Horizontal + vertical privilege escalation"
            },
            {
                "id": 5,
                "name": "JWT Manipulation",
                "endpoints": [
                    "POST /api/privesc/verify-token-weak",
                    "GET /api/privesc/admin-with-jwt"
                ],
                "exploit": "Forge JWT with alg='none' or brute-force secret",
                "impact": "Authentication bypass + privilege escalation"
            },
            {
                "id": 6,
                "name": "CSRF to Admin Functions",
                "endpoints": [
                    "POST /api/privesc/admin-delete-user",
                    "POST /api/privesc/admin-change-password"
                ],
                "exploit": "Create malicious page that auto-submits form",
                "impact": "Account takeover + data manipulation"
            },
            {
                "id": 7,
                "name": "SSRF",
                "endpoints": [
                    "POST /api/privesc/fetch-profile-ssrf",
                    "POST /api/privesc/import-users-ssrf"
                ],
                "exploit": "Access http://localhost:5000/api/admin/* endpoints",
                "impact": "Internal API access + credential theft"
            },
            {
                "id": 8,
                "name": "Authorization Bypass",
                "endpoints": [
                    "GET /api/privesc/admin-stats",
                    "POST /api/privesc/admin-promote"
                ],
                "exploit": "Access without authentication",
                "impact": "Information disclosure + privilege escalation"
            },
            {
                "id": 9,
                "name": "Session Fixation",
                "endpoints": ["POST /api/privesc/login-session-fixation"],
                "exploit": "Pre-set victim's session_id",
                "impact": "Session hijacking"
            },
            {
                "id": 10,
                "name": "IDOR",
                "endpoints": [
                    "GET /api/privesc/user/<id>/permissions",
                    "POST /api/privesc/user/<id>/upgrade"
                ],
                "exploit": "Enumerate user_id values",
                "impact": "Horizontal + vertical privilege escalation"
            }
        ],
        "total_vulnerabilities": 10,
        "test_endpoint": "GET /api/privesc/check-privilege"
    })
