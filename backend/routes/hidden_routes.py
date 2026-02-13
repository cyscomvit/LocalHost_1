"""
CTOP University - Hidden Internal Routes
INTENTIONALLY INSECURE: Undocumented endpoints that expose sensitive data

These endpoints represent "security by obscurity" - they're not linked in the UI
or documented, but are accessible to anyone who discovers the URL.

VULNERABILITIES:
1. No authentication required
2. Expose sensitive system information
3. Expose user PII and credentials
4. Not documented but discoverable via fuzzing/directory enumeration

WORKSHOP GOAL: Students will learn to:
- Discover hidden endpoints
- Understand why security by obscurity fails
- Implement proper access controls
- Restrict endpoints to server-side only or authenticated admin users

PATCHING INSTRUCTIONS:
- Uncomment the SECURE sections to enable protection
- Comment out or modify the VULNERABLE sections
- Test each change to verify it works
"""

from flask import Blueprint, jsonify, request
import os
import sys
import platform
import psutil
from datetime import datetime
from db_mysql import get_mysql_connection
from functools import wraps
# import logging  # Uncomment for audit logging

hidden_bp = Blueprint('hidden', __name__)


# ============================================================
# SECURITY DECORATORS (UNCOMMENT TO USE)
# ============================================================

# # UNCOMMENT THIS FOR AUDIT LOGGING:
# audit_logger = logging.getLogger('audit')
# audit_logger.setLevel(logging.INFO)
# handler = logging.FileHandler('audit.log')
# handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
# audit_logger.addHandler(handler)

# ALLOWED_IPS = ['127.0.0.1', '::1', 'localhost']

# def require_admin(f):
#     """SECURE: Decorator to require admin role for endpoint access."""
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         auth_header = request.headers.get('Authorization')
#         if not auth_header:
#             # audit_logger.warning(f"Unauthorized access attempt to {request.path} from {request.remote_addr}")
#             return jsonify({"error": "Authentication required"}), 401
#         
#         # Check if user has admin role
#         from auth import decode_token
#         try:
#             token = auth_header.replace('Bearer ', '')
#             user_data = decode_token(token)
#             
#             if not user_data or user_data.get('role') != 'admin':
#                 # audit_logger.warning(f"Non-admin user {user_data.get('username', 'unknown')} attempted to access {request.path}")
#                 return jsonify({"error": "Admin access required"}), 403
#             
#             # audit_logger.info(f"Admin {user_data.get('username')} accessed {request.path} from {request.remote_addr}")
#             
#         except Exception as e:
#             # audit_logger.error(f"Token validation failed: {str(e)}")
#             return jsonify({"error": "Invalid token"}), 401
#         
#         return f(*args, **kwargs)
#     return decorated_function

# def require_localhost(f):
#     """SECURE: Decorator to restrict endpoint to localhost only."""
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if request.remote_addr not in ALLOWED_IPS:
#             # audit_logger.warning(f"Non-localhost access attempt to {request.path} from {request.remote_addr}")
#             return jsonify({"error": "This endpoint is only accessible from localhost"}), 403
#         return f(*args, **kwargs)
#     return decorated_function


# ============================================================
# HIDDEN ENDPOINT #1: System Information & Diagnostics
# ============================================================

# VULNERABLE VERSION (CURRENT):
@hidden_bp.route('/api/internal/system-info', methods=['GET'])
def system_info():
    """
    Internal system diagnostics endpoint.
    
    INTENTIONALLY VULNERABLE:
    - No authentication required
    - Exposes system configuration and environment variables
    - Reveals infrastructure details to attackers
    - Should be restricted to localhost/admin only
    
    PATCH STRATEGY:
    1. Add @require_localhost decorator (uncomment above)
    2. Add @require_admin decorator (uncomment above)
    3. Remove secrets from environment section
    4. Uncomment secure version below and comment this function
    """
    
    try:
        # Get system information
        cpu_count = psutil.cpu_count()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        system_data = {
            "endpoint": "/api/internal/system-info",
            "status": "exposed",
            "warning": "⚠️ This endpoint should not be publicly accessible!",
            
            "system": {
                "platform": platform.platform(),
                "python_version": sys.version,
                "os": platform.system(),
                "architecture": platform.machine(),
                "hostname": platform.node(),
                "processor": platform.processor(),
            },
            
            "resources": {
                "cpu_cores": cpu_count,
                "memory_total_gb": round(memory.total / (1024**3), 2),
                "memory_available_gb": round(memory.available / (1024**3), 2),
                "memory_percent": memory.percent,
                "disk_total_gb": round(disk.total / (1024**3), 2),
                "disk_free_gb": round(disk.free / (1024**3), 2),
                "disk_percent": disk.percent,
            },
            
            "environment": {
                "flask_env": os.getenv('FLASK_ENV', 'unknown'),
                "flask_debug": os.getenv('FLASK_DEBUG', 'unknown'),
                "database_url": os.getenv('DATABASE_URL', 'unknown'),
                "jwt_secret": os.getenv('JWT_SECRET', 'unknown'),  # 🚨 EXPOSED SECRET!
                "admin_password": os.getenv('ADMIN_PASSWORD', 'unknown'),  # 🚨 EXPOSED PASSWORD!
                "stripe_key": os.getenv('STRIPE_SECRET_KEY', 'unknown'),  # 🚨 EXPOSED API KEY!
                "aws_access_key": os.getenv('AWS_ACCESS_KEY_ID', 'unknown'),  # 🚨 EXPOSED CREDENTIALS!
            },
            
            "application": {
                "name": "CTOP University Portal",
                "version": "1.0.0-vulnerable",
                "uptime_seconds": None,
                "debug_mode": True,
                "cors_enabled": True,
                "cors_origins": "*",
            },
            
            "request_info": {
                "remote_addr": request.remote_addr,
                "user_agent": request.headers.get('User-Agent'),
                "timestamp": datetime.utcnow().isoformat(),
            },
            
            "flags": {
                "ctf_flag_1": "FLAG{h1dd3n_3ndp01nt5_ar3_n0t_s3cur3}",
                "discovery_method": "directory_fuzzing",
            }
        }
        
        return jsonify(system_data), 200
        
    except Exception as e:
        return jsonify({
            "error": str(e),
            "traceback": str(e.__traceback__)
        }), 500


# # SECURE VERSION (UNCOMMENT TO USE):
# # TO PATCH: Comment out the vulnerable function above and uncomment this one
# @hidden_bp.route('/api/internal/system-info', methods=['GET'])
# @require_localhost  # ✅ Only accessible from localhost
# @require_admin      # ✅ Requires admin authentication
# def system_info():
#     """SECURE VERSION: System diagnostics with proper access control."""
#     try:
#         cpu_count = psutil.cpu_count()
#         memory = psutil.virtual_memory()
#         disk = psutil.disk_usage('/')
#         
#         system_data = {
#             "endpoint": "/api/internal/system-info",
#             "status": "secured",
#             "access_level": "admin_only",
#             
#             "system": {
#                 "platform": platform.platform(),
#                 "python_version": sys.version.split()[0],  # ✅ Version only, no full details
#                 "os": platform.system(),
#                 "architecture": platform.machine(),
#                 # ✅ Removed: hostname, processor (too detailed)
#             },
#             
#             "resources": {
#                 "cpu_cores": cpu_count,
#                 "memory_total_gb": round(memory.total / (1024**3), 2),
#                 "memory_available_gb": round(memory.available / (1024**3), 2),
#                 "memory_percent": memory.percent,
#                 "disk_total_gb": round(disk.total / (1024**3), 2),
#                 "disk_free_gb": round(disk.free / (1024**3), 2),
#                 "disk_percent": disk.percent,
#             },
#             
#             "environment": {
#                 "flask_env": os.getenv('FLASK_ENV', 'production'),
#                 "flask_debug": "false",  # ✅ Never expose actual debug state
#                 "note": "Sensitive environment variables excluded for security"
#                 # ✅ Removed: ALL secrets (jwt_secret, passwords, API keys, AWS credentials)
#             },
#             
#             "application": {
#                 "name": "CTOP University Portal",
#                 "version": "1.0.0-secure",
#                 "debug_mode": False,  # ✅ Don't reveal actual state
#             },
#             
#             "request_info": {
#                 "timestamp": datetime.utcnow().isoformat(),
#                 # ✅ Removed: user_agent, IP (minimal disclosure)
#             },
#         }
#         
#         return jsonify(system_data), 200
#         
#     except Exception as e:
#         # ✅ SECURE: Generic error message, no stack trace
#         # audit_logger.error(f"Error in system_info: {str(e)}")
#         return jsonify({"error": "Internal server error"}), 500


# ============================================================
# HIDDEN ENDPOINT #2: User Data Export
# ============================================================

# VULNERABLE VERSION (CURRENT):
@hidden_bp.route('/api/internal/users/export', methods=['GET'])
def export_users():
    """
    Internal user data export endpoint for "administrative purposes".
    
    INTENTIONALLY VULNERABLE:
    - No authentication required
    - Exposes ALL user PII (emails, passwords, roles)
    - No audit logging
    - No rate limiting
    
    PATCH STRATEGY:
    1. Add @require_admin decorator
    2. Remove password_hash from export (never expose passwords)
    3. Add pagination to prevent mass export
    4. Add audit logging for all exports
    5. Uncomment secure version below and comment this function
    """
    
    try:
        # Get export format (JSON or CSV)
        export_format = request.args.get('format', 'json')
        include_passwords = request.args.get('include_passwords', 'true').lower() == 'true'
        
        # Query ALL users from MySQL database
        connection = get_mysql_connection()
        cursor = connection.cursor()
        
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        
        user_data = []
        for user in users:
            user_dict = {
                "id": user['id'],
                "username": user['username'],
                "student_id": user.get('student_id', 'N/A'),
                "email": user['email'],
                "full_name": user.get('full_name', 'Unknown'),
                "program": user.get('program', 'N/A'),
                "semester": user.get('semester', 0),
                "cgpa": float(user['cgpa']) if user.get('cgpa') else 0.0,
                "is_admin": bool(user.get('is_admin', False)),
                "created_at": user['created_at'].isoformat() if user.get('created_at') else None,
            }
            
            # 🚨 INTENTIONALLY VULNERABLE: Exposing password hashes!
            if include_passwords:
                user_dict["password_hash"] = user['password_hash']
                user_dict["password_algorithm"] = "MD5" if len(user['password_hash']) == 32 else "unknown"
            
            user_data.append(user_dict)
        
        cursor.close()
        connection.close()
        
        response = {
            "endpoint": "/api/internal/users/export",
            "status": "exposed",
            "warning": "⚠️ This endpoint exposes sensitive PII without authentication!",
            "export_timestamp": datetime.utcnow().isoformat(),
            "total_users": len(user_data),
            "format": export_format,
            "includes_passwords": include_passwords,
            "users": user_data,
            "flags": {
                "ctf_flag_2": "FLAG{1d0r_m33ts_m4ss_4ss1gnm3nt}",
                "note": "You just exported the entire user database without authentication!",
            },
            "exploitation_tips": {
                "crack_passwords": "Use hashcat or john to crack MD5 hashes (mode -m 0)",
                "phishing": "Use email addresses for targeted phishing",
                "privilege_escalation": "Target admin accounts for escalation",
                "md5_collision": "Look for users with same hash but different passwords!"
            }
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        return jsonify({
            "error": "Failed to export users",
            "details": str(e),
            "traceback": str(e.__traceback__)
        }), 500


# # SECURE VERSION (UNCOMMENT TO USE):
# # TO PATCH: Comment out the vulnerable function above and uncomment this one
# @hidden_bp.route('/api/internal/users/export', methods=['GET'])
# @require_admin  # ✅ Requires admin authentication
# def export_users():
#     """SECURE VERSION: User export with proper access control."""
#     try:
#         # Get pagination parameters
#         page = request.args.get('page', 1, type=int)
#         per_page = min(request.args.get('per_page', 50, type=int), 100)  # ✅ Max 100 per page
#         offset = (page - 1) * per_page
#         
#         connection = get_mysql_connection()
#         cursor = connection.cursor()
#         
#         # Get total count
#         cursor.execute("SELECT COUNT(*) as total FROM users")
#         total = cursor.fetchone()['total']
#         
#         # ✅ Get paginated users WITHOUT password field
#         cursor.execute(f"""
#             SELECT id, username, student_id, email, full_name, program, semester, cgpa 
#             FROM users 
#             LIMIT {per_page} OFFSET {offset}
#         """)
#         users = cursor.fetchall()
#         
#         user_data = []
#         for user in users:
#             user_dict = {
#                 "id": user['id'],
#                 "username": user['username'],
#                 "student_id": user.get('student_id', 'N/A'),
#                 "email": user['email'],
#                 "full_name": user.get('full_name', 'Unknown'),
#                 "program": user.get('program', 'N/A'),
#                 # ✅ SECURE: Password field NEVER included, even if requested
#             }
#             user_data.append(user_dict)
#         
#         cursor.close()
#         connection.close()
#         
#         # ✅ Log the export to audit trail
#         # from auth import decode_token
#         # auth_header = request.headers.get('Authorization', '')
#         # token = auth_header.replace('Bearer ', '')
#         # user_info = decode_token(token)
#         # audit_logger.info(f"User export by admin {user_info.get('username', 'unknown')} - Page {page}, {len(user_data)} users")
#         
#         total_pages = (total + per_page - 1) // per_page
#         
#         response = {
#             "endpoint": "/api/internal/users/export",
#             "status": "secured",
#             "access_level": "admin_only",
#             "export_timestamp": datetime.utcnow().isoformat(),
#             "total_users": total,
#             "page": page,
#             "per_page": per_page,
#             "total_pages": total_pages,
#             "users": user_data,
#             "note": "Password hashes excluded for security. All exports are audited.",
#         }
#         
#         return jsonify(response), 200
#         
#     except Exception as e:
#         # ✅ SECURE: Generic error message, log details internally
#         # audit_logger.error(f"Error in export_users: {str(e)}")
#         return jsonify({"error": "Failed to export users"}), 500


# ============================================================
# HIDDEN ENDPOINT #3: Database Query Console (BONUS!)
# ============================================================

# VULNERABLE VERSION (CURRENT):
@hidden_bp.route('/api/internal/db-console', methods=['POST'])
def db_console():
    """
    Internal database console for "debugging".
    
    INTENTIONALLY VULNERABLE:
    - Allows arbitrary SQL queries
    - No authentication
    - No input sanitization
    - Direct database access
    
    THIS IS EXTREMELY DANGEROUS! Demonstrates worst-case scenario.
    
    PATCH STRATEGY:
    1. DELETE THIS ENDPOINT COMPLETELY (recommended)
    2. Or replace with the secure version that returns 410 Gone
    3. Never allow arbitrary SQL execution in production
    4. Use proper database admin tools instead
    """
    
    try:
        sql_query = request.json.get('query', '')
        
        if not sql_query:
            return jsonify({"error": "No query provided"}), 400
        
        # 🚨 EXTREMELY VULNERABLE: Direct SQL execution!
        connection = get_mysql_connection()
        cursor = connection.cursor()
        
        cursor.execute(sql_query)
        
        # Try to fetch results (if SELECT query)
        try:
            rows = cursor.fetchall()
            
            return jsonify({
                "status": "success",
                "query": sql_query,
                "row_count": len(rows),
                "data": rows,
                "warning": "🚨 You just executed arbitrary SQL! This should NEVER be possible!",
                "flag": "FLAG{sql_c0ns0l3_1s_g4m3_0v3r}"
            }), 200
            
        except Exception:
            # Query didn't return results (INSERT, UPDATE, DELETE, etc.)
            connection.commit()
            return jsonify({
                "status": "success",
                "query": sql_query,
                "message": "Query executed successfully",
                "warning": "🚨 You just modified the database without authentication!"
            }), 200
            
    except Exception as e:
        if 'connection' in locals():
            connection.rollback()
        return jsonify({
            "error": "Query execution failed",
            "query": request.json.get('query', ''),
            "details": str(e)
        }), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()


# # SECURE VERSION (UNCOMMENT TO USE):
# # TO PATCH: Comment out or DELETE the vulnerable function above and uncomment this one
# @hidden_bp.route('/api/internal/db-console', methods=['POST'])
# def db_console():
#     """
#     SECURE VERSION: This endpoint has been removed for security.
#     
#     ✅ Best practice: Delete endpoints that allow arbitrary SQL execution.
#     There is NO safe way to implement this functionality.
#     
#     Alternatives for database debugging:
#     - Use proper database admin tools (MySQL Workbench, pgAdmin)
#     - Create specific read-only query endpoints
#     - Use application logging instead
#     - Implement health check endpoints with validation
#     """
#     # audit_logger.warning(f"Attempt to access removed db-console from {request.remote_addr}")
#     
#     return jsonify({
#         "error": "This endpoint has been removed for security reasons",
#         "reason": "Arbitrary SQL execution is not permitted",
#         "alternative": "Use proper database administration tools",
#         "status": "endpoint_removed"
#     }), 410  # ✅ 410 Gone - indicates the resource has been permanently removed


# ============================================================
# HIDDEN ENDPOINT #4: Real Database Backup Dump
# Discoverable via directory fuzzing (common word: "backup")
# ============================================================

@hidden_bp.route('/api/backup', methods=['GET'])
def backup_database():
    """
    Real database backup endpoint - dumps actual user table.
    
    INTENTIONALLY VULNERABLE:
    - No authentication required
    - Dumps real user data including password hashes
    - Discoverable via wordlist fuzzing (backup is common)
    
    PATCH: Add @require_admin, remove password_hash from output
    """
    try:
        connection = get_mysql_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT id, username, email, full_name, password_hash, is_admin, created_at FROM users")
        users = cursor.fetchall()
        cursor.close()
        connection.close()

        backup = []
        for u in users:
            backup.append({
                "id": u["id"],
                "username": u["username"],
                "email": u["email"],
                "full_name": u.get("full_name"),
                "password_hash": u["password_hash"],
                "is_admin": bool(u.get("is_admin", False)),
                "created_at": u["created_at"].isoformat() if u.get("created_at") else None
            })

        return jsonify({
            "backup_timestamp": datetime.utcnow().isoformat(),
            "total_records": len(backup),
            "table": "users",
            "data": backup
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# HIDDEN ENDPOINT #5: Application Config Dump
# Exposes real .env variables loaded into the running process
# ============================================================

@hidden_bp.route('/api/internal/config', methods=['GET'])
def app_config():
    """
    Dumps real application configuration from environment.
    
    INTENTIONALLY VULNERABLE:
    - Exposes actual DB credentials, JWT secret, etc.
    - No authentication required
    
    PATCH: Delete this endpoint entirely
    """
    return jsonify({
        "database": {
            "host": os.getenv("MYSQL_HOST", ""),
            "port": os.getenv("MYSQL_PORT", "3306"),
            "user": os.getenv("MYSQL_USER", ""),
            "password": os.getenv("MYSQL_PASSWORD", ""),
            "database": os.getenv("MYSQL_DATABASE", ""),
        },
        "jwt": {
            "secret": os.getenv("JWT_SECRET", ""),
            "algorithm": "HS256",
        },
        "flask": {
            "secret_key": os.getenv("SECRET_KEY", "taskflowr-flask-secret-not-so-secret"),
            "debug": os.getenv("FLASK_DEBUG", "true"),
        },
        "server_time": datetime.utcnow().isoformat()
    }), 200


# ============================================================
# HIDDEN ENDPOINT #6: Password Reset (no auth, no email)
# A real "forgot password" backdoor that resets any user
# ============================================================

@hidden_bp.route('/api/internal/reset-password', methods=['POST'])
def reset_any_password():
    """
    Resets any user's password without authentication or email verification.
    
    INTENTIONALLY VULNERABLE:
    - No authentication required
    - No email verification
    - Accepts username directly
    - Uses weak MD5 hashing
    
    PATCH: Require email-based token verification, add rate limiting
    """
    import hashlib
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    new_password = data.get("new_password", "")

    if not username or not new_password:
        return jsonify({"error": "username and new_password required"}), 400

    try:
        connection = get_mysql_connection()
        cursor = connection.cursor()

        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if not user:
            cursor.close()
            connection.close()
            return jsonify({"error": "User not found"}), 404

        new_hash = hashlib.md5(new_password.encode()).hexdigest()
        cursor.execute("UPDATE users SET password_hash = %s WHERE username = %s", (new_hash, username))
        connection.commit()
        cursor.close()
        connection.close()

        return jsonify({
            "message": f"Password for {username} has been reset",
            "new_hash": new_hash
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# HIDDEN ENDPOINT #7: Promote user to admin (no auth)
# A real privilege escalation backdoor
# ============================================================

@hidden_bp.route('/api/internal/make-admin', methods=['POST'])
def make_admin():
    """
    Promotes any user to admin without authentication.
    
    INTENTIONALLY VULNERABLE:
    - No authentication required
    - Direct database modification
    - No audit trail
    
    PATCH: Delete this endpoint entirely
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")

    if not username:
        return jsonify({"error": "username required"}), 400

    try:
        connection = get_mysql_connection()
        cursor = connection.cursor()

        cursor.execute("SELECT id, username, is_admin FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if not user:
            cursor.close()
            connection.close()
            return jsonify({"error": "User not found"}), 404

        cursor.execute("UPDATE users SET is_admin = 1 WHERE username = %s", (username,))
        connection.commit()
        cursor.close()
        connection.close()

        return jsonify({
            "message": f"{username} is now an admin",
            "previous_admin_status": bool(user.get("is_admin", False))
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# PATCHING INSTRUCTIONS
# ============================================================
#
# STEP 1: Uncomment Security Decorators (lines 30-70)
#   - Uncomment audit_logger setup
#   - Uncomment ALLOWED_IPS list
#   - Uncomment require_admin() function
#   - Uncomment require_localhost() function
#
# STEP 2: Patch System Info Endpoint
#   - Comment out vulnerable system_info() function (lines 75-150)
#   - Uncomment secure system_info() function (lines 155-200)
#   - Test: curl -H "Authorization: Bearer TOKEN" http://localhost:5000/api/internal/system-info
#   - Verify: No secrets in response
#
# STEP 3: Patch User Export Endpoint
#   - Comment out vulnerable export_users() function (lines 205-280)
#   - Uncomment secure export_users() function (lines 285-350)
#   - Test: curl -H "Authorization: Bearer ADMIN_TOKEN" http://localhost:5000/api/internal/users/export
#   - Verify: No password_hash field in response
#
# STEP 4: Remove Database Console Endpoint
#   - Comment out vulnerable db_console() function (lines 355-410)
#   - Uncomment secure db_console() function (lines 415-435)
#   - Test: curl -X POST http://localhost:5000/api/internal/db-console
#   - Verify: Returns 410 Gone status
#
# STEP 5: Test All Changes
#   - Run: python test_hidden_endpoints.py
#   - All endpoints should require authentication
#   - System info should not expose secrets
#   - User export should not include passwords
#   - DB console should return 410 Gone
#
# STEP 6: Enable Audit Logging (Optional)
#   - Uncomment all audit_logger lines in decorators
#   - Uncomment audit_logger lines in secure functions
#   - Check audit.log file for access logs
#
# ============================================================
