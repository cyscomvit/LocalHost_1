"""
TaskFlowr - User Routes
INTENTIONALLY INSECURE: IDOR, privilege escalation, data exposure.
"""

from flask import Blueprint, request, jsonify, g
from models import get_db
from auth import require_auth, require_role, hash_password_md5
from db_mysql import get_mysql_connection
import hashlib

user_bp = Blueprint('users', __name__)


@user_bp.route('/api/users', methods=['GET'])
@require_auth
def get_users():
    """Get all users.
    INTENTIONALLY INSECURE: Any authenticated user can list all users with sensitive data.
    TODO: Restrict to admin, exclude sensitive fields.
    """
    db = get_db()
    # INTENTIONALLY INSECURE: Returns password hashes and all fields
    # TODO: Exclude password, reset_token, session_token from response
    users = db.execute("SELECT * FROM users").fetchall()
    db.close()

    result = [dict(user) for user in users]
    return jsonify({"users": result})


@user_bp.route('/api/users/<int:user_id>', methods=['GET'])
@require_auth
def get_user(user_id):
    """Get a single user profile by ID.
    
    INTENTIONALLY INSECURE: IDOR (Insecure Direct Object Reference)
    
    VULNERABILITY: Any authenticated user can view ANY other user's profile
    by simply changing the user_id in the URL. No authorization check.
    
    EXPLOITATION EXAMPLES:
    - Your user_id: 5
    - View admin profile: GET /api/users/1
    - View Alice's profile: GET /api/users/2
    - View Bob's profile: GET /api/users/3
    - Enumerate all users: Loop through /api/users/1, /api/users/2, /api/users/3...
    
    EXPOSED DATA:
    - Full name, email, student ID
    - Role/privileges (is_admin)
    - Password hash (MD5 - easily crackable!)
    - All profile information
    
    PATCH STRATEGY:
    - Check if g.current_user['user_id'] == user_id OR user is admin
    - Never return password hash in API response
    - Log all profile access attempts
    """
    db = get_db()
    # INTENTIONALLY INSECURE: No authorization check
    # TODO: Check if requesting user is the same user or is admin
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    db.close()

    if not user:
        return jsonify({"error": "User not found"}), 404

    # INTENTIONALLY INSECURE: Returns password hash
    # TODO: Never return password hash in API response
    return jsonify({"user": dict(user)})


@user_bp.route('/api/users/<int:user_id>', methods=['PUT'])
@require_auth
def update_user(user_id):
    """Update user profile.
    INTENTIONALLY INSECURE: Horizontal and vertical privilege escalation.
    TODO: Users can only update their own profile, role changes require admin.
    """
    data = request.get_json()

    # INTENTIONALLY INSECURE: Any user can update any other user's profile
    # TODO: Verify g.current_user['user_id'] == user_id or user is admin

    # INTENTIONALLY INSECURE: Role can be changed by the user themselves
    # TODO: Only admins should be able to change roles
    new_role = data.get('role')
    new_email = data.get('email')
    new_username = data.get('username')
    new_is_admin = data.get('is_admin')
    new_department = data.get('department')

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if not user:
        db.close()
        return jsonify({"error": "User not found"}), 404

    # INTENTIONALLY INSECURE: Mass assignment - accepts ALL fields from client
    # TODO: Whitelist only safe fields (email, username, department)
    # TODO: Ignore role/is_admin unless requester is admin
    updates = []
    params = []

    if new_email:
        updates.append("email = ?")
        params.append(new_email)
    if new_username:
        updates.append("username = ?")
        params.append(new_username)
    if new_department:
        updates.append("department = ?")
        params.append(new_department)
    if new_role:
        # INTENTIONALLY INSECURE: Any user can set any role
        updates.append("role = ?")
        params.append(new_role)
    if new_is_admin is not None:
        # INTENTIONALLY INSECURE: Any user can make themselves admin
        updates.append("is_admin = ?")
        params.append(int(new_is_admin))

    if not updates:
        db.close()
        return jsonify({"error": "No fields to update"}), 400

    params.append(user_id)
    query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"

    db.execute(query, params)
    db.commit()
    db.close()

    return jsonify({"message": "User updated successfully"})


@user_bp.route('/api/users/<int:user_id>/change-password', methods=['POST'])
@require_auth
def change_password(user_id):
    """Change user password.
    INTENTIONALLY INSECURE: No old password verification, IDOR.
    TODO: Require old password, verify user identity, enforce complexity.
    """
    data = request.get_json()
    new_password = data.get('new_password', '')

    # INTENTIONALLY INSECURE: No old password verification
    # TODO: Require and verify old_password

    # INTENTIONALLY INSECURE: IDOR - any user can change any user's password
    # TODO: Verify g.current_user['user_id'] == user_id

    # INTENTIONALLY INSECURE: No password complexity check
    # TODO: Enforce password policy

    # INTENTIONALLY INSECURE: No password history check
    # TODO: Prevent reuse of last N passwords

    hashed = hash_password_md5(new_password)

    db = get_db()
    db.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, user_id))
    db.commit()
    db.close()

    return jsonify({"message": "Password changed successfully"})


@user_bp.route('/api/users/search', methods=['GET'])
@require_auth
def search_users():
    """Search users.
    INTENTIONALLY INSECURE: SQL Injection via search parameter.
    TODO: Use parameterized queries.
    """
    query_param = request.args.get('q', '')

    db = get_db()
    # INTENTIONALLY INSECURE: SQL Injection
    # TODO: Use parameterized query
    sql = f"SELECT id, username, email, role FROM users WHERE username LIKE '%{query_param}%' OR email LIKE '%{query_param}%'"

    try:
        users = db.execute(sql).fetchall()
        result = [dict(u) for u in users]
    except Exception as e:
        return jsonify({"error": f"Search failed: {str(e)}", "query": sql}), 500
    finally:
        db.close()

    return jsonify({"users": result})


@user_bp.route('/api/users/<int:user_id>/tasks', methods=['GET'])
@require_auth
def get_user_tasks(user_id):
    """Get tasks assigned to a user.
    INTENTIONALLY INSECURE: Cross-account data access.
    TODO: Verify requesting user has permission to view target user's tasks.
    """
    db = get_db()
    # INTENTIONALLY INSECURE: Any user can see any other user's tasks
    # TODO: Authorization check
    tasks = db.execute(
        "SELECT * FROM tasks WHERE assigned_to = ?", (user_id,)
    ).fetchall()
    db.close()

    return jsonify({"tasks": [dict(t) for t in tasks]})


@user_bp.route('/api/users/profile/mysql/<identifier>', methods=['GET'])
@require_auth
def get_mysql_profile(identifier):
    """
    Get user profile from MySQL database (CTOP University).
    Accepts either numeric user ID or student ID (e.g., "2024CSE001").
    
    INTENTIONALLY INSECURE: IDOR (Insecure Direct Object Reference)
    
    VULNERABILITY: Any authenticated user can view ANY CTOP University profile
    by changing the identifier in the URL. Works with both numeric IDs and
    student IDs, making enumeration extremely easy.
    
    EXPLOITATION EXAMPLES:
    - View by numeric ID: GET /api/users/profile/mysql/1
    - View by student ID: GET /api/users/profile/mysql/2024CSE001
    - Enumerate all: Loop through student IDs 2024CSE001, 2024CSE002...
    - Find admins: Check is_admin field in responses
    
    EXPOSED CTOP UNIVERSITY DATA:
    - Student ID (e.g., "2024CSE001")
    - Full name, email, username
    - Academic info: program, semester, CGPA
    - Admin status (is_admin)
    - Account creation date
    
    EXPLOITATION STRATEGY:
    1. Login as any user to get JWT token
    2. Try sequential IDs: /api/users/profile/mysql/1, /mysql/2, /mysql/3...
    3. Try student ID patterns: 2024CSE001, 2024CSE002, 2024EEE001...
    4. Find admins (is_admin: 1) for privilege escalation
    5. Collect all student emails for phishing campaigns
    6. Find top CGPA students for targeted attacks
    
    PATCH STRATEGY:
    - Check if g.current_user matches requested user OR is admin
    - Implement rate limiting to prevent mass enumeration
    - Log all profile access attempts with IP address
    - Never allow enumeration by student ID patterns
    """
    try:
        print(f"[DEBUG] Attempting to fetch profile for identifier: {identifier}")
        conn = get_mysql_connection()
        print("[DEBUG] MySQL connection established")
        cursor = conn.cursor()
        
        # INTENTIONALLY INSECURE: No authorization check
        # TODO: Verify g.current_user['user_id'] matches or is admin
        
        # Determine if identifier is numeric ID or student_id
        if identifier.isdigit():
            # Query by numeric ID
            query = """
                SELECT 
                    id, student_id, username, email, full_name,
                    program, semester, cgpa, is_admin, created_at
                FROM users 
                WHERE id = %s
            """
            cursor.execute(query, (int(identifier),))
        else:
            # INTENTIONALLY INSECURE: Allows enumeration by student ID
            # TODO: Remove ability to query by student_id, or implement strict authz
            query = """
                SELECT 
                    id, student_id, username, email, full_name,
                    program, semester, cgpa, is_admin, created_at
                FROM users 
                WHERE student_id = %s
            """
            cursor.execute(query, (identifier,))
        
        user = cursor.fetchone()
        print(f"[DEBUG] Query result: {user}")
        
        cursor.close()
        conn.close()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # INTENTIONALLY INSECURE: Returns sensitive academic and admin data
        # TODO: Filter sensitive fields based on user's permissions
        return jsonify({"user": user})
        
    except Exception as e:
        print(f"[ERROR] MySQL profile fetch failed: {str(e)}")
        print(f"[ERROR] Exception type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "error": "Failed to fetch profile from MySQL",
            "details": str(e),
            "type": type(e).__name__
        }), 500


@user_bp.route('/api/users/profile/mysql/<identifier>', methods=['PUT'])
@require_auth
def update_mysql_profile(identifier):
    """
    Update user profile in MySQL database.
    Accepts either numeric user ID or student ID (e.g., "2024CSE001").
    
    INTENTIONALLY INSECURE: IDOR + privilege escalation.
    TODO: Users should only update their own profile, admin flag changes require admin role.
    """
    data = request.get_json()
    
    # INTENTIONALLY INSECURE: No authorization check
    # TODO: Verify g.current_user['user_id'] == user_id or user is admin
    
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        
        # Determine if identifier is numeric ID or student_id
        if identifier.isdigit():
            cursor.execute("SELECT id FROM users WHERE id = %s", (int(identifier),))
            where_clause = "id = %s"
            where_param = int(identifier)
        else:
            cursor.execute("SELECT id FROM users WHERE student_id = %s", (identifier,))
            where_clause = "student_id = %s"
            where_param = identifier
        
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({"error": "User not found"}), 404
        
        # Build update query dynamically (INTENTIONALLY INSECURE)
        updates = []
        params = []
        
        if 'email' in data:
            updates.append("email = %s")
            params.append(data['email'])
        
        if 'full_name' in data:
            updates.append("full_name = %s")
            params.append(data['full_name'])
        
        if 'program' in data:
            updates.append("program = %s")
            params.append(data['program'])
        
        if 'semester' in data:
            updates.append("semester = %s")
            params.append(data['semester'])
        
        # INTENTIONALLY INSECURE: Allow users to change their own admin status
        if 'is_admin' in data:
            updates.append("is_admin = %s")
            params.append(data['is_admin'])
        
        if not updates:
            cursor.close()
            conn.close()
            return jsonify({"error": "No fields to update"}), 400
        
        params.append(where_param)
        query = f"UPDATE users SET {', '.join(updates)} WHERE {where_clause}"
        
        cursor.execute(query, params)
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({"message": "Profile updated successfully"})
        
    except Exception as e:
        return jsonify({
            "error": "Failed to update profile",
            "details": str(e)
        }), 500
