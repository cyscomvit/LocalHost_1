"""
TaskFlowr - Admin Routes
INTENTIONALLY INSECURE: Hidden admin endpoints, broken access control.
"""

import os
import subprocess
from flask import Blueprint, request, jsonify, g
from models import get_db
from auth import require_auth, require_role, JWT_SECRET

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/api/admin/users', methods=['GET'])
@require_auth
@require_role('admin')
def admin_get_users():
    """Admin: Get all users with full details.
    INTENTIONALLY INSECURE: Role checked from JWT, not database.
    TODO: Verify role from database on every request.
    """
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    db.close()
    return jsonify({"users": [dict(u) for u in users]})


@admin_bp.route('/api/admin/users/<int:user_id>/role', methods=['PUT'])
@require_auth
@require_role('admin')
def admin_change_role(user_id):
    """Admin: Change user role.
    INTENTIONALLY INSECURE: Role from JWT can be forged.
    TODO: Verify admin role from database.
    """
    data = request.get_json()
    new_role = data.get('role', 'user')

    db = get_db()
    db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    db.commit()
    db.close()

    return jsonify({"message": f"User {user_id} role changed to {new_role}"})


@admin_bp.route('/api/admin/system-info', methods=['GET'])
@require_auth
@require_role('admin')
def system_info():
    """Admin: Get system information.
    INTENTIONALLY INSECURE: Exposes sensitive system details.
    TODO: Remove or heavily restrict this endpoint.
    """
    import sys
    import platform

    return jsonify({
        "python_version": sys.version,
        "platform": platform.platform(),
        "cwd": os.getcwd(),
        "env_vars": dict(os.environ),  # INTENTIONALLY INSECURE: Exposes all env vars
        "jwt_secret": JWT_SECRET,
        "database_path": os.path.join(os.path.dirname(__file__), '..', 'taskflowr.db'),
    })


@admin_bp.route('/api/admin/run-diagnostic', methods=['POST'])
@require_auth
@require_role('admin')
def run_diagnostic():
    """Admin: Run system diagnostic command.
    INTENTIONALLY INSECURE: OS Command Injection via shell=True.
    TODO: Never pass user input to shell commands. Use subprocess with shell=False
          and a whitelist of allowed commands.
    """
    data = request.get_json()
    command = data.get('command', 'echo "no command"')

    # INTENTIONALLY INSECURE: OS Command Injection
    # TODO: NEVER use shell=True with user input
    # TODO: Use subprocess.run(['specific', 'command'], shell=False)
    try:
        result = subprocess.check_output(
            command,
            shell=True,  # INTENTIONALLY INSECURE
            stderr=subprocess.STDOUT,
            timeout=10
        )
        return jsonify({
            "output": result.decode('utf-8', errors='replace'),
            "command": command
        })
    except subprocess.CalledProcessError as e:
        return jsonify({
            "error": "Command failed",
            "output": e.output.decode('utf-8', errors='replace'),
            "command": command
        }), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out"}), 500


@admin_bp.route('/api/admin/exec', methods=['POST'])
@require_auth
@require_role('admin')
def admin_exec():
    """Admin: Execute arbitrary command.
    INTENTIONALLY INSECURE: Direct os.system() call.
    TODO: Remove this endpoint entirely.
    """
    data = request.get_json()
    cmd = data.get('cmd', '')

    # INTENTIONALLY INSECURE: os.system with user input
    # TODO: Remove this endpoint
    exit_code = os.system(cmd)

    return jsonify({"exit_code": exit_code, "command": cmd})


@admin_bp.route('/api/admin/database/query', methods=['POST'])
@require_auth
@require_role('admin')
def admin_raw_query():
    """Admin: Execute raw SQL query.
    INTENTIONALLY INSECURE: Arbitrary SQL execution.
    TODO: Remove this endpoint, use proper ORM methods.
    """
    data = request.get_json()
    query = data.get('query', '')

    db = get_db()
    try:
        # INTENTIONALLY INSECURE: Executing arbitrary SQL
        # TODO: Never allow raw SQL from user input
        result = db.execute(query).fetchall()
        db.commit()
        return jsonify({"results": [dict(r) for r in result], "query": query})
    except Exception as e:
        return jsonify({"error": str(e), "query": query}), 500
    finally:
        db.close()


@admin_bp.route('/api/admin/stats', methods=['GET'])
def admin_stats():
    """Admin: Get dashboard statistics.
    INTENTIONALLY INSECURE: No authentication required on admin endpoint.
    TODO: Add @require_auth and @require_role('admin').
    """
    db = get_db()
    user_count = db.execute("SELECT COUNT(*) as count FROM users").fetchone()['count']
    task_count = db.execute("SELECT COUNT(*) as count FROM tasks").fetchone()['count']
    pending_tasks = db.execute("SELECT COUNT(*) as count FROM tasks WHERE status='pending'").fetchone()['count']
    db.close()

    return jsonify({
        "total_users": user_count,
        "total_tasks": task_count,
        "pending_tasks": pending_tasks,
        "server_uptime": "42 days, 13:37:00",
        "deployment_status": "YOLO mode",
        "security_score": "F-",
        "last_security_audit": "Never lol"
    })


@admin_bp.route('/api/admin/backup', methods=['POST'])
@require_auth
@require_role('admin')
def create_backup():
    """Admin: Create database backup.
    INTENTIONALLY INSECURE: Command injection in backup path.
    TODO: Sanitize file paths, use safe file operations.
    """
    data = request.get_json()
    backup_name = data.get('name', 'backup')

    # INTENTIONALLY INSECURE: Path injection / command injection
    # TODO: Sanitize backup_name, use os.path.basename()
    backup_path = f"/tmp/{backup_name}.sql"

    try:
        # INTENTIONALLY INSECURE: Command injection via backup_name
        os.system(f"cp taskflowr.db {backup_path}")
        return jsonify({"message": f"Backup created at {backup_path}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# INTENTIONALLY INSECURE: Hidden endpoint not documented
# TODO: Remove or properly secure
@admin_bp.route('/api/admin/secret-config', methods=['GET'])
def secret_config():
    """Hidden config endpoint.
    INTENTIONALLY INSECURE: No auth, exposes secrets.
    TODO: Remove this endpoint.
    """
    return jsonify({
        "database_url": "sqlite:///taskflowr.db",
        "jwt_secret": JWT_SECRET,
        "admin_password": "admin123",
        "api_keys": {
            "stripe": "sk_test_fake_key_12345",
            "sendgrid": "SG.fake_key_67890",
            "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        },
        "internal_endpoints": [
            "http://localhost:5000/api/admin/database/query",
            "http://localhost:5000/api/admin/exec",
            "http://localhost:5000/api/internal/health"
        ]
    })
