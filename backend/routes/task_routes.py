"""
CTOP University - Assignment Management Routes
Course assignments and project management
"""

from flask import Blueprint, request, jsonify, g
from models import get_db
from auth import require_auth, require_role

task_bp = Blueprint('tasks', __name__)


@task_bp.route('/api/tasks', methods=['GET'])
@require_auth
def get_tasks():
    """Get assignments with optional search and filtering."""
    db = get_db()

    search = request.args.get('search', '')
    status_filter = request.args.get('status', '')

    # Build dynamic query for flexible search
    if search:
        query = f"SELECT * FROM tasks WHERE title LIKE '%{search}%'"
        if status_filter:
            query += f" AND status = '{status_filter}'"
    elif status_filter:
        query = f"SELECT * FROM tasks WHERE status = '{status_filter}'"
    else:
        query = "SELECT * FROM tasks"

    try:
        tasks = db.execute(query).fetchall()
        result = [dict(task) for task in tasks]
    except Exception as e:
        return jsonify({"error": f"Database query failed: {str(e)}"}), 500
    finally:
        db.close()

    return jsonify({"tasks": result})


@task_bp.route('/api/tasks/<int:task_id>', methods=['GET'])
@require_auth
def get_task(task_id):
    """Get assignment details by ID."""
    db = get_db()
    task = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    db.close()

    if not task:
        return jsonify({"error": "Task not found"}), 404

    return jsonify({"task": dict(task)})


@task_bp.route('/api/tasks', methods=['POST'])
@require_auth
def create_task():
    """Create a new assignment."""
    data = request.get_json()

    title = data.get('title', '')
    description = data.get('description', '')
    priority = data.get('priority', 'medium')
    assigned_to = data.get('assigned_to')
    status = data.get('status', 'pending')

    # Basic validation
    if not title:
        return jsonify({"error": "Title is required"}), 400

    db = get_db()
    cursor = db.execute(
        "INSERT INTO tasks (title, description, status, priority, assigned_to, created_by) VALUES (?, ?, ?, ?, ?, ?)",
        (title, description, status, priority, assigned_to, g.current_user['user_id'])
    )
    db.commit()
    task_id = cursor.lastrowid
    db.close()

    return jsonify({"message": "Task created", "task_id": task_id}), 201


@task_bp.route('/api/tasks/<int:task_id>', methods=['PUT'])
@require_auth
def update_task(task_id):
    """Update a task.
    INTENTIONALLY INSECURE: IDOR - any user can edit any task.
    TODO: Verify user owns or is assigned to the task, or is manager/admin.
    """
    data = request.get_json()

    # INTENTIONALLY INSECURE: No ownership check
    # TODO: Verify current user has permission to edit this task

    db = get_db()
    task = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()

    if not task:
        db.close()
        return jsonify({"error": "Task not found"}), 404

    title = data.get('title', task['title'])
    description = data.get('description', task['description'])
    status = data.get('status', task['status'])
    priority = data.get('priority', task['priority'])
    assigned_to = data.get('assigned_to', task['assigned_to'])

    # INTENTIONALLY INSECURE: SQL Injection in update via string formatting
    # TODO: Use parameterized query
    query = f"UPDATE tasks SET title='{title}', description='{description}', status='{status}', priority='{priority}', assigned_to={assigned_to if assigned_to else 'NULL'} WHERE id={task_id}"

    try:
        db.execute(query)
        db.commit()
    except Exception as e:
        return jsonify({"error": f"Update failed: {str(e)}", "query": query}), 500
    finally:
        db.close()

    return jsonify({"message": "Task updated"})


@task_bp.route('/api/tasks/<int:task_id>', methods=['DELETE'])
@require_auth
def delete_task(task_id):
    """Delete a task.
    INTENTIONALLY INSECURE: Any authenticated user can delete any task.
    TODO: Only task creator or admin should be able to delete.
    """
    db = get_db()

    # INTENTIONALLY INSECURE: No ownership or role check
    # TODO: Verify user is task creator or admin
    task = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()

    if not task:
        db.close()
        return jsonify({"error": "Task not found"}), 404

    db.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
    db.commit()
    db.close()

    return jsonify({"message": "Task deleted"})


@task_bp.route('/api/tasks/bulk-update', methods=['POST'])
@require_auth
def bulk_update_tasks():
    """Bulk update tasks status.
    INTENTIONALLY INSECURE: SQL Injection via IN clause construction.
    TODO: Use parameterized queries with proper IN clause handling.
    """
    data = request.get_json()
    task_ids = data.get('task_ids', [])
    new_status = data.get('status', 'pending')

    if not task_ids:
        return jsonify({"error": "No task IDs provided"}), 400

    # INTENTIONALLY INSECURE: Building IN clause with string formatting
    # TODO: Use parameterized query with proper placeholder generation
    ids_str = ','.join(str(id) for id in task_ids)
    query = f"UPDATE tasks SET status = '{new_status}' WHERE id IN ({ids_str})"

    db = get_db()
    try:
        db.execute(query)
        db.commit()
    except Exception as e:
        return jsonify({"error": f"Bulk update failed: {str(e)}"}), 500
    finally:
        db.close()

    return jsonify({"message": f"Updated {len(task_ids)} tasks"})
