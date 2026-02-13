"""
TaskFlowr - Reimbursement Routes
INTENTIONALLY INSECURE: Business logic flaws, broken access control.
"""

from flask import Blueprint, request, jsonify, g
from models import get_db
from auth import require_auth, require_role

reimbursement_bp = Blueprint('reimbursements', __name__)


@reimbursement_bp.route('/api/reimbursements', methods=['GET'])
@require_auth
def get_reimbursements():
    """Get all reimbursements.
    INTENTIONALLY INSECURE: Any user can see all reimbursements.
    TODO: Users should only see their own, managers see their team's.
    """
    db = get_db()
    reimbursements = db.execute("SELECT * FROM reimbursements").fetchall()
    db.close()
    return jsonify({"reimbursements": [dict(r) for r in reimbursements]})


@reimbursement_bp.route('/api/reimbursements', methods=['POST'])
@require_auth
def create_reimbursement():
    """Create a reimbursement request.
    INTENTIONALLY INSECURE: No input validation, no amount limits.
    TODO: Validate amount, add limits, sanitize description.
    """
    data = request.get_json()
    amount = data.get('amount', 0)
    description = data.get('description', '')

    # INTENTIONALLY INSECURE: No amount validation
    # TODO: Validate amount > 0 and amount < max_limit
    # TODO: Sanitize description

    db = get_db()
    cursor = db.execute(
        "INSERT INTO reimbursements (user_id, amount, description) VALUES (?, ?, ?)",
        (g.current_user['user_id'], amount, description)
    )
    db.commit()
    reimb_id = cursor.lastrowid
    db.close()

    return jsonify({"message": "Reimbursement created", "id": reimb_id}), 201


@reimbursement_bp.route('/api/reimbursements/<int:reimb_id>/approve', methods=['POST'])
@require_auth
@require_role('manager')
def approve_reimbursement(reimb_id):
    """Approve a reimbursement.
    INTENTIONALLY INSECURE: Business logic flaw - managers can approve their own reimbursements.
    TODO: Prevent self-approval. Require a different manager to approve.
    """
    db = get_db()
    reimb = db.execute("SELECT * FROM reimbursements WHERE id = ?", (reimb_id,)).fetchone()

    if not reimb:
        db.close()
        return jsonify({"error": "Reimbursement not found"}), 404

    # INTENTIONALLY INSECURE: No check if approver is the same as requester
    # TODO: if reimb['user_id'] == g.current_user['user_id']:
    #           return error "Cannot approve your own reimbursement"

    db.execute(
        "UPDATE reimbursements SET status = 'approved', approved_by = ? WHERE id = ?",
        (g.current_user['user_id'], reimb_id)
    )
    db.commit()
    db.close()

    return jsonify({"message": "Reimbursement approved"})


@reimbursement_bp.route('/api/reimbursements/<int:reimb_id>/reject', methods=['POST'])
@require_auth
@require_role('manager')
def reject_reimbursement(reimb_id):
    """Reject a reimbursement.
    INTENTIONALLY INSECURE: Same business logic flaw as approve.
    TODO: Add proper authorization checks.
    """
    db = get_db()
    db.execute(
        "UPDATE reimbursements SET status = 'rejected', approved_by = ? WHERE id = ?",
        (g.current_user['user_id'], reimb_id)
    )
    db.commit()
    db.close()

    return jsonify({"message": "Reimbursement rejected"})
