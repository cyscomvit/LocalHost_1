"""
CTOP University - Academic Routes (VULNERABLE)
Intentionally vulnerable endpoints for CTF challenges

Vulnerabilities:
1. IDOR in grades - Can view any student's grades by changing student_id
2. IDOR in fees - Can view any student's fee records
3. IDOR in messages - Can read anyone's messages
4. SQL Injection in grade search
"""

from flask import Blueprint, request, jsonify, g
from auth import require_auth
from db_mysql import get_mysql_connection

academic_bp = Blueprint('academic', __name__)


# ============================================================================
# GRADES ENDPOINTS - IDOR Vulnerable
# ============================================================================

@academic_bp.route('/api/grades', methods=['GET'])
@require_auth
def get_grades():
    """
    Get student grades (IDOR VULNERABLE).
    
    VULNERABILITY: No authorization check - any logged-in user can view
    any student's grades by passing student_id parameter.
    
    Example Attack:
    - Login as Alice (student_id=2)
    - Request: GET /api/grades?student_id=3
    - Result: See Bob's grades!
    
    Exploit: /api/grades?student_id=1  (view admin's grades)
             /api/grades?student_id=2  (view Alice's grades)
             /api/grades?student_id=3  (view Bob's grades)
    """
    student_id = request.args.get('student_id', type=int)
    
    # INTENTIONALLY VULNERABLE: No check if g.user_id == student_id
    if not student_id:
        return jsonify({"error": "student_id parameter required"}), 400
    
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        
        # Query grades with course information
        query = """
            SELECT 
                g.id, g.grade, g.marks, g.semester,
                c.course_code, c.course_name, c.credits, c.professor,
                u.full_name as student_name, u.student_id as student_number
            FROM grades g
            JOIN courses c ON g.course_id = c.id
            JOIN users u ON g.student_id = u.id
            WHERE g.student_id = %s
            ORDER BY g.semester DESC, c.course_code
        """
        cursor.execute(query, (student_id,))
        grades = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "grades": grades,
            "total_courses": len(grades)
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@academic_bp.route('/api/grades/search', methods=['GET'])
@require_auth
def search_grades():
    """
    Search grades by course code (SQL INJECTION VULNERABLE).
    
    VULNERABILITY: User input concatenated directly into SQL query.
    
    Example Attack:
    - Normal: /api/grades/search?course=CS301
    - Attack: /api/grades/search?course=CS301' UNION SELECT id,secret_name,secret_value,1,1,1,1,1 FROM secrets--
    
    This allows extracting data from any table including 'secrets' table!
    """
    course = request.args.get('course', '')
    student_id = request.args.get('student_id', type=int)
    
    if not course:
        return jsonify({"error": "course parameter required"}), 400
    
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        
        # INTENTIONALLY VULNERABLE: String concatenation = SQL Injection
        query = f"""
            SELECT 
                g.id, g.grade, g.marks, g.semester,
                c.course_code, c.course_name,
                u.full_name as student_name
            FROM grades g
            JOIN courses c ON g.course_id = c.id
            JOIN users u ON g.student_id = u.id
            WHERE c.course_code LIKE '%{course}%'
        """
        
        if student_id:
            query += f" AND g.student_id = {student_id}"
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return jsonify({"results": results})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# FEES ENDPOINTS - IDOR Vulnerable
# ============================================================================

@academic_bp.route('/api/fees', methods=['GET'])
@require_auth
def get_fees():
    """
    Get student fee records (IDOR VULNERABLE).
    
    VULNERABILITY: No authorization check - any user can view
    any student's financial records.
    
    Example Attack:
    - Login as any student
    - Request: GET /api/fees?student_id=2
    - Result: See Alice's fee payment details, dues, etc.
    
    Exploit: /api/fees?student_id=1  (view admin records)
             /api/fees?student_id=2  (view Alice's fees - ₹95,000 paid)
             /api/fees?student_id=3  (view Bob's fees - ₹95,000 UNPAID)
    """
    student_id = request.args.get('student_id', type=int)
    
    # INTENTIONALLY VULNERABLE: No ownership verification
    if not student_id:
        return jsonify({"error": "student_id parameter required"}), 400
    
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        
        query = """
            SELECT 
                f.id, f.semester, f.tuition_fee, f.hostel_fee, 
                f.other_fees, f.total_amount, f.due_date, f.paid,
                u.full_name, u.student_id as student_number, u.program
            FROM fees f
            JOIN users u ON f.student_id = u.id
            WHERE f.student_id = %s
            ORDER BY f.semester DESC
        """
        cursor.execute(query, (student_id,))
        fees = cursor.fetchall()
        
        # Also get payment history
        query_payments = """
            SELECT 
                p.amount, p.payment_date, p.payment_method, p.transaction_id
            FROM payments p
            WHERE p.student_id = %s
            ORDER BY p.payment_date DESC
        """
        cursor.execute(query_payments, (student_id,))
        payments = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "fees": fees,
            "payments": payments,
            "total_records": len(fees)
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@academic_bp.route('/api/fees/<int:fee_id>', methods=['GET'])
@require_auth
def get_fee_detail(fee_id):
    """
    Get specific fee record by ID (IDOR VULNERABLE).
    
    VULNERABILITY: Direct access to fee records by sequential ID.
    
    Exploit: Just increment fee_id to see everyone's fees
             /api/fees/1, /api/fees/2, /api/fees/3, etc.
    """
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        
        # INTENTIONALLY VULNERABLE: No ownership check
        query = """
            SELECT 
                f.*, u.full_name, u.student_id as student_number,
                u.email, u.program
            FROM fees f
            JOIN users u ON f.student_id = u.id
            WHERE f.id = %s
        """
        cursor.execute(query, (fee_id,))
        fee = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        if not fee:
            return jsonify({"error": "Fee record not found"}), 404
        
        return jsonify(fee)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# MESSAGES ENDPOINTS - IDOR Vulnerable
# ============================================================================

@academic_bp.route('/api/messages', methods=['GET'])
@require_auth
def get_messages():
    """
    Get user messages (IDOR VULNERABLE).
    
    VULNERABILITY: Can view any user's messages by changing user_id.
    
    Example Attack:
    - Request: GET /api/messages?user_id=1
    - Result: Read admin's messages containing sensitive info
    
    Message #1 contains: "Database credentials: ctop_user / ctop_secure_2024"
    """
    user_id = request.args.get('user_id', type=int)
    
    # INTENTIONALLY VULNERABLE: No authorization check
    if not user_id:
        return jsonify({"error": "user_id parameter required"}), 400
    
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        
        # Get all messages where user is sender or recipient
        query = """
            SELECT 
                m.id, m.subject, m.content, m.timestamp, m.is_read,
                sender.full_name as sender_name, sender.username as sender_username,
                recipient.full_name as recipient_name, recipient.username as recipient_username
            FROM messages m
            JOIN users sender ON m.sender_id = sender.id
            JOIN users recipient ON m.recipient_id = recipient.id
            WHERE m.sender_id = %s OR m.recipient_id = %s
            ORDER BY m.timestamp DESC
        """
        cursor.execute(query, (user_id, user_id))
        messages = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "messages": messages,
            "total": len(messages)
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@academic_bp.route('/api/messages/<int:message_id>', methods=['GET'])
@require_auth
def get_message(message_id):
    """
    Get specific message by ID (IDOR VULNERABLE).
    
    VULNERABILITY: Sequential message IDs allow reading anyone's messages.
    
    Exploit: /api/messages/1 (admin message with credentials!)
             /api/messages/2, /api/messages/3, etc.
    """
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        
        # INTENTIONALLY VULNERABLE: No authorization check
        query = """
            SELECT 
                m.*, 
                sender.full_name as sender_name, sender.username as sender_username,
                recipient.full_name as recipient_name, recipient.username as recipient_username
            FROM messages m
            JOIN users sender ON m.sender_id = sender.id
            JOIN users recipient ON m.recipient_id = recipient.id
            WHERE m.id = %s
        """
        cursor.execute(query, (message_id,))
        message = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        if not message:
            return jsonify({"error": "Message not found"}), 404
        
        return jsonify(message)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# COURSES ENDPOINTS - Public (but can be used for enumeration)
# ============================================================================

@academic_bp.route('/api/courses', methods=['GET'])
@require_auth
def get_courses():
    """Get all available courses."""
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        
        query = """
            SELECT * FROM courses 
            ORDER BY semester, course_code
        """
        cursor.execute(query)
        courses = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "courses": courses,
            "total": len(courses)
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# STUDENT DIRECTORY ENDPOINT - REMOVED
# ============================================================================
# The student directory endpoint has been removed.
# To view student profiles, use the IDOR-vulnerable profile endpoints:
#   - /api/users/<user_id> - View any user's profile by ID
#   - /api/users/profile/mysql/<identifier> - View any MySQL user profile
# 
# This forces students to discover and exploit IDOR vulnerabilities
# rather than using a convenient directory listing.
