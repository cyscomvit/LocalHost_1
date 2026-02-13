"""
Broken Access Control Vulnerabilities
Users can access resources they shouldn't have permission to access
"""

from flask import Blueprint, request, jsonify, g
from auth import require_auth
from db_mysql import get_mysql_connection

broken_access_bp = Blueprint('broken_access', __name__)


@broken_access_bp.route('/api/broken-access/user/<int:user_id>/profile', methods=['GET'])
@require_auth
def get_user_profile(user_id):
    """
    Any authenticated user can view any other user's profile.
    Missing authorization check - should verify user owns the profile or is admin.
    """
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, full_name, student_id, program, semester, cgpa, is_admin FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        if isinstance(user, dict):
            user_dict = {
                "id": user.get('id'),
                "username": user.get('username'),
                "email": user.get('email'),
                "full_name": user.get('full_name'),
                "student_id": user.get('student_id'),
                "program": user.get('program'),
                "semester": user.get('semester'),
                "cgpa": float(user.get('cgpa')) if user.get('cgpa') else None,
                "is_admin": bool(user.get('is_admin')),
                "role": "admin" if user.get('is_admin') else "student"
            }
        else:
            # Fallback for tuple format
            user_dict = {
                "id": user[0],
                "username": user[1],
                "email": user[2],
                "full_name": user[3],
                "student_id": user[4],
                "program": user[5],
                "semester": user[6],
                "cgpa": float(user[7]) if user[7] else None,
                "is_admin": bool(user[8]),
                "role": "admin" if user[8] else "student"
            }
        
        return jsonify({
            "user": user_dict
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@broken_access_bp.route('/api/broken-access/admin/users', methods=['GET'])
def list_all_users():
    """
    Admin endpoint accessible without any authentication.
    Missing @require_auth decorator and admin role check.
    """
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, full_name, student_id, program, semester, cgpa, is_admin FROM users")
        users = cursor.fetchall()
        cursor.close()
        conn.close()
        
        users_list = []
        for user in users:
            if isinstance(user, dict):
                users_list.append({
                    "id": user.get('id'),
                    "username": user.get('username'),
                    "email": user.get('email'),
                    "full_name": user.get('full_name'),
                    "student_id": user.get('student_id'),
                    "program": user.get('program'),
                    "semester": user.get('semester'),
                    "cgpa": float(user.get('cgpa')) if user.get('cgpa') else None,
                    "is_admin": bool(user.get('is_admin')),
                    "role": "admin" if user.get('is_admin') else "student"
                })
            else:
                # Fallback for tuple format
                users_list.append({
                    "id": user[0],
                    "username": user[1],
                    "email": user[2],
                    "full_name": user[3],
                    "student_id": user[4],
                    "program": user[5],
                    "semester": user[6],
                    "cgpa": float(user[7]) if user[7] else None,
                    "is_admin": bool(user[8]),
                    "role": "admin" if user[8] else "student"
                })
        
        return jsonify({
            "users": users_list,
            "total": len(users_list)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

