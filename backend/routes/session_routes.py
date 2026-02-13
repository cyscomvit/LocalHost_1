"""
CTOP University - Session Hijacking Demo Routes
Demonstrates session fixation, hijacking, and token reuse vulnerabilities
"""

from flask import Blueprint, request, jsonify
from auth_production import TokenManager, config
from session_manager import session_service
import json
import time
from datetime import datetime, timezone

session_bp = Blueprint('session', __name__)

# In-memory session store (vulnerable: no persistence, no cleanup)
active_sessions = {}


@session_bp.route('/api/session/create', methods=['POST'])
def create_session():
    """Create a session after login.
    INTENTIONALLY VULNERABLE: Accepts client-provided session_id (session fixation).
    """
    data = request.get_json(silent=True) or {}

    # Vulnerable: Accept session_id from client
    client_session_id = data.get('session_id') or request.args.get('session_id')

    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        token = request.cookies.get('access_token')

    user_data = None
    if token:
        user_data = TokenManager.verify_token(token)

    if not user_data or user_data.get('error'):
        return jsonify({"error": "Invalid token", "code": "INVALID_TOKEN"}), 401

    # Vulnerable: Use client-provided session ID if given (session fixation)
    if client_session_id:
        session_id = client_session_id
        print(f"[SESSION FIXATION] Using client-provided session ID: {session_id}")
    else:
        import uuid
        session_id = str(uuid.uuid4())

    session_data = {
        'session_id': session_id,
        'user_id': user_data.get('user_id'),
        'username': user_data.get('username'),
        'email': user_data.get('email'),
        'role': user_data.get('role', 'student'),
        'ip_address': request.environ.get('REMOTE_ADDR'),
        'user_agent': request.headers.get('User-Agent', ''),
        'created_at': datetime.now(timezone.utc).isoformat(),
        'is_active': True
    }

    active_sessions[session_id] = session_data

    response = jsonify({
        "message": "Session created",
        "session_id": session_id,
        "user": user_data.get('username'),
        "fixated": bool(client_session_id)
    })

    # Vulnerable: No HttpOnly, no Secure, no SameSite
    response.set_cookie('session_id', session_id, httponly=False, secure=False, samesite=None)

    return response


@session_bp.route('/api/session/validate', methods=['GET'])
def validate_session():
    """Validate a session.
    INTENTIONALLY VULNERABLE:
    - Accepts session_id from URL params, headers, or cookies
    - No IP or User-Agent validation (hijacking)
    - Returns full session data (information disclosure)
    """
    # Vulnerable: Multiple session sources
    session_id = request.args.get('session_id') or \
                 request.headers.get('X-Session-ID') or \
                 request.cookies.get('session_id')

    if not session_id:
        return jsonify({"error": "Session ID required", "code": "MISSING_SESSION"}), 400

    session_data = active_sessions.get(session_id)

    if not session_data:
        # Fallback: try JWT token validation (vulnerable)
        token = request.headers.get('Authorization', '').replace('Bearer ', '') or \
                request.cookies.get('access_token')
        if token:
            payload = TokenManager.verify_token(token)
            if payload and not payload.get('error'):
                return jsonify({
                    "valid": True,
                    "session_id": session_id,
                    "user": payload.get('username'),
                    "role": payload.get('role'),
                    "source": "jwt_fallback",
                    "vulnerability": "Session validated via JWT - no proper session store"
                })

        return jsonify({"error": "Invalid session", "code": "INVALID_SESSION"}), 401

    # Vulnerable: No IP/User-Agent check - allows hijacking
    original_ip = session_data.get('ip_address')
    current_ip = request.environ.get('REMOTE_ADDR')
    original_ua = session_data.get('user_agent')
    current_ua = request.headers.get('User-Agent', '')

    return jsonify({
        "valid": True,
        "session_data": session_data,
        "hijack_detection": {
            "ip_match": original_ip == current_ip,
            "ua_match": original_ua == current_ua,
            "original_ip": original_ip,
            "current_ip": current_ip,
            "blocked": False,
            "vulnerability": "No IP or User-Agent validation - session hijacking possible"
        }
    })


@session_bp.route('/api/session/hijack-test', methods=['GET'])
def hijack_test():
    """Test session hijacking by accessing data with a stolen session ID.
    INTENTIONALLY VULNERABLE: Demonstrates session hijacking.
    """
    # Vulnerable: Accept session from any source
    session_id = request.args.get('session_id') or \
                 request.headers.get('X-Session-ID') or \
                 request.cookies.get('session_id')

    if not session_id:
        return jsonify({
            "error": "Provide a session_id parameter to test hijacking",
            "example": "/api/session/hijack-test?session_id=STOLEN_SESSION_ID",
            "active_sessions": len(active_sessions)
        }), 400

    session_data = active_sessions.get(session_id)

    if session_data:
        # Vulnerable: Returns sensitive data without verifying requester
        return jsonify({
            "hijack_successful": True,
            "message": "Session hijacked! You accessed another user's session.",
            "stolen_data": {
                "username": session_data.get('username'),
                "email": session_data.get('email'),
                "role": session_data.get('role'),
                "user_id": session_data.get('user_id'),
                "session_id": session_id
            },
            "vulnerability": "No IP/User-Agent binding - any client with session_id gets access"
        })

    return jsonify({
        "hijack_successful": False,
        "message": "Session not found",
        "active_sessions": len(active_sessions)
    }), 404


@session_bp.route('/api/session/token-reuse', methods=['GET'])
def token_reuse_test():
    """Test JWT token reuse after logout.
    INTENTIONALLY VULNERABLE: Tokens are not invalidated on logout.
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '') or \
            request.args.get('token') or \
            request.cookies.get('access_token')

    if not token:
        return jsonify({
            "error": "Provide a JWT token to test reuse",
            "example": "Add Authorization: Bearer <token> header"
        }), 400

    payload = TokenManager.verify_token(token)

    if payload and not payload.get('error'):
        return jsonify({
            "token_reuse_successful": True,
            "message": "Token still valid after logout! No server-side invalidation.",
            "user_data": {
                "username": payload.get('username'),
                "email": payload.get('email'),
                "role": payload.get('role'),
                "user_id": payload.get('user_id'),
                "session_id": payload.get('session_id')
            },
            "token_info": {
                "issued_at": payload.get('iat'),
                "expires_at": payload.get('exp'),
                "algorithm": "HS256",
                "jti": payload.get('jti')
            },
            "vulnerability": "JWT tokens not revoked on logout - can be reused indefinitely until expiry"
        })

    return jsonify({
        "token_reuse_successful": False,
        "message": "Token is invalid or expired",
        "error": payload.get('error') if payload else "Decode failed"
    }), 401


@session_bp.route('/api/session/list', methods=['GET'])
def list_sessions():
    """List all active sessions.
    INTENTIONALLY VULNERABLE: Exposes all session data without auth.
    """
    sessions = []
    for sid, data in active_sessions.items():
        sessions.append({
            "session_id": sid,
            "username": data.get('username'),
            "role": data.get('role'),
            "ip_address": data.get('ip_address'),
            "created_at": data.get('created_at')
        })

    return jsonify({
        "active_sessions": sessions,
        "total": len(sessions),
        "vulnerability": "Session list exposed without authentication"
    })
