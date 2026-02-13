"""
TaskFlowr - CTF GameServer Routes
INTENTIONALLY INSECURE: Vulnerable endpoints for CTF challenges.

This file implements 4 major vulnerabilities by calling the GameServer API:
1. SQL Injection (secrets table)
2. SQL Truncation Attack (users table)  
3. IDOR - Insecure Direct Object Reference (messages table)
4. Race Condition (coupons table)

⚠️ WARNING: These routes are intentionally vulnerable for educational purposes.
DO NOT use this code in production!
"""

from flask import Blueprint, request, jsonify, g
import requests
import os
from auth import require_auth

ctf_bp = Blueprint('ctf', __name__)

# GameServer API URL from environment
GAMESERVER_API_URL = os.getenv('GAMESERVER_API_URL', 'http://localhost:5001')


# ============================================================
# CONNECTION TEST ENDPOINT
# ============================================================

@ctf_bp.route('/api/ctf/test-connection', methods=['GET'])
def test_gameserver_connection():
    """Test connection to GameServer API.
    
    Returns connection status and server info.
    """
    try:
        response = requests.get(f"{GAMESERVER_API_URL}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return jsonify({
                "status": "connected",
                "gameserver_url": GAMESERVER_API_URL,
                "server_status": data.get('status'),
                "service": data.get('service'),
                "last_reset": data.get('last_reset')
            })
        else:
            return jsonify({
                "status": "error",
                "gameserver_url": GAMESERVER_API_URL,
                "http_code": response.status_code
            }), 500
    except requests.exceptions.RequestException as e:
        return jsonify({
            "status": "failed",
            "gameserver_url": GAMESERVER_API_URL,
            "error": str(e)
        }), 500


# ============================================================
# VULNERABILITY #1: SQL INJECTION
# Target: secrets table
# ============================================================

@ctf_bp.route('/api/ctf/search-secrets', methods=['GET'])
def search_secrets():
    """
    Search secrets by keyword.
    
    INTENTIONALLY VULNERABLE: SQL INJECTION
    
    The search_term parameter is passed to GameServer which concatenates it
    into SQL query without sanitization, allowing SQL injection.
    
    Attack Examples:
        ?search_term=' OR '1'='1
        ?search_term=' UNION SELECT secret_value FROM secrets --
        ?search_term=' UNION SELECT username, password FROM users --
    """
    search_term = request.args.get('search_term', '')
    
    if not search_term:
        return jsonify({"error": "search_term parameter required"}), 400
    
    try:
        response = requests.get(
            f"{GAMESERVER_API_URL}/api/search-secrets",
            params={"search_term": search_term},
            timeout=10
        )
        
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify(response.json()), response.status_code
            
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Failed to connect to GameServer", "details": str(e)}), 500


# ============================================================
# VULNERABILITY #2: SQL TRUNCATION ATTACK  
# Target: users table (20 character username limit)
# ============================================================

@ctf_bp.route('/api/ctf/register-truncate', methods=['POST'])
def register_with_truncation():
    """
    Register a user (demonstrates SQL truncation attack).
    
    INTENTIONALLY VULNERABLE: SQL TRUNCATION ATTACK
    
    The users table has a 20-character limit on usernames.
    MySQL with sql_mode='' truncates longer strings.
    
    Attack Example:
        POST {"username": "admin               x", "password": "hacked123"}
        MySQL truncates to "admin" and allows duplicate admin account creation.
    """
    data = request.get_json()
    
    try:
        response = requests.post(
            f"{GAMESERVER_API_URL}/api/register",
            json=data,
            timeout=10
        )
        
        if response.status_code == 201:
            return jsonify(response.json()), 201
        else:
            return jsonify(response.json()), response.status_code
            
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Failed to connect to GameServer", "details": str(e)}), 500


@ctf_bp.route('/api/ctf/login-gameserver', methods=['POST'])
def login_gameserver():
    """
    Login using GameServer database credentials.
    
    This endpoint authenticates against the GameServer users table.
    """
    data = request.get_json()
    
    try:
        response = requests.post(
            f"{GAMESERVER_API_URL}/api/login",
            json=data,
            timeout=10
        )
        
        return jsonify(response.json()), response.status_code
            
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Failed to connect to GameServer", "details": str(e)}), 500


# ============================================================
# VULNERABILITY #3: IDOR (Insecure Direct Object Reference)
# Target: messages table
# ============================================================

@ctf_bp.route('/api/ctf/messages/<int:message_id>', methods=['GET'])
def get_message_by_id(message_id):
    """
    Get a message by ID.
    
    INTENTIONALLY VULNERABLE: IDOR (Insecure Direct Object Reference)
    
    Any user can access any message by guessing/incrementing the ID.
    GameServer performs no authorization check.
    
    Attack Example:
        GET /api/ctf/messages/1
        GET /api/ctf/messages/2
        GET /api/ctf/messages/3
        ... enumerate all messages
    """
    try:
        response = requests.get(
            f"{GAMESERVER_API_URL}/api/messages/{message_id}",
            timeout=10
        )
        
        return jsonify(response.json()), response.status_code
            
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Failed to connect to GameServer", "details": str(e)}), 500


@ctf_bp.route('/api/ctf/messages', methods=['GET'])
def list_all_messages():
    """
    List all messages (another IDOR variant - mass data exposure).
    
    INTENTIONALLY VULNERABLE: Any user can see all messages.
    """
    try:
        response = requests.get(
            f"{GAMESERVER_API_URL}/api/messages",
            timeout=10
        )
        
        return jsonify(response.json()), response.status_code
            
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Failed to connect to GameServer", "details": str(e)}), 500


# ============================================================
# VULNERABILITY #4: RACE CONDITION
# Target: coupons table
# ============================================================

@ctf_bp.route('/api/ctf/coupons/<coupon_code>/redeem', methods=['POST'])
def redeem_coupon(coupon_code):
    """
    Redeem a coupon code.
    
    INTENTIONALLY VULNERABLE: RACE CONDITION
    
    The GameServer performs non-atomic check-then-update:
    1. Check if current_uses < max_uses
    2. Increment current_uses
    
    Multiple concurrent requests can pass the check before any update,
    allowing the coupon to be redeemed more times than max_uses.
    
    Attack Example:
        # Send 10 concurrent requests
        for i in range(10):
            threading.Thread(target=redeem_coupon, args=('LIMITEDEDITION',)).start()
    """
    data = request.get_json() or {}
    
    try:
        response = requests.post(
            f"{GAMESERVER_API_URL}/api/coupons/{coupon_code}/redeem",
            json=data,
            timeout=10
        )
        
        return jsonify(response.json()), response.status_code
            
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Failed to connect to GameServer", "details": str(e)}), 500


@ctf_bp.route('/api/ctf/coupons', methods=['GET'])
def list_coupons():
    """List all available coupons."""
    try:
        response = requests.get(
            f"{GAMESERVER_API_URL}/api/coupons",
            timeout=10
        )
        
        return jsonify(response.json()), response.status_code
            
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Failed to connect to GameServer", "details": str(e)}), 500


# ============================================================
# HELPER ENDPOINTS FOR CTF
# ============================================================

@ctf_bp.route('/api/ctf/info', methods=['GET'])
def database_info():
    """Get database schema and statistics from GameServer."""
    try:
        response = requests.get(
            f"{GAMESERVER_API_URL}/api/info",
            timeout=10
        )
        
        return jsonify(response.json()), response.status_code
            
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Failed to connect to GameServer", "details": str(e)}), 500


@ctf_bp.route('/api/ctf/reset-status', methods=['GET'])
def reset_status():
    """Check when the database was last reset."""
    try:
        response = requests.get(
            f"{GAMESERVER_API_URL}/health",
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            return jsonify({
                "message": "Database auto-resets every 15 minutes",
                "service": data.get('service'),
                "last_reset": data.get('last_reset'),
                "reset_count": data.get('reset_count'),
                "seconds_since_last_reset": data.get('seconds_since_last_reset')
            })
        else:
            return jsonify({"error": "Failed to get status"}), response.status_code
            
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Failed to connect to GameServer", "details": str(e)}), 500
