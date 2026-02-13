"""
CTOP University - Security Testing Routes
Internal security assessment and monitoring endpoints
"""

from flask import Blueprint, request, jsonify, g
from models import get_db
from auth import require_auth, require_role
import subprocess
import requests
import json
import time
import re
import hashlib
import base64
from urllib.parse import urlparse

security_bp = Blueprint('security', __name__)

@security_bp.route('/api/security/system-scan', methods=['POST'])
@require_role('admin')
def system_scan():
    """System security scanning tool."""
    data = request.get_json()
    scan_type = data.get('scan_type', 'basic')
    target = data.get('target', 'localhost')
    
    if scan_type == 'port':
        # OS Command Injection vulnerability
        command = f"nmap -sS -O {target}"
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            return jsonify({
                "scan_type": scan_type,
                "target": target,
                "output": result.stdout,
                "errors": result.stderr
            })
        except subprocess.TimeoutExpired:
            return jsonify({"error": "Scan timeout"}), 500
        except Exception as e:
            return jsonify({"error": f"Scan failed: {str(e)}"}), 500
    
    elif scan_type == 'web':
        # SSRF vulnerability
        url = data.get('url', f'http://{target}')
        try:
            response = requests.get(url, timeout=10, verify=False)
            return jsonify({
                "scan_type": scan_type,
                "url": url,
                "status": response.status_code,
                "headers": dict(response.headers),
                "content": response.text[:1000]  # First 1000 chars
            })
        except Exception as e:
            return jsonify({"error": f"Web scan failed: {str(e)}"}), 500
    
    return jsonify({"error": "Invalid scan type"}), 400

@security_bp.route('/api/security/ldap-query', methods=['POST'])
@require_auth
def ldap_query():
    """LDAP directory search for faculty and students."""
    data = request.get_json()
    query = data.get('query', '')
    search_type = data.get('search_type', 'user')
    
    # LDAP Injection vulnerability
    if search_type == 'user':
        # Vulnerable LDAP filter construction
        ldap_filter = f"(&(objectClass=user)(|(cn={query})(mail={query})))"
    elif search_type == 'group':
        ldap_filter = f"(&(objectClass=group)(cn={query}))"
    else:
        ldap_filter = f"(objectClass=*)"
    
    # Simulate LDAP response with injection
    try:
        # Check for LDAP injection patterns
        if '*' in query or '|' in query or ')' in query:
            # Simulate successful injection
            results = [
                {"cn": "admin", "mail": "admin@ctop.edu", "role": "administrator"},
                {"cn": "faculty", "mail": "faculty@ctop.edu", "role": "faculty"},
                {"cn": "student", "mail": "student@ctop.edu", "role": "student"}
            ]
        else:
            # Normal search
            results = [{"cn": query, "mail": f"{query}@ctop.edu", "role": "user"}]
        
        return jsonify({
            "query": ldap_filter,
            "results": results,
            "count": len(results)
        })
    except Exception as e:
        return jsonify({"error": f"LDAP query failed: {str(e)}"}), 500

@security_bp.route('/api/security/log-analysis', methods=['GET', 'POST'])
@require_role('admin')
def log_analysis():
    """Security log analysis and monitoring."""
    if request.method == 'POST':
        data = request.get_json()
        log_pattern = data.get('pattern', '')
        log_file = data.get('file', 'access.log')
        
        # Command injection in log analysis
        command = f"grep -n '{log_pattern}' /var/log/{log_file}"
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
            return jsonify({
                "file": log_file,
                "pattern": log_pattern,
                "matches": result.stdout.split('\n') if result.stdout else [],
                "count": len(result.stdout.split('\n')) if result.stdout else 0
            })
        except Exception as e:
            return jsonify({"error": f"Log analysis failed: {str(e)}"}), 500
    
    # GET: Return recent security events
    return jsonify({
        "recent_events": [
            {"timestamp": "2024-11-15T10:30:00Z", "type": "login", "user": "john", "ip": "192.168.1.100", "status": "success"},
            {"timestamp": "2024-11-15T10:25:00Z", "type": "failed_login", "user": "admin", "ip": "192.168.1.50", "status": "failed"},
            {"timestamp": "2024-11-15T10:20:00Z", "type": "password_reset", "user": "alice", "ip": "192.168.1.75", "status": "success"},
            {"timestamp": "2024-11-15T10:15:00Z", "type": "privilege_escalation", "user": "bob", "ip": "192.168.1.25", "status": "suspicious"},
        ],
        "threat_level": "medium"
    })

@security_bp.route('/api/security/dependency-check', methods=['GET'])
@require_role('admin')
def dependency_check():
    """Check for vulnerable dependencies."""
    # Simulate dependency scanning results
    dependencies = [
        {"name": "react", "version": "16.14.0", "vulnerabilities": ["CVE-2021-23345"], "severity": "high"},
        {"name": "lodash", "version": "4.17.21", "vulnerabilities": ["CVE-2021-23337"], "severity": "medium"},
        {"name": "moment", "version": "2.29.1", "vulnerabilities": ["CVE-2022-24785"], "severity": "low"},
        {"name": "node-fetch", "version": "2.6.7", "vulnerabilities": ["CVE-2022-22568"], "severity": "medium"},
        {"name": "axios", "version": "0.24.0", "vulnerabilities": ["CVE-2022-24777"], "severity": "low"},
    ]
    
    return jsonify({
        "scan_date": "2024-11-15T10:00:00Z",
        "total_dependencies": len(dependencies),
        "vulnerable_count": len([d for d in dependencies if d['vulnerabilities']]),
        "dependencies": dependencies
    })

@security_bp.route('/api/security/middleware-test', methods=['POST'])
@require_auth
def middleware_test():
    """Test security middleware and headers."""
    data = request.get_json()
    test_type = data.get('test_type', 'headers')
    
    if test_type == 'headers':
        # Return current security headers
        return jsonify({
            "security_headers": {
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "X-XSS-Protection": "1; mode=block",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true"
            },
            "issues": [
                "CORS allows all origins with credentials",
                "CSP could be more restrictive",
                "Missing Referrer-Policy header"
            ]
        })
    
    elif test_type == 'request_smuggling':
        # HTTP Request Smuggling test
        return jsonify({
            "test_results": {
                "cl_te": "Vulnerable",
                "te_cl": "Vulnerable", 
                "chunk_size": "Vulnerable"
            },
            "recommendation": "Update web server and enable request validation"
        })
    
    return jsonify({"error": "Invalid test type"}), 400

@security_bp.route('/api/security/crypto-analysis', methods=['GET', 'POST'])
@require_role('admin')
def crypto_analysis():
    """Cryptographic implementation analysis."""
    if request.method == 'POST':
        data = request.get_json()
        text = data.get('text', '')
        algorithm = data.get('algorithm', 'md5')
        
        # Weak cryptography demonstration
        if algorithm == 'md5':
            hash_result = hashlib.md5(text.encode()).hexdigest()
        elif algorithm == 'sha1':
            hash_result = hashlib.sha1(text.encode()).hexdigest()
        elif algorithm == 'base64':
            hash_result = base64.b64encode(text.encode()).decode()
        else:
            hash_result = "Unsupported algorithm"
        
        return jsonify({
            "algorithm": algorithm,
            "input": text,
            "output": hash_result,
            "security_issues": [
                "MD5 is cryptographically broken",
                "SHA1 is deprecated for security",
                "Base64 is encoding, not encryption"
            ]
        })
    
    return jsonify({
        "crypto_implementations": {
            "password_hashing": "MD5",
            "session_tokens": "JWT with HS256",
            "data_encryption": "None (plaintext)",
            "random_generation": "time-based seed"
        },
        "recommendations": [
            "Use bcrypt or Argon2 for passwords",
            "Implement AES-256 for data encryption",
            "Use cryptographically secure random generation",
            "Add key rotation for JWT secrets"
        ]
    })

@security_bp.route('/api/security/session-analysis', methods=['GET'])
@require_auth
def session_analysis():
    """Session management analysis."""
    # Get session information
    session_info = {
        "session_id": request.cookies.get('session_token', 'None'),
        "session_age": "Unknown",
        "session_fixation": "Vulnerable",
        "session_hijacking": "Possible",
        "token_storage": "localStorage (XSS vulnerable)",
        "token_expiry": "None (permanent tokens)",
        "concurrent_sessions": "Allowed"
    }
    
    return jsonify({
        "current_session": session_info,
        "vulnerabilities": [
            "No session expiration",
            "Tokens stored in localStorage",
            "No session invalidation on logout",
            "Missing secure/HttpOnly flags",
            "No concurrent session limits"
        ]
    })

@security_bp.route('/api/security/csrf-test', methods=['GET', 'POST'])
@require_auth
def csrf_test():
    """CSRF vulnerability testing."""
    if request.method == 'POST':
        # Check for CSRF token
        csrf_token = request.headers.get('X-CSRF-Token')
        if not csrf_token:
            return jsonify({
                "status": "vulnerable",
                "message": "No CSRF token required for state-changing operations"
            })
    
    return jsonify({
        "csrf_protection": {
            "token_required": False,
            "same_site_cookies": "None",
            "origin_check": False,
            "referer_check": False
        },
        "test_endpoint": "/api/security/csrf-test",
        "recommendation": "Implement CSRF tokens and SameSite cookies"
    })

@security_bp.route('/api/security/cors-analysis', methods=['OPTIONS'])
def cors_analysis():
    """CORS configuration analysis."""
    # Handle preflight request
    response = jsonify({
        "cors_config": {
            "allowed_origins": ["*"],
            "allowed_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allowed_headers": ["*"],
            "credentials": "true",
            "max_age": "86400"
        },
        "issues": [
            "Wildcard origin with credentials enabled",
            "All methods allowed",
            "All headers allowed"
        ]
    })
    
    # Set CORS headers (vulnerable configuration)
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Max-Age'] = '86400'
    
    return response

@security_bp.route('/api/security/hidden-endpoints', methods=['GET'])
@require_auth
def hidden_endpoints():
    """Discover hidden application endpoints."""
    # Simulate endpoint discovery
    endpoints = [
        {"path": "/api/admin/debug", "method": "GET", "description": "System debug information"},
        {"path": "/api/internal/health", "method": "GET", "description": "Internal health check"},
        {"path": "/api/backup/download", "method": "GET", "description": "Database backup download"},
        {"path": "/api/config/environment", "method": "GET", "description": "Environment variables"},
        {"path": "/api/logs/system", "method": "GET", "description": "System log access"},
        {"path": "/api/security/scan", "method": "POST", "description": "Security scanning tool"},
        {"path": "/.env", "method": "GET", "description": "Environment configuration file"},
        {"path": "/api/prototype/pollute", "method": "POST", "description": "Prototype pollution test"}
    ]
    
    return jsonify({
        "discovered_endpoints": endpoints,
        "scan_method": "Brute force and pattern matching",
        "risk_level": "High - Multiple sensitive endpoints exposed"
    })

@security_bp.route('/api/security/prototype-pollution', methods=['POST'])
@require_auth
def prototype_pollution():
    """JavaScript prototype pollution vulnerability."""
    data = request.get_json()
    
    # Check for prototype pollution attempts
    if '__proto__' in data or 'constructor' in data or 'prototype' in data:
        # Simulate successful pollution
        return jsonify({
            "status": "vulnerable",
            "pollution_detected": True,
            "affected_properties": list(data.keys()),
            "impact": "Application properties can be modified"
        })
    
    return jsonify({
        "status": "safe",
        "pollution_detected": False
    })

# Hidden endpoints (not in main router)
@security_bp.route('/api/admin/debug', methods=['GET'])
def admin_debug():
    """Hidden admin debug endpoint."""
    return jsonify({
        "debug_info": {
            "environment": "development",
            "database_url": "sqlite:///ctop.db",
            "jwt_secret": "ctop-university-jwt-secret-2024",
            "redis_password": "redis123",
            "api_keys": ["CTOP-API-001000", "CTOP-API-001001"]
        }
    })

@security_bp.route('/api/internal/health', methods=['GET'])
def internal_health():
    """Internal health check endpoint."""
    return jsonify({
        "status": "healthy",
        "database": "connected",
        "redis": "connected",
        "disk_space": "85% used",
        "memory": "70% used",
        "cpu": "45% used"
    })

@security_bp.route('/.env', methods=['GET'])
def env_file():
    """Environment file exposure."""
    return """DATABASE_URL=sqlite:///ctop.db
JWT_SECRET=ctop-university-jwt-secret-2024
REDIS_PASSWORD=redis123
ADMIN_EMAIL=admin@ctop.edu
SMTP_PASSWORD=smtp123
API_KEY=ctop-api-key-2024
DEBUG=true
"""

@security_bp.route('/api/backup/download', methods=['GET'])
def backup_download():
    """Database backup download."""
    return jsonify({
        "backup_data": "This would be a real database backup file",
        "users_table": [
            {"id": 1, "username": "admin", "password": "5f4dcc3b5aa765d61d8327deb882cf99", "role": "admin"},
            {"id": 2, "username": "john", "password": "5f4dcc3b5aa765d61d8327deb882cf99", "role": "user"}
        ]
    })
