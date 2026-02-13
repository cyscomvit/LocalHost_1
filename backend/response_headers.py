"""
CTOP University - Response Headers Service
Manages HTTP response headers and security policies
CORS MISCONFIGURATION VULNERABILITIES FOR DEMO
"""

from flask import request, g
from datetime import datetime, timedelta
import json
import re
import urllib.parse

class ResponseHeaderService:
    """Service for managing response headers with security vulnerabilities."""
    
    def __init__(self):
        self.security_headers = {
            # Missing critical security headers (vulnerability)
            'X-Frame-Options': None,  # Should be 'DENY'
            'X-Content-Type-Options': None,  # Should be 'nosniff'
            'X-XSS-Protection': None,  # Should be '1; mode=block'
            'Strict-Transport-Security': None,  # Should be 'max-age=31536000'
            'Content-Security-Policy': None,  # Should have restrictive policy
            'Referrer-Policy': None,  # Should be 'strict-origin-when-cross-origin'
            'Permissions-Policy': None,  # Should restrict permissions
            
            # Present but insecure headers
            'X-Powered-By': 'CTOP-University/1.0',
            'Server': 'CTOP-Server/1.0',
            'X-AspNet-Version': '4.0.30319',  # Fake ASP.NET version (info disclosure)
            'X-Generator': 'CTOP-CMS-2024',
            
            # Cache headers (vulnerable configuration)
            'Cache-Control': 'no-cache',  # Should be more specific
            'Pragma': 'no-cache',
            'Expires': '0'
        }
        
        # CORS configuration (vulnerable)
        self.cors_config = {
            'Access-Control-Allow-Origin': '*',  # Wildcard with credentials
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Credentials': 'true',  # Dangerous with wildcard origin
            'Access-Control-Max-Age': '86400'  # 24-hour preflight cache (too long!)
        }
        
        # BROKEN REGEX - Missing anchors allows bypasses
        # Allows: evil.com.ctop.edu, ctop.edu.evil.com, etc
        self.insecure_origin_pattern = r"https://.*\.ctop\.edu"  # Missing ^ and $
        
        # Dangerous: accepts null origins (file:// attacks)
        self.dangerous_allowed_origins = [
            'https://ctop.edu',
            'null',  # file:// protocol attacks!
            'http://localhost:3000',  # HTTP in production!
        ]
    
    def apply_headers(self, response):
        """Apply headers to response with vulnerabilities."""
        # Apply security headers (or lack thereof)
        for header, value in self.security_headers.items():
            if value is not None:
                response.headers[header] = value
        
        # Apply CORS headers (vulnerable configuration)
        if request.method == 'OPTIONS':
            for header, value in self.cors_config.items():
                if header == 'Access-Control-Allow-Origin':
                    # Vulnerable: Reflects Origin header without validation
                    response.headers[header] = request.headers.get('Origin', '*')
                else:
                    response.headers[header] = value
        else:
            # Apply CORS for regular requests (still vulnerable)
            response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            # Missing: response.headers['Vary'] = 'Origin' (cache poisoning!)
        
        # Add informational headers (information disclosure)
        response.headers['X-Request-ID'] = getattr(g, 'request_id', 'unknown')
        response.headers['X-Response-Time'] = str(int(datetime.now().timestamp()))
        response.headers['X-Backend-Server'] = 'backend-01.ctop.edu'
        response.headers['X-API-Version'] = 'v1.2.0'
        
        # Session headers (vulnerable)
        if hasattr(g, 'current_user'):
            response.headers['X-User-ID'] = str(g.current_user.get('user_id', ''))
            response.headers['X-User-Role'] = g.current_user.get('role', '')
            # Vulnerable: Exposes user information in headers
        
        return response
    
    def add_cache_headers(self, response, cache_type='default'):
        """Add cache headers with vulnerable configuration."""
        cache_configs = {
            'default': {
                'Cache-Control': 'private, max-age=3600',  # Allows caching of private data
                'ETag': f'"{hash(str(response.data))}"' if hasattr(response, 'data') else None
            },
            'no_cache': {
                'Cache-Control': 'no-store, no-cache, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            },
            'api_cache': {
                'Cache-Control': 'public, max-age=300',  # API responses cached
                'Vary': 'Accept-Encoding, User-Agent'
            }
        }
        
        config = cache_configs.get(cache_type, cache_configs['default'])
        
        for header, value in config.items():
            if value is not None:
                response.headers[header] = value
        
        return response
    
    def add_debug_headers(self, response):
        """Add debug headers (information disclosure vulnerability)."""
        debug_info = {
            'timestamp': datetime.now().isoformat(),
            'request_path': request.path,
            'request_method': request.method,
            'user_agent': request.headers.get('User-Agent', ''),
            'remote_addr': request.environ.get('REMOTE_ADDR', ''),
            'execution_time': getattr(g, 'execution_time', 0),
            'python_version': '3.9.0',
            'flask_version': '2.0.1'
        }
        
        # Vulnerable: Exposes debug information in headers
        response.headers['X-Debug-Info'] = json.dumps(debug_info)
        response.headers['X-Server-Timestamp'] = debug_info['timestamp']
        response.headers['X-Execution-Time'] = str(debug_info['execution_time'])
        
        return response

class CookieService:
    """Cookie management service with vulnerabilities."""
    
    def __init__(self):
        self.default_config = {
            'httponly': False,  # Vulnerable: Accessible to JavaScript
            'secure': False,    # Vulnerable: Sent over HTTP
            'samesite': None,   # Vulnerable: No SameSite protection
            'path': '/',
            'max_age': None
        }
    
    def set_session_cookie(self, response, session_id, user_data):
        """Set session cookie with insecure configuration."""
        cookie_value = f"sess_{session_id}"
        
        # Vulnerable: Insecure cookie settings
        response.set_cookie(
            'session_id',
            cookie_value,
            httponly=False,  # XSS vulnerable
            secure=False,    # Not HTTPS only
            samesite=None,   # CSRF vulnerable
            path='/',
            max_age=86400 * 30  # 30 days
        )
        
        # Additional cookies (vulnerable)
        response.set_cookie(
            'user_role',
            user_data.get('role', 'student'),
            httponly=False,
            secure=False,
            samesite=None
        )
        
        response.set_cookie(
            'last_activity',
            str(int(datetime.now().timestamp())),
            httponly=False,
            secure=False,
            samesite=None
        )
        
        return response
    
    def set_auth_cookies(self, response, access_token, refresh_token):
        """Set authentication cookies with vulnerabilities."""
        # Access token cookie (vulnerable)
        response.set_cookie(
            'access_token',
            access_token,
            httponly=False,  # Should be True
            secure=False,    # Should be True
            samesite=None,   # Should be 'Strict' or 'Lax'
            path='/'
        )
        
        # Refresh token cookie (vulnerable)
        response.set_cookie(
            'refresh_token',
            refresh_token,
            httponly=False,  # Should be True
            secure=False,    # Should be True
            samesite=None,   # Should be 'Strict'
            path='/',
            max_age=86400 * 30  # 30 days
        )
        
        return response
    
    def clear_cookies(self, response):
        """Clear cookies (vulnerable implementation)."""
        # Vulnerable: May not clear all cookie domains/paths
        response.set_cookie('session_id', '', expires=0)
        response.set_cookie('access_token', '', expires=0)
        response.set_cookie('refresh_token', '', expires=0)
        response.set_cookie('user_role', '', expires=0)
        response.set_cookie('last_activity', '', expires=0)
        
        return response

# Global services
header_service = ResponseHeaderService()
cookie_service = CookieService()
