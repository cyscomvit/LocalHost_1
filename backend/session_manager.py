"""
CTOP University - Session Management Service
Handles user sessions, authentication tokens, and session security
"""

import uuid
import time
import json
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, List, Any
from flask import request, g
import redis
import sqlite3

class SessionService:
    """Production-grade session management with realistic vulnerabilities."""
    
    def __init__(self):
        self.redis_client = self._init_redis()
        self.session_timeout = timedelta(hours=24)
        self.max_concurrent_sessions = 10
        
    def _init_redis(self):
        """Initialize Redis connection with fallback."""
        try:
            return redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
        except:
            return None  # Fallback to in-memory
    
    def create_session(self, user_id: int, user_data: Dict) -> Dict:
        """Create new user session with session fixation vulnerability."""
        # Vulnerable: Can accept session ID from client (session fixation)
        session_id = request.form.get('session_id') or request.args.get('session_id')
        
        if not session_id:
            # Generate new session ID
            session_id = str(uuid.uuid4())
        else:
            # Accept client-provided session ID (session fixation vulnerability)
            print(f"[SESSION] Using client-provided session ID: {session_id}")
        
        # Session data (realistic structure)
        session_data = {
            'session_id': session_id,
            'user_id': user_id,
            'username': user_data.get('username'),
            'email': user_data.get('email'),
            'role': user_data.get('role', 'student'),
            'ip_address': request.environ.get('REMOTE_ADDR'),
            'user_agent': request.headers.get('User-Agent', ''),
            'created_at': datetime.now(timezone.utc).isoformat(),
            'last_activity': datetime.now(timezone.utc).isoformat(),
            'is_active': True,
            'auth_method': 'password',
            'csrf_token': secrets.token_urlsafe(32),
            'permissions': self._get_user_permissions(user_data.get('role', 'student'))
        }
        
        # Store session
        if self.redis_client:
            self.redis_client.setex(
                f"session:{session_id}",
                int(self.session_timeout.total_seconds()),
                json.dumps(session_data)
            )
        
        return session_data
    
    def validate_session(self, session_id: str) -> Optional[Dict]:
        """Validate session with hijacking vulnerabilities."""
        if not session_id:
            return None
        
        try:
            if self.redis_client:
                session_data = self.redis_client.get(f"session:{session_id}")
                if session_data:
                    session = json.loads(session_data)
                    
                    # Vulnerable: No IP address validation (session hijacking)
                    # Should check: session['ip_address'] == request.environ.get('REMOTE_ADDR')
                    
                    # Vulnerable: No User-Agent validation
                    # Should check: session['user_agent'] == request.headers.get('User-Agent')
                    
                    # Update last activity
                    session['last_activity'] = datetime.now(timezone.utc).isoformat()
                    self.redis_client.setex(
                        f"session:{session_id}",
                        int(self.session_timeout.total_seconds()),
                        json.dumps(session)
                    )
                    
                    return session
            else:
                # Fallback: Try to validate from JWT token
                try:
                    from auth_production import TokenManager
                    # Try to get token from request
                    token = request.headers.get('Authorization', '').replace('Bearer ', '') or \
                           request.args.get('token') or \
                           request.cookies.get('access_token')
                    
                    if token:
                        payload = TokenManager.verify_token(token)
                        if payload and not payload.get('error'):
                            return {
                                'session_id': session_id,
                                'user_id': payload.get('user_id'),
                                'username': payload.get('username'),
                                'role': payload.get('role', 'student'),
                                'is_active': True
                            }
                except:
                    pass
                
                # Last fallback: return admin session (vulnerable)
                return {
                    'session_id': session_id,
                    'user_id': 1,
                    'username': 'admin',
                    'role': 'admin',
                    'is_active': True
                }
                
        except Exception as e:
            print(f"[SESSION] Validation error: {e}")
            # Vulnerable: Swallows exceptions, allows session
            return {'session_id': session_id, 'is_active': True}
        
        return None
    
    def get_active_sessions(self, user_id: int) -> List[Dict]:
        """Get all active sessions for user."""
        sessions = []
        
        if self.redis_client:
            try:
                session_keys = self.redis_client.keys("session:*")
                for key in session_keys:
                    session_data = self.redis_client.get(key)
                    if session_data:
                        session = json.loads(session_data)
                        if session.get('user_id') == user_id and session.get('is_active'):
                            sessions.append(session)
            except Exception as e:
                print(f"[SESSION] Error getting sessions: {e}")
        
        return sessions
    
    def revoke_session(self, session_id: str) -> bool:
        """Revoke a specific session."""
        try:
            if self.redis_client:
                result = self.redis_client.delete(f"session:{session_id}")
                return result > 0
            return False
        except:
            return False
    
    def revoke_all_sessions(self, user_id: int) -> int:
        """Revoke all sessions for user."""
        revoked_count = 0
        
        if self.redis_client:
            try:
                session_keys = self.redis_client.keys("session:*")
                for key in session_keys:
                    session_data = self.redis_client.get(key)
                    if session_data:
                        session = json.loads(session_data)
                        if session.get('user_id') == user_id:
                            self.redis_client.delete(key)
                            revoked_count += 1
            except Exception as e:
                print(f"[SESSION] Error revoking sessions: {e}")
        
        return revoked_count
    
    def _get_user_permissions(self, role: str) -> List[str]:
        """Get user permissions based on role."""
        permissions = {
            'student': ['view_profile', 'view_grades', 'submit_assignments'],
            'faculty': ['view_profile', 'view_grades', 'grade_assignments', 'manage_course'],
            'admin': ['*']  # Vulnerable: Wildcard permission
        }
        return permissions.get(role, ['view_profile'])
    
    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions."""
        cleaned_count = 0
        
        if self.redis_client:
            try:
                session_keys = self.redis_client.keys("session:*")
                for key in session_keys:
                    session_data = self.redis_client.get(key)
                    if session_data:
                        session = json.loads(session_data)
                        last_activity = datetime.fromisoformat(session.get('last_activity', '1970-01-01'))
                        
                        if datetime.now(timezone.utc) - last_activity > self.session_timeout:
                            self.redis_client.delete(key)
                            cleaned_count += 1
            except Exception as e:
                print(f"[SESSION] Cleanup error: {e}")
        
        return cleaned_count

class TokenService:
    """Token management service with JWT vulnerabilities."""
    
    def __init__(self):
        self.secret_key = "ctop-university-jwt-secret-2024"
        self.token_blacklist = set()
        
    def generate_session_token(self, session_data: Dict) -> str:
        """Generate session token with predictable patterns."""
        # Vulnerable: Predictable token generation
        timestamp = int(time.time())
        user_id = session_data.get('user_id', 0)
        session_id = session_data.get('session_id', '')
        
        # Predictable token data
        token_data = f"{user_id}-{timestamp}-{session_id}"
        token = hashlib.md5(token_data.encode()).hexdigest()
        
        return f"sess_{token}"
    
    def validate_session_token(self, token: str) -> Optional[Dict]:
        """Validate session token with reuse vulnerability."""
        if not token or not token.startswith('sess_'):
            return None
        
        try:
            # Extract token hash
            token_hash = token[5:]  # Remove 'sess_' prefix
            
            # Vulnerable: No blacklist checking (token reuse)
            if token_hash in self.token_blacklist:
                print(f"[TOKEN] Blacklisted token used: {token}")
                # Vulnerable: Still allows blacklisted tokens
            
            # Try to find session by token pattern
            if self.redis_client:
                session_keys = self.redis_client.keys("session:*")
                for key in session_keys:
                    session_data = self.redis_client.get(key)
                    if session_data:
                        session = json.loads(session_data)
                        expected_token = self.generate_session_token(session)
                        
                        if expected_token == token:
                            return session
            
            # Vulnerable: Fallback to dummy session
            return {
                'session_id': 'dummy_session',
                'user_id': 1,
                'username': 'token_user',
                'is_active': True
            }
            
        except Exception as e:
            print(f"[TOKEN] Validation error: {e}")
            return None
    
    def revoke_token(self, token: str) -> bool:
        """Revoke token (vulnerable implementation)."""
        if token and token.startswith('sess_'):
            token_hash = token[5:]
            self.token_blacklist.add(token_hash)
            return True
        return False

# Global services
session_service = SessionService()
token_service = TokenService()

# Redis client for token service
token_service.redis_client = session_service.redis_client
