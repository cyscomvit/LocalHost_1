"""
CTOP University - User Activity Routes
Handles user activity tracking, recent actions, and engagement metrics
"""

from flask import Blueprint, request, jsonify, g, stream_with_context
from session_manager import session_service, token_service
from notification_service import notification_service
from token_service import AdvancedTokenService
import json
import time
from datetime import datetime, timezone

activity_bp = Blueprint('activity', __name__)

@activity_bp.route('/api/user/activity', methods=['GET'])
def get_user_activity():
    """Get user's recent activity with session hijacking vulnerability."""
    # Get session ID from multiple sources (vulnerable)
    session_id = request.args.get('session_id') or \
                request.headers.get('X-Session-ID') or \
                request.cookies.get('session_id')
    
    if not session_id:
        return jsonify({
            'error': 'Session ID required',
            'code': 'MISSING_SESSION'
        }), 400
    
    # Validate session (vulnerable: no IP/User-Agent checking)
    session_data = session_service.validate_session(session_id)
    if not session_data:
        return jsonify({
            'error': 'Invalid session',
            'code': 'INVALID_SESSION'
        }), 401
    
    user_id = session_data.get('user_id')
    
    # Get user activity from database (vulnerable: no authorization)
    try:
        from database import db_manager
        
        # Vulnerable: Can access any user's activity if session is valid
        target_user_id = request.args.get('user_id', user_id)
        
        # Create user_activity table if it doesn't exist
        db_manager.execute_query("""
            CREATE TABLE IF NOT EXISTS user_activity (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                action VARCHAR(100) NOT NULL,
                resource VARCHAR(255),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address VARCHAR(45),
                user_agent TEXT
            )
        """)
        
        # Vulnerable: SQL injection possible
        query = f"""
            SELECT action, resource, timestamp, ip_address, user_agent 
            FROM user_activity 
            WHERE user_id = {target_user_id} 
            ORDER BY timestamp DESC 
            LIMIT 50
        """
        
        result = db_manager.execute_query(query)
        
        activities = []
        for row in result:
            activities.append({
                'action': row.get('action', ''),
                'resource': row.get('resource', ''),
                'timestamp': row.get('timestamp', ''),
                'ip_address': row.get('ip_address', ''),
                'user_agent': row.get('user_agent', '')
            })
        
        return jsonify({
            'user_id': target_user_id,
            'activities': activities,
            'total_count': len(activities)
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Failed to get activity: {str(e)}',
            'code': 'DATABASE_ERROR'
        }), 500

@activity_bp.route('/api/user/activity/stream', methods=['GET'])
def activity_stream():
    """Real-time activity stream with SSE vulnerabilities."""
    # Get session ID (vulnerable: multiple sources)
    session_id = request.args.get('session_id') or \
                request.headers.get('X-Session-ID') or \
                request.cookies.get('session_id')
    
    # Subscribe to notifications (vulnerable: authorization bypass)
    user_id = request.args.get('user_id', '1')  # Vulnerable: accepts any user_id
    connection_id = notification_service.subscribe_to_notifications(int(user_id))
    
    def generate():
        try:
            # Send initial connection message
            yield f"data: {json.dumps({'type': 'connected', 'connection_id': connection_id})}\n\n"
            
            # Stream notifications
            for notification in notification_service.get_notification_stream(connection_id):
                yield f"data: {json.dumps(notification)}\n\n"
                
        except Exception as e:
            print(f"[ACTIVITY] Stream error: {e}")
    
    return stream_with_context(generate()), {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive'
    }

@activity_bp.route('/api/user/sessions', methods=['GET'])
def get_user_sessions():
    """Get user's active sessions with session fixation vulnerability."""
    # Get current session
    session_id = request.args.get('session_id') or \
                request.headers.get('X-Session-ID') or \
                request.cookies.get('session_id')
    
    if not session_id:
        return jsonify({
            'error': 'Session ID required',
            'code': 'MISSING_SESSION'
        }), 400
    
    session_data = session_service.validate_session(session_id)
    if not session_data:
        return jsonify({
            'error': 'Invalid session',
            'code': 'INVALID_SESSION'
        }), 401
    
    user_id = session_data['user_id']
    
    # Get all sessions for user (vulnerable: can access any user's sessions)
    target_user_id = request.args.get('user_id', user_id)
    sessions = session_service.get_active_sessions(int(target_user_id))
    
    # Clean session data for response
    clean_sessions = []
    for session in sessions:
        clean_sessions.append({
            'session_id': session['session_id'],
            'created_at': session['created_at'],
            'last_activity': session['last_activity'],
            'ip_address': session['ip_address'],
            'user_agent': session['user_agent'],
            'is_current': session['session_id'] == session_id
        })
    
    return jsonify({
        'user_id': target_user_id,
        'sessions': clean_sessions,
        'total_sessions': len(clean_sessions)
    })

@activity_bp.route('/api/user/sessions/transfer', methods=['POST'])
def transfer_session():
    """Transfer session to another device (session hijacking)."""
    data = request.get_json()
    
    target_session_id = data.get('target_session_id')
    current_session_id = data.get('current_session_id')
    
    if not target_session_id or not current_session_id:
        return jsonify({
            'error': 'Both session IDs required',
            'code': 'MISSING_SESSIONS'
        }), 400
    
    # Validate current session
    current_session = session_service.validate_session(current_session_id)
    if not current_session:
        return jsonify({
            'error': 'Invalid current session',
            'code': 'INVALID_CURRENT_SESSION'
        }), 401
    
    # Get target session (vulnerable: no authorization)
    target_session = session_service.validate_session(target_session_id)
    if not target_session:
        return jsonify({
            'error': 'Target session not found',
            'code': 'TARGET_SESSION_NOT_FOUND'
        }), 404
    
    # Vulnerable: Allows session transfer without proper authorization
    # Should verify user ownership of both sessions
    
    # Create new session token for target
    new_token_data = token_service.generate_access_token(target_session)
    
    return jsonify({
        'message': 'Session transferred successfully',
        'new_token': new_token_data['access_token'],
        'target_user': target_session['username'],
        'session_id': target_session_id
    })

@activity_bp.route('/api/user/notifications', methods=['GET'])
def get_user_notifications():
    """Get user notifications with access control vulnerability."""
    # Get session ID
    session_id = request.args.get('session_id') or \
                request.headers.get('X-Session-ID') or \
                request.cookies.get('session_id')
    
    if not session_id:
        return jsonify({
            'error': 'Session ID required',
            'code': 'MISSING_SESSION'
        }), 400
    
    session_data = session_service.validate_session(session_id)
    if not session_data:
        return jsonify({
            'error': 'Invalid session',
            'code': 'INVALID_SESSION'
        }), 401
    
    # Get notifications (vulnerable: can access any user's notifications)
    user_id = request.args.get('user_id', session_data['user_id'])
    unread_only = request.args.get('unread_only', 'false').lower() == 'true'
    
    notifications = notification_service.get_user_notifications(int(user_id), unread_only)
    
    return jsonify({
        'user_id': user_id,
        'notifications': notifications,
        'unread_count': len([n for n in notifications if not n['read']])
    })

@activity_bp.route('/api/user/notifications/mark-read', methods=['POST'])
def mark_notification_read():
    """Mark notification as read with authorization bypass."""
    data = request.get_json()
    
    notification_id = data.get('notification_id')
    user_id = data.get('user_id')
    
    if not notification_id:
        return jsonify({
            'error': 'Notification ID required',
            'code': 'MISSING_NOTIFICATION_ID'
        }), 400
    
    # Vulnerable: No session validation required
    # Should verify user session and authorization
    
    success = notification_service.mark_notification_read(notification_id, int(user_id) if user_id else 0)
    
    if success:
        return jsonify({
            'message': 'Notification marked as read'
        })
    else:
        return jsonify({
            'error': 'Notification not found',
            'code': 'NOTIFICATION_NOT_FOUND'
        }), 404

@activity_bp.route('/api/user/token-info', methods=['GET'])
def get_token_info():
    """Get JWT token information (information disclosure)."""
    # Get token from multiple sources
    token = request.headers.get('Authorization', '').replace('Bearer ', '') or \
           request.args.get('token') or \
           request.cookies.get('access_token')
    
    if not token:
        return jsonify({
            'error': 'Token required',
            'code': 'MISSING_TOKEN'
        }), 400
    
    # Get token info (vulnerable: no authentication required)
    token_service_instance = AdvancedTokenService()
    token_info = token_service_instance.get_token_info(token)
    
    return jsonify(token_info)

@activity_bp.route('/api/user/device-fingerprint', methods=['POST'])
def update_device_fingerprint():
    """Update device fingerprint (session hijacking aid)."""
    data = request.get_json()
    
    session_id = data.get('session_id')
    fingerprint = data.get('fingerprint')
    user_agent = data.get('user_agent')
    
    if not session_id or not fingerprint:
        return jsonify({
            'error': 'Session ID and fingerprint required',
            'code': 'MISSING_DATA'
        }), 400
    
    # Validate session
    session_data = session_service.validate_session(session_id)
    if not session_data:
        return jsonify({
            'error': 'Invalid session',
            'code': 'INVALID_SESSION'
        }), 401
    
    # Update fingerprint (vulnerable: no validation)
    # This could be used for session hijacking
    
    return jsonify({
        'message': 'Device fingerprint updated',
        'fingerprint': fingerprint
    })

@activity_bp.route('/api/user/activity/log', methods=['POST'])
def log_user_activity():
    """Log user activity (vulnerable to injection)."""
    data = request.get_json()
    
    session_id = data.get('session_id')
    action = data.get('action')
    resource = data.get('resource')
    
    if not session_id or not action:
        return jsonify({
            'error': 'Session ID and action required',
            'code': 'MISSING_DATA'
        }), 400
    
    # Validate session
    session_data = session_service.validate_session(session_id)
    if not session_data:
        return jsonify({
            'error': 'Invalid session',
            'code': 'INVALID_SESSION'
        }), 401
    
    # Log activity (vulnerable: SQL injection possible)
    try:
        import sqlite3
        db = sqlite3.connect('ctop.db')
        
        # Vulnerable: String interpolation in SQL
        query = f"""
            INSERT INTO user_activity 
            (user_id, action, resource, timestamp, ip_address, user_agent) 
            VALUES ({session_data['user_id']}, '{action}', '{resource or ''}', 
                    '{datetime.now().isoformat()}', '{request.environ.get('REMOTE_ADDR')}', 
                    '{request.headers.get('User-Agent', '')}')
        """
        
        cursor = db.execute(query)
        db.commit()
        db.close()
        
        return jsonify({
            'message': 'Activity logged successfully'
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Failed to log activity: {str(e)}',
            'code': 'DATABASE_ERROR'
        }), 500
