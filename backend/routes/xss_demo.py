from flask import Blueprint, request, jsonify
from datetime import datetime

xss_bp = Blueprint('xss_demo', __name__)

# Hardcoded announcements (in-memory storage)
announcements = [
    {'id': 1, 'title': 'Welcome!', 'content': 'This is a demo of XSS vulnerability', 'author': 'Admin', 'created_at': '2024-02-12T10:00:00'},
    {'id': 2, 'title': 'Security Notice', 'content': 'Please test XSS payloads responsibly', 'author': 'Admin', 'created_at': '2024-02-12T11:00:00'}
]
next_id = 3

# VULNERABLE: No input sanitization
@xss_bp.route('/api/xss/announcements', methods=['GET'])
def get_xss_announcements():
    """Get announcements - VULNERABLE to XSS"""
    return jsonify({'announcements': announcements}), 200

# VULNERABLE: Stores raw input without sanitization
@xss_bp.route('/api/xss/announcements', methods=['POST'])
def create_xss_announcement():
    """Create announcement - VULNERABLE to XSS"""
    global next_id
    data = request.get_json()
    
    # NO SANITIZATION - XSS VULNERABILITY!
    new_announcement = {
        'id': next_id,
        'title': data.get('title', ''),
        'content': data.get('content', ''),
        'author': 'User',
        'created_at': datetime.now().isoformat()
    }
    announcements.append(new_announcement)
    next_id += 1
    
    return jsonify({'success': True, 'id': new_announcement['id']}), 201

@xss_bp.route('/api/xss/announcements/<int:ann_id>', methods=['DELETE'])
def delete_xss_announcement(ann_id):
    """Delete announcement"""
    global announcements
    announcements = [a for a in announcements if a['id'] != ann_id]
    return jsonify({'success': True}), 200


# SECURE VERSION (commented out for demo)
"""
import html
import re

def sanitize(text):
    # Method 1: Escape all HTML
    return html.escape(text)
    
    # Method 2: Remove dangerous tags
    # text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
    # text = re.sub(r'on\w+\s*=', '', text, flags=re.IGNORECASE)
    # return text

@xss_bp.route('/api/xss/announcements/secure', methods=['POST'])
def create_secure_announcement():
    global next_id
    data = request.get_json()
    
    # SANITIZED INPUT - SECURE!
    new_announcement = {
        'id': next_id,
        'title': sanitize(data.get('title', '')),
        'content': sanitize(data.get('content', '')),
        'author': 'User',
        'created_at': datetime.now().isoformat()
    }
    announcements.append(new_announcement)
    next_id += 1
    
    return jsonify({'success': True, 'id': new_announcement['id']}), 201
"""
