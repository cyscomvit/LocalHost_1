"""
TaskFlowr - NoSQL Routes (MongoDB)
INTENTIONALLY INSECURE: NoSQL Injection demonstrations.
"""

from flask import Blueprint, request, jsonify, g
from auth import require_auth
import json

nosql_bp = Blueprint('nosql', __name__)

# In-memory mock MongoDB-like store for demo purposes
# In a real setup, this would connect to MongoDB via pymongo
MOCK_NOTES_DB = [
    {"_id": "1", "user_id": 1, "title": "Sprint planning notes", "content": "Discussed Q1 roadmap", "tags": ["meeting", "planning"]},
    {"_id": "2", "user_id": 1, "title": "API design doc", "content": "REST endpoints for v2", "tags": ["technical", "api"]},
    {"_id": "3", "user_id": 2, "title": "Budget review", "content": "Q4 budget allocation details - CONFIDENTIAL", "tags": ["finance", "confidential"]},
    {"_id": "4", "user_id": 3, "title": "Security audit findings", "content": "Found 47 critical vulnerabilities", "tags": ["security", "urgent"]},
    {"_id": "5", "user_id": 1, "title": "Deployment checklist", "content": "Steps for production deploy", "tags": ["devops"]},
]

# Try to import pymongo for real MongoDB demo
try:
    from pymongo import MongoClient
    MONGO_AVAILABLE = True
except ImportError:
    MONGO_AVAILABLE = False


def get_mongo_db():
    """Get MongoDB connection.
    INTENTIONALLY INSECURE: No authentication on MongoDB connection.
    TODO: Use authenticated connection with TLS.
    """
    if MONGO_AVAILABLE:
        try:
            # INTENTIONALLY INSECURE: No auth, no TLS
            client = MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=2000)
            client.server_info()  # Test connection
            return client.taskflowr
        except:
            return None
    return None


@nosql_bp.route('/api/notes', methods=['GET'])
@require_auth
def get_notes():
    """Get notes with optional filtering.
    INTENTIONALLY INSECURE: NoSQL Injection via query parameters.
    TODO: Validate and sanitize query parameters, use proper query building.
    """
    mongo_db = get_mongo_db()

    if mongo_db:
        # Real MongoDB path
        title_filter = request.args.get('title', '')
        user_filter = request.args.get('user_id', '')

        # INTENTIONALLY INSECURE: NoSQL Injection
        # Attacker can pass: ?title[$regex]=.*&user_id[$ne]=null
        # TODO: Validate types, don't pass raw query params to MongoDB
        query = {}
        if title_filter:
            # INTENTIONALLY INSECURE: Direct use of user input in query
            query['title'] = json.loads(title_filter) if title_filter.startswith('{') else title_filter
        if user_filter:
            query['user_id'] = json.loads(user_filter) if user_filter.startswith('{') else int(user_filter)

        try:
            notes = list(mongo_db.notes.find(query, {'_id': 0}))
            return jsonify({"notes": notes, "source": "mongodb"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    else:
        # Mock MongoDB path - simulates NoSQL injection behavior
        title_filter = request.args.get('title', '')
        user_filter = request.args.get('user_id', '')

        results = MOCK_NOTES_DB.copy()

        # INTENTIONALLY INSECURE: Simulated NoSQL injection
        # If user passes JSON operators like {"$ne": null}, return all records
        if title_filter:
            if title_filter.startswith('{'):
                try:
                    parsed = json.loads(title_filter)
                    if '$ne' in parsed or '$regex' in parsed or '$gt' in parsed:
                        # NoSQL injection successful - return all notes
                        pass  # Don't filter, return everything
                    else:
                        results = [n for n in results if parsed.get('$eq', '') in n['title']]
                except:
                    results = [n for n in results if title_filter.lower() in n['title'].lower()]
            else:
                results = [n for n in results if title_filter.lower() in n['title'].lower()]

        if user_filter:
            if user_filter.startswith('{'):
                try:
                    parsed = json.loads(user_filter)
                    if '$ne' in parsed:
                        # NoSQL injection - bypass user filter
                        pass
                except:
                    pass
            else:
                try:
                    uid = int(user_filter)
                    results = [n for n in results if n['user_id'] == uid]
                except:
                    pass

        return jsonify({"notes": results, "source": "mock-mongodb"})


@nosql_bp.route('/api/notes/search', methods=['POST'])
@require_auth
def search_notes():
    """Search notes with complex query.
    INTENTIONALLY INSECURE: Accepts raw MongoDB query from user.
    TODO: Build queries server-side, never accept raw queries from clients.
    """
    data = request.get_json()

    mongo_db = get_mongo_db()

    if mongo_db:
        # INTENTIONALLY INSECURE: Raw MongoDB query from user input
        # TODO: Never pass user-provided queries directly to MongoDB
        raw_query = data.get('query', {})
        try:
            results = list(mongo_db.notes.find(raw_query, {'_id': 0}))
            return jsonify({"notes": results})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    else:
        # Mock: return all notes if query contains injection operators
        raw_query = data.get('query', {})
        if isinstance(raw_query, dict) and any(k.startswith('$') for k in raw_query.keys()):
            return jsonify({"notes": MOCK_NOTES_DB, "injected": True})
        return jsonify({"notes": MOCK_NOTES_DB[:2]})


@nosql_bp.route('/api/notes', methods=['POST'])
@require_auth
def create_note():
    """Create a new note.
    INTENTIONALLY INSECURE: No input validation.
    TODO: Validate and sanitize all inputs.
    """
    data = request.get_json()

    note = {
        "_id": str(len(MOCK_NOTES_DB) + 1),
        "user_id": g.current_user['user_id'],
        "title": data.get('title', ''),
        "content": data.get('content', ''),
        "tags": data.get('tags', [])
    }

    mongo_db = get_mongo_db()
    if mongo_db:
        mongo_db.notes.insert_one(note)
    else:
        MOCK_NOTES_DB.append(note)

    return jsonify({"message": "Note created", "note": note}), 201
