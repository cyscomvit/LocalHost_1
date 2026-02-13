"""
CTOP University - Main Application
Student and faculty management system
"""

import os
from dotenv import load_dotenv
from flask import Flask, jsonify
from flask_cors import CORS
from models import init_db
from middleware import setup_middleware

# Load environment variables from .env file
load_dotenv()

# Route imports
from routes.auth_routes_production import auth_bp
from routes.task_routes import task_bp
from routes.user_routes import user_bp
from routes.admin_routes import admin_bp
from routes.report_routes import report_bp
from routes.reimbursement_routes import reimbursement_bp
try:
    from routes.nosql_routes import nosql_bp
except Exception as e:
    print(f"[WARNING] Could not import nosql_routes: {e}")
    print("[WARNING] NoSQL routes will be disabled")
    nosql_bp = None
from routes.csrf_routes import csrf_bp
from routes.security_routes import security_bp
from routes.session_routes import session_bp
from utils.ldap_mock import ldap_bp
# from insecure_examples import examples_bp
from routes.ctf_routes import ctf_bp
from routes.academic_routes import academic_bp
from routes.privesc_routes import privesc_bp
from utils.ldap_mock import ldap_bp
# from insecure_examples import examples_bp
try:
    from routes.cors_demo_routes import cors_demo_bp
except Exception as e:
    print(f"[WARNING] Could not import cors_demo_routes: {e}")
    print("[WARNING] CORS demo routes will be disabled")
    cors_demo_bp = None
from routes.broken_access_routes import broken_access_bp
from routes.xss_demo import xss_bp
from routes.hidden_routes import hidden_bp


def create_app():
    app = Flask(__name__)

    # INTENTIONALLY INSECURE: Debug mode enabled in "production"
    # TODO: Set DEBUG=False in production
    app.config['DEBUG'] = True

    # INTENTIONALLY INSECURE: Hardcoded secret key
    # TODO: Use a strong random secret from environment variable
    app.config['SECRET_KEY'] = 'taskflowr-flask-secret-not-so-secret'

    # INTENTIONALLY INSECURE: Session cookie configuration
    # TODO: Set SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=True,
    #       SESSION_COOKIE_SAMESITE='Strict'
    app.config['SESSION_COOKIE_HTTPONLY'] = False
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['SESSION_COOKIE_SAMESITE'] = None

    # ============================================================
    # CORS MISCONFIGURATION - Multiple attack vectors
    # ============================================================
    # 1. Wildcard + credentials = any site can steal data
    # 2. No origin validation (see response_headers.py)
    # 3. Null origin allowed (file:// attacks)
    # 4. Broken regex validation (evil.com.ctop.edu bypasses)
    # 5. Missing Vary header (cache poisoning)
    # 6. Subdomain takeover possible
    # 7. DNS rebinding attack vector
    # Demo: /cors-attack/exfiltrate.html
    CORS(app,
         origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # INTENTIONALLY INSECURE: Should be more restrictive
         supports_credentials=True,
         allow_headers=["*"],
         expose_headers=["*"],
         methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])

    # Setup middleware (logging, error handling, headers)
    setup_middleware(app)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(task_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(reimbursement_bp)
    if nosql_bp:
        app.register_blueprint(nosql_bp)
    app.register_blueprint(csrf_bp)
    app.register_blueprint(security_bp)
    app.register_blueprint(session_bp)
    app.register_blueprint(ctf_bp)
    app.register_blueprint(privesc_bp)
    app.register_blueprint(academic_bp) 
    app.register_blueprint(ldap_bp)
    # app.register_blueprint(examples_bp)
    if cors_demo_bp:
        app.register_blueprint(cors_demo_bp)
    app.register_blueprint(broken_access_bp)
    app.register_blueprint(xss_bp)
    app.register_blueprint(hidden_bp)

    # ============================================================
    # API DOCUMENTATION (intentionally reveals too much)
    # ============================================================
    @app.route('/api/docs', methods=['GET'])
    def api_docs():
        """API documentation endpoint.
        INTENTIONALLY INSECURE: Reveals all endpoints including admin/internal.
        TODO: Only document public endpoints, require auth for full docs.
        """
        return jsonify({
            "name": "TaskFlowr API",
            "version": "1.0.0",
            "motto": "Move fast. Break things. Deploy anyway.",
            "endpoints": {
                "auth": {
                    "POST /api/auth/register": "Register a new user",
                    "POST /api/auth/login": "Login",
                    "POST /api/auth/login-plaintext": "Login (plaintext mode)",
                    "POST /api/auth/logout": "Logout",
                    "POST /api/auth/forgot-password": "Request password reset",
                    "POST /api/auth/reset-password": "Reset password with token",
                    "GET /api/auth/me": "Get current user",
                    "GET /api/auth/debug-token": "Debug JWT configuration",
                },
                "tasks": {
                    "GET /api/tasks": "List tasks (supports ?search= and ?status=)",
                    "GET /api/tasks/<id>": "Get task by ID",
                    "POST /api/tasks": "Create task",
                    "PUT /api/tasks/<id>": "Update task",
                    "DELETE /api/tasks/<id>": "Delete task",
                    "POST /api/tasks/bulk-update": "Bulk update tasks",
                },
                "users": {
                    "GET /api/users": "List all users",
                    "GET /api/users/<id>": "Get user by ID",
                    "PUT /api/users/<id>": "Update user",
                    "POST /api/users/<id>/change-password": "Change password",
                    "GET /api/users/search?q=": "Search users",
                    "GET /api/users/<id>/tasks": "Get user's tasks",
                },
                "admin": {
                    "GET /api/admin/users": "Admin: List users",
                    "PUT /api/admin/users/<id>/role": "Admin: Change role",
                    "GET /api/admin/system-info": "Admin: System info",
                    "POST /api/admin/run-diagnostic": "Admin: Run command",
                    "POST /api/admin/exec": "Admin: Execute command",
                    "POST /api/admin/database/query": "Admin: Raw SQL",
                    "GET /api/admin/stats": "Admin: Dashboard stats",
                    "POST /api/admin/backup": "Admin: Create backup",
                    "GET /api/admin/secret-config": "Admin: Secret config",
                },
                "reports": {
                    "POST /api/fetch-report": "Fetch report from URL (SSRF demo)",
                    "POST /api/reports/import": "Import pickle report",
                    "POST /api/reports/import-yaml": "Import YAML report",
                    "POST /api/reports/generate": "Generate report",
                    "POST /api/reports/export": "Export report as pickle",
                    "GET /api/internal/health": "Internal health check",
                },
                "reimbursements": {
                    "GET /api/reimbursements": "List reimbursements",
                    "POST /api/reimbursements": "Create reimbursement",
                    "POST /api/reimbursements/<id>/approve": "Approve reimbursement",
                    "POST /api/reimbursements/<id>/reject": "Reject reimbursement",
                },
                "notes_nosql": {
                    "GET /api/notes?title=&user_id=": "Get notes (NoSQL injection)",
                    "POST /api/notes/search": "Search notes with raw query",
                    "POST /api/notes": "Create note",
                },
                "ldap": {
                    "GET /api/ldap/search?username=": "LDAP search",
                    "POST /api/ldap/authenticate": "LDAP authentication",
                },
                "csrf": {
                    "POST /api/csrf/transfer": "Transfer tasks (CSRF vuln)",
                    "POST /api/csrf/change-email": "Change email (CSRF vuln)",
                    "POST /api/csrf/change-password": "Change password (CSRF vuln)",
                    "GET /api/csrf/demo-page": "CSRF attack demo page (pizza trap)",
                },
                "cors_vulnerabilities": {
                    "GET /api/cors-demo/user/secrets": "Sensitive data with wildcard CORS",
                    "POST /api/cors-demo/user/upgrade-role": "Privilege escalation via CORS",
                    "GET /api/cors-demo/test-origin": "Test origin validation bypasses",
                    "GET /api/cors-demo/challenge": "CORS configuration challenge",
                    "GET /api/cors-demo/dns-rebinding-info": "DNS rebinding attack info",
                    "GET /cors-attack/exfiltrate.html": "CORS data exfiltration attack page",
                    "GET /cors-attack/privilege-escalation.html": "CORS privilege escalation attack page"
                },
                "hidden_endpoints": {
                    "GET /api/internal/system-info": "System diagnostics (no auth)",
                    "GET /api/internal/users/export": "Full user data export with passwords",
                    "POST /api/internal/db-console": "Arbitrary SQL execution",
                    "GET /api/backup": "Database backup dump with password hashes",
                    "GET /api/internal/config": "Application config with DB creds and JWT secret",
                    "POST /api/internal/reset-password": "Reset any user password without auth",
                    "POST /api/internal/make-admin": "Promote any user to admin without auth"
                },
                "examples": {
                    "GET /.env": "Exposed environment file",
                    "GET /api/examples/xss-reflect?name=": "Reflected XSS",
                    "POST /api/examples/xss-stored": "Stored XSS",
                    "GET /api/examples/download?file=": "Path traversal",
                    "GET /api/examples/generate-token": "Insecure random",
                    "GET /api/examples/debug": "Debug info disclosure",
                    "POST /api/examples/update-profile": "Mass assignment",
                    "GET /api/examples/redirect?url=": "Open redirect",
                    "GET /api/examples/set-header?value=": "Header injection",
                    "POST /api/examples/calculate": "Unsafe eval",
                    "GET /api/examples/error-demo?type=": "Verbose errors",
                },
                "broken_access": {
                    "GET /api/broken-access/user/<id>/profile": "View any user profile (vulnerable)",
                    "GET /api/broken-access/admin/users": "List all users without auth (vulnerable)",
                }
            }
        })

    @app.route('/', methods=['GET'])
    def index():
        return jsonify({
            "name": "TaskFlowr API",
            "version": "1.0.0",
            "status": "running",
            "docs": "/api/docs",
            "motto": "Move fast. Break things. Deploy anyway. 🚀"
        })

    return app


if __name__ == '__main__':
    print("=" * 60)
    print("  TaskFlowr API Server")
    print("  'Move fast. Break things. Deploy anyway.'")
    print("=" * 60)
    print()
    print("  ⚠️  WARNING: This application is INTENTIONALLY INSECURE")
    print("  ⚠️  DO NOT deploy in production!")
    print("  ⚠️  For educational purposes only.")
    print()
    print("=" * 60)

    # Initialize database
    init_db()

    # Create and run app
    app = create_app()

    # INTENTIONALLY INSECURE: Binding to all interfaces, debug mode on
    # TODO: Bind to 127.0.0.1 only, disable debug in production
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True  # INTENTIONALLY INSECURE: Debug mode exposes Werkzeug debugger
    )
