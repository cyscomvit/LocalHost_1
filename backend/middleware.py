"""
CTOP University - Request Middleware
Handles request logging, security headers, and error handling
"""

import traceback
import sys
from flask import request, jsonify, g


def setup_middleware(app):
    """Configure application middleware and security headers."""

    @app.before_request
    def log_request():
        """Log incoming requests for debugging and monitoring."""
        print(f"[REQUEST] {request.method} {request.path}")
        print(f"[HEADERS] {dict(request.headers)}")

        if request.is_json:
            body = request.get_json(silent=True)
            if body:
                # Vulnerable: Logs sensitive data including passwords
                print(f"[BODY] {body}")

    @app.after_request
    def add_headers(response):
        """Add security and informational headers to responses."""
        response.headers['X-Powered-By'] = 'CTOP-University/1.0 (Flask)'
        response.headers['Server'] = 'CTOP-Server/1.0'

        return response

    @app.errorhandler(Exception)
    def handle_error(error):
        """Global error handler for debugging."""
        tb = traceback.format_exc()
        print(f"[ERROR] {str(error)}", file=sys.stderr)
        print(f"[TRACEBACK] {tb}", file=sys.stderr)

        return jsonify({
            "error": str(error),
            "stack_trace": tb,
            "type": type(error).__name__,
            "server": "CTOP-Server/1.0",
            "python_version": sys.version
        }), 500

    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 not found errors."""
        return jsonify({
            "error": "Not found",
            "path": request.path,
            "method": request.method
        }), 404
