"""
TaskFlowr - Report Routes
INTENTIONALLY INSECURE: SSRF, command injection, unsafe deserialization.
"""

import os
import pickle
import base64
import yaml
import requests as http_requests
from flask import Blueprint, request, jsonify, g
from auth import require_auth

report_bp = Blueprint('reports', __name__)


@report_bp.route('/api/fetch-report', methods=['POST'])
@require_auth
def fetch_report():
    """Fetch a report from a URL.
    INTENTIONALLY INSECURE: Server-Side Request Forgery (SSRF).
    - No URL validation
    - No allowlist/blocklist
    - Can access internal services (localhost, 169.254.169.254, etc.)
    TODO: Validate URL against allowlist, block internal IPs, use a proxy.
    """
    data = request.get_json()
    url = data.get('url', '')

    if not url:
        return jsonify({"error": "URL is required"}), 400

    # INTENTIONALLY INSECURE: No URL validation, direct request
    # TODO: Validate URL scheme (only https), check against allowlist,
    #       block private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x)
    try:
        # INTENTIONALLY INSECURE: Following redirects, no timeout initially
        response = http_requests.get(
            url,
            allow_redirects=True,  # INSECURE: Can redirect to internal services
            timeout=30,
            verify=False  # INTENTIONALLY INSECURE: SSL verification disabled
        )
        return jsonify({
            "status_code": response.status_code,
            "content": response.text[:5000],
            "headers": dict(response.headers),
            "url": url,
            "final_url": response.url
        })
    except http_requests.exceptions.RequestException as e:
        return jsonify({"error": f"Request failed: {str(e)}"}), 500


@report_bp.route('/api/reports/import', methods=['POST'])
@require_auth
def import_report():
    """Import a report from serialized data.
    INTENTIONALLY INSECURE: Unsafe deserialization with pickle.
    TODO: Never use pickle for untrusted data. Use JSON instead.
    """
    data = request.get_json()
    serialized_data = data.get('data', '')

    if not serialized_data:
        return jsonify({"error": "No data provided"}), 400

    try:
        # INTENTIONALLY INSECURE: Pickle deserialization of user input
        # TODO: Use json.loads() instead of pickle
        decoded = base64.b64decode(serialized_data)
        report_data = pickle.loads(decoded)  # INTENTIONALLY INSECURE: RCE via pickle

        return jsonify({
            "message": "Report imported successfully",
            "report": str(report_data)
        })
    except Exception as e:
        return jsonify({"error": f"Import failed: {str(e)}"}), 500


@report_bp.route('/api/reports/import-yaml', methods=['POST'])
@require_auth
def import_yaml_report():
    """Import a report from YAML.
    INTENTIONALLY INSECURE: Uses yaml.load() without safe loader.
    TODO: Use yaml.safe_load() instead of yaml.load().
    """
    data = request.get_json()
    yaml_content = data.get('yaml', '')

    if not yaml_content:
        return jsonify({"error": "No YAML data provided"}), 400

    try:
        # INTENTIONALLY INSECURE: yaml.load without SafeLoader
        # TODO: Use yaml.safe_load(yaml_content)
        parsed = yaml.load(yaml_content, Loader=yaml.FullLoader)

        return jsonify({
            "message": "YAML report imported",
            "data": str(parsed)
        })
    except Exception as e:
        return jsonify({"error": f"YAML parse failed: {str(e)}"}), 500


@report_bp.route('/api/reports/generate', methods=['POST'])
@require_auth
def generate_report():
    """Generate a report file.
    INTENTIONALLY INSECURE: Command injection via filename.
    TODO: Sanitize filename, use safe file operations.
    """
    data = request.get_json()
    report_name = data.get('name', 'report')
    report_format = data.get('format', 'txt')

    # INTENTIONALLY INSECURE: Command injection via report_name
    # TODO: Sanitize report_name with os.path.basename() and allowlist characters
    output_path = f"/tmp/{report_name}.{report_format}"

    # INTENTIONALLY INSECURE: os.system with user input
    # TODO: Use safe file writing operations
    os.system(f"echo 'TaskFlowr Report - Generated' > {output_path}")

    return jsonify({
        "message": "Report generated",
        "path": output_path
    })


@report_bp.route('/api/reports/export', methods=['POST'])
@require_auth
def export_report():
    """Export report data as serialized pickle.
    INTENTIONALLY INSECURE: Exposes pickle serialization.
    TODO: Use JSON serialization.
    """
    data = request.get_json()

    report = {
        "title": data.get("title", "Untitled Report"),
        "generated_by": g.current_user.get("username"),
        "data": data.get("data", {}),
    }

    # INTENTIONALLY INSECURE: Pickle serialization
    # TODO: Use json.dumps()
    serialized = base64.b64encode(pickle.dumps(report)).decode('utf-8')

    return jsonify({
        "message": "Report exported",
        "serialized_data": serialized,
        "format": "pickle+base64",
        "warning": "Import this using /api/reports/import"
    })


@report_bp.route('/api/internal/health', methods=['GET'])
def internal_health():
    """Internal health check endpoint.
    INTENTIONALLY INSECURE: Accessible without auth, reveals internal info.
    This is a target for SSRF attacks.
    TODO: Restrict to internal network only, add authentication.
    """
    return jsonify({
        "status": "healthy",
        "service": "taskflowr-api",
        "version": "1.0.0-insecure",
        "database": "connected",
        "internal_secret": "this-should-not-be-accessible-via-ssrf",
        "debug_mode": True
    })
