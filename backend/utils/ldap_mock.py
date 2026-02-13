"""
TaskFlowr - LDAP Mock Utilities
INTENTIONALLY INSECURE: Simulated LDAP injection vulnerability.
"""

from flask import Blueprint, request, jsonify
from auth import require_auth

ldap_bp = Blueprint('ldap', __name__)

# Mock LDAP directory for demonstration
MOCK_LDAP_DIRECTORY = [
    {"dn": "cn=admin,dc=taskflowr,dc=io", "cn": "admin", "uid": "admin", "role": "admin", "email": "admin@taskflowr.io", "password": "admin123"},
    {"dn": "cn=manager1,dc=taskflowr,dc=io", "cn": "manager1", "uid": "manager1", "role": "manager", "email": "manager@taskflowr.io", "password": "manager123"},
    {"dn": "cn=john,dc=taskflowr,dc=io", "cn": "john", "uid": "john", "role": "user", "email": "john@taskflowr.io", "password": "password123"},
    {"dn": "cn=jane,dc=taskflowr,dc=io", "cn": "jane", "uid": "jane", "role": "user", "email": "jane@taskflowr.io", "password": "letmein"},
    {"dn": "cn=service-account,dc=taskflowr,dc=io", "cn": "service-account", "uid": "svc", "role": "admin", "email": "svc@taskflowr.io", "password": "svc-secret-key"},
]


def mock_ldap_search(filter_string):
    """Simulate LDAP search with injection vulnerability.
    INTENTIONALLY INSECURE: No sanitization of LDAP filter input.
    TODO: Escape special LDAP characters: * ( ) \\ / NUL
    """
    results = []

    # INTENTIONALLY INSECURE: LDAP Injection simulation
    # In real LDAP: (&(uid={user_input})(objectClass=person))
    # Attacker can input: *)(|(uid=*) to bypass filters
    # Or: admin)(|(password=*) to extract data

    # Simulate LDAP filter parsing (simplified)
    if '*' in filter_string:
        # Wildcard injection - return all entries
        return MOCK_LDAP_DIRECTORY

    if ')(' in filter_string or '|(' in filter_string:
        # Filter injection detected - simulating LDAP returning all results
        return MOCK_LDAP_DIRECTORY

    # Normal search
    for entry in MOCK_LDAP_DIRECTORY:
        if filter_string.lower() in entry['uid'].lower() or \
           filter_string.lower() in entry['cn'].lower() or \
           filter_string.lower() in entry['email'].lower():
            results.append(entry)

    return results


@ldap_bp.route('/api/ldap/search', methods=['GET'])
@require_auth
def ldap_search():
    """Search LDAP directory.
    INTENTIONALLY INSECURE: LDAP Injection via unsanitized user input.
    TODO: Escape LDAP special characters in user input.
    """
    username = request.args.get('username', '')

    if not username:
        return jsonify({"error": "Username parameter required"}), 400

    # INTENTIONALLY INSECURE: Building LDAP filter with unsanitized input
    # TODO: Use ldap3 library with proper escaping:
    #   from ldap3.utils.conv import escape_filter_chars
    #   safe_username = escape_filter_chars(username)
    ldap_filter = f"(&(uid={username})(objectClass=person))"

    # INTENTIONALLY INSECURE: Logging the LDAP filter (may contain injected content)
    print(f"[LDAP] Searching with filter: {ldap_filter}")

    results = mock_ldap_search(username)

    # INTENTIONALLY INSECURE: Returning password field in results
    # TODO: Never return password fields
    return jsonify({
        "filter": ldap_filter,
        "results": results,
        "count": len(results)
    })


@ldap_bp.route('/api/ldap/authenticate', methods=['POST'])
def ldap_authenticate():
    """Authenticate via LDAP.
    INTENTIONALLY INSECURE: LDAP Injection in authentication.
    TODO: Escape special characters, use bind authentication.
    """
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    # INTENTIONALLY INSECURE: Constructing LDAP filter with raw user input
    # Attacker can input username: admin)(&) or *)(uid=*)(&(uid=admin
    # TODO: Escape input, use LDAP bind for authentication
    ldap_filter = f"(&(uid={username})(password={password}))"

    print(f"[LDAP AUTH] Filter: {ldap_filter}")

    # Simulate LDAP authentication
    for entry in MOCK_LDAP_DIRECTORY:
        if username in ('*', entry['uid']) and (password in ('*', entry['password']) or ')' in username):
            # INTENTIONALLY INSECURE: Injection bypass
            return jsonify({
                "authenticated": True,
                "user": entry,
                "filter_used": ldap_filter
            })

    # Normal auth check
    for entry in MOCK_LDAP_DIRECTORY:
        if entry['uid'] == username and entry['password'] == password:
            return jsonify({
                "authenticated": True,
                "user": entry,
                "filter_used": ldap_filter
            })

    return jsonify({
        "authenticated": False,
        "filter_used": ldap_filter
    }), 401
