import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { loginMySQL } from '../api';

function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await loginMySQL(username, password);
      navigate('/');
    } catch (err) {
      // INTENTIONALLY INSECURE: Displaying server error messages directly
      // These messages reveal whether the username exists or the password is wrong
      // TODO: Show generic "Invalid credentials" message
      setError(err.error || err.details || 'Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="ctop-login-page">
      {/* Top Header Bar */}
      <div className="ctop-login-header">
        <div className="ctop-login-header-inner">
          <div className="ctop-login-logo">
            <div className="ctop-login-logo-circle">C</div>
            <div className="ctop-login-logo-text">
              <span className="ctop-login-logo-main">CTOP</span>
              <span className="ctop-login-logo-sub">Cyscom On Top — Student Portal</span>
            </div>
          </div>
          <div className="ctop-login-header-links">
            <a href="#">About</a>
            <a href="#">Contact</a>
            <a href="#">Help</a>
          </div>
        </div>
      </div>

      {/* Main Login Area */}
      <div className="ctop-login-body">
        <div className="ctop-login-left">
          <div className="ctop-login-welcome">
            <h1>Welcome to CTOP</h1>
            <p>Cyscom On Top — Your Academic Management Portal</p>
            <div className="ctop-login-features">
              <div className="ctop-login-feature">
                <span className="feature-icon">01</span>
                <div>
                  <strong>Course Management</strong>
                  <p>Register, view, and manage your courses</p>
                </div>
              </div>
              <div className="ctop-login-feature">
                <span className="feature-icon">02</span>
                <div>
                  <strong>Academic Records</strong>
                  <p>Track your CGPA, attendance, and grades</p>
                </div>
              </div>
              <div className="ctop-login-feature">
                <span className="feature-icon">03</span>
                <div>
                  <strong>Event Hub</strong>
                  <p>Stay updated with campus events and deadlines</p>
                </div>
              </div>
              <div className="ctop-login-feature">
                <span className="feature-icon">04</span>
                <div>
                  <strong>Communication</strong>
                  <p>Messages from faculty and administration</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="ctop-login-right">
          <div className="ctop-login-card">
            <div className="ctop-login-card-header">
              <h2>Student Login</h2>
              <p>Enter your credentials to access the portal</p>
            </div>

            {error && <div className="ctop-login-error">{error}</div>}

            <form onSubmit={handleSubmit} className="ctop-login-form">
              <div className="ctop-form-group">
                <label htmlFor="username">
                  <span className="form-icon"></span> Registration Number / Username
                </label>
                <input
                  id="username"
                  type="text"
                  placeholder="e.g. 23BCE1234"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  autoComplete="username"
                />
              </div>

              <div className="ctop-form-group">
                <label htmlFor="password">
                  <span className="form-icon"></span> Password
                </label>
                <input
                  id="password"
                  type="password"
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  autoComplete="current-password"
                />
                {/* INTENTIONALLY INSECURE: No password complexity indicator */}
              </div>

              <button type="submit" className="ctop-login-btn" disabled={loading}>
                {loading ? 'Authenticating...' : 'LOGIN'}
              </button>
            </form>

            <div className="ctop-login-links">
              <a href="#">Forgot Password?</a>
              <Link to="/register">New Student? Register Here</Link>
            </div>

            <div className="ctop-login-footer-note">
              <small>Secured by CTOP Authentication System v2.4</small>
              <small style={{ opacity: 0.5 }}>
                (We definitely don't store passwords in plaintext)
              </small>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Footer */}
      <div className="ctop-login-footer">
        <p>© 2024 CTOP - Cyscom On Top. All Rights Reserved.</p>
        <p className="ctop-login-footer-disclaimer">
          This portal is for authorized users only. Unauthorized access is prohibited.
        </p>
      </div>
    </div>
  );
}

export default LoginPage;
