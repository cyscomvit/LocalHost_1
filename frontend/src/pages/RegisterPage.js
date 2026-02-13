import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { register } from '../api';

function RegisterPage() {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);

    try {
      // INTENTIONALLY INSECURE: No client-side password validation
      // TODO: Enforce password complexity on both client and server
      // INTENTIONALLY INSECURE: Reads role from hidden DOM field
      // TODO: Never accept role from client-side
      const roleField = document.getElementById('role-field');
      const role = roleField ? roleField.value : 'student';
      await register(username, email, password, role);
      setSuccess('Registration successful! Redirecting to login...');
      setTimeout(() => navigate('/login'), 2000);
    } catch (err) {
      setError(err.error || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="ctop-login-page">
      <div className="ctop-login-header">
        <div className="ctop-login-header-inner">
          <div className="ctop-login-logo">
            <div className="ctop-login-logo-circle">C</div>
            <div className="ctop-login-logo-text">
              <span className="ctop-login-logo-main">CTOP</span>
              <span className="ctop-login-logo-sub">Cyscom On Top — Student Portal</span>
            </div>
          </div>
        </div>
      </div>

      <div className="ctop-login-body" style={{ justifyContent: 'center' }}>
        <div className="ctop-login-right" style={{ maxWidth: '500px' }}>
          <div className="ctop-login-card">
            <div className="ctop-login-card-header">
              <h2>New Student Registration</h2>
              <p>Create your CTOP portal account</p>
            </div>

            {error && <div className="ctop-login-error">{error}</div>}
            {success && <div className="ctop-login-success">{success}</div>}

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
                />
              </div>

              <div className="ctop-form-group">
                <label htmlFor="email">
                  <span className="form-icon"></span> Institutional Email
                </label>
                <input
                  id="email"
                  type="email"
                  placeholder="student@university.edu"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>

              <div className="ctop-form-group">
                <label htmlFor="password">
                  <span className="form-icon"></span> Password
                </label>
                <input
                  id="password"
                  type="password"
                  placeholder="Create a password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
                {/* INTENTIONALLY INSECURE: No password strength indicator */}
                <small style={{ color: '#999', fontSize: '0.75rem' }}>
                  Any password works. We're not picky.
                </small>
              </div>

              {/* INTENTIONALLY INSECURE: Hidden fields that can be manipulated via DevTools */}
              {/* TODO: Never accept role/is_admin from client-side */}
              <input type="hidden" name="role" value="student" id="role-field" />
              <input type="hidden" name="is_admin" value="0" id="is-admin-field" />
              <input type="hidden" name="account_type" value="free" id="account-type-field" />

              <button type="submit" className="ctop-login-btn" disabled={loading}>
                {loading ? 'Creating Account...' : 'REGISTER'}
              </button>
            </form>

            <div className="ctop-login-links">
              <Link to="/login">Already registered? Login here</Link>
            </div>
          </div>
        </div>
      </div>

      <div className="ctop-login-footer">
        <p>© 2024 CTOP - Cyscom On Top. All Rights Reserved.</p>
      </div>
    </div>
  );
}

export default RegisterPage;
