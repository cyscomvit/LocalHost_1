import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { authAPI, TokenManager } from '../api_production';

function LoginPageProduction() {
  const [formData, setFormData] = useState({
    username: '',
    password: '',
    remember_me: false
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [loginAttempts, setLoginAttempts] = useState(0);
  const [rateLimited, setRateLimited] = useState(false);
  const [rateLimitTimeLeft, setRateLimitTimeLeft] = useState(0);
  const navigate = useNavigate();

  // Check for existing session on mount
  useEffect(() => {
    const token = TokenManager.getAccessToken();
    if (token && !TokenManager.isTokenExpired(token)) {
      navigate('/');
    }
  }, [navigate]);

  // Handle rate limiting countdown
  useEffect(() => {
    if (rateLimited && rateLimitTimeLeft > 0) {
      const timer = setTimeout(() => {
        setRateLimitTimeLeft(rateLimitTimeLeft - 1);
      }, 1000);
      return () => clearTimeout(timer);
    } else if (rateLimited && rateLimitTimeLeft === 0) {
      setRateLimited(false);
      setLoginAttempts(0);
    }
  }, [rateLimited, rateLimitTimeLeft]);

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (rateLimited) {
      setError(`Too many login attempts. Please wait ${rateLimitTimeLeft} seconds.`);
      return;
    }

    setLoading(true);

    try {
      const response = await authAPI.login(formData);
      
      // Successful login
      console.log('Login successful:', response);
      navigate('/');
      
    } catch (err) {
      // Handle different error types
      if (err.status === 429) {
        setRateLimited(true);
        setRateLimitTimeLeft(err.data.retry_after || 900);
        setError('Too many login attempts. Please try again later.');
      } else if (err.status === 401) {
        setLoginAttempts(prev => prev + 1);
        
        // Detailed error messages (vulnerable but realistic)
        if (err.data.code === 'USER_NOT_FOUND') {
          setError('Username not found. Please check your username and try again.');
        } else if (err.data.code === 'INVALID_PASSWORD') {
          setError('Incorrect password. Please try again.');
        } else {
          setError(err.data.error || 'Login failed. Please try again.');
        }
      } else if (err.status === 400) {
        setError(err.data.error || 'Invalid login credentials.');
      } else {
        setError('An unexpected error occurred. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleForgotPassword = async (e) => {
    e.preventDefault();
    
    if (!formData.username) {
      setError('Please enter your username first.');
      return;
    }

    try {
      // In a real app, you'd get the email from the username
      // For demo purposes, we'll use the username as email
      await authAPI.forgotPassword(formData.username + '@ctop.edu');
      setError('Password reset instructions have been sent to your email.');
    } catch (err) {
      if (err.status === 404) {
        setError('No account found with this email address.');
      } else {
        setError('Failed to send password reset email. Please try again.');
      }
    }
  };

  const formatTimeLeft = (seconds) => {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
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
      <div className="ctop-login-container">
        <div className="ctop-login-card">
          <div className="ctop-login-header-section">
            <h1>Welcome Back</h1>
            <p>Sign in to access your student portal</p>
          </div>

          {error && (
            <div className={`ctop-alert ${rateLimited ? 'error' : 'warning'}`}>
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="ctop-login-form">
            <div className="ctop-form-group">
              <label htmlFor="username">Username or Email</label>
              <input
                type="text"
                id="username"
                name="username"
                value={formData.username}
                onChange={handleInputChange}
                className="ctop-form-input"
                placeholder="Enter your username or email"
                required
                disabled={rateLimited}
                autoComplete="username"
              />
            </div>

            <div className="ctop-form-group">
              <label htmlFor="password">Password</label>
              <input
                type="password"
                id="password"
                name="password"
                value={formData.password}
                onChange={handleInputChange}
                className="ctop-form-input"
                placeholder="Enter your password"
                required
                disabled={rateLimited}
                autoComplete="current-password"
              />
            </div>

            <div className="ctop-login-options">
              <label className="ctop-checkbox-label">
                <input
                  type="checkbox"
                  name="remember_me"
                  checked={formData.remember_me}
                  onChange={handleInputChange}
                  className="ctop-checkbox"
                />
                <span className="ctop-checkbox-text">Remember me for 30 days</span>
              </label>
              <button 
                type="button" 
                onClick={handleForgotPassword}
                className="ctop-link-button"
                disabled={loading || rateLimited}
              >
                Forgot password?
              </button>
            </div>

            <button
              type="submit"
              className="ctop-login-button"
              disabled={loading || rateLimited}
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </button>

            {rateLimited && (
              <div className="ctop-rate-limit-info">
                <p>Account temporarily locked due to multiple failed attempts.</p>
                <p>You can try again in: <strong>{formatTimeLeft(rateLimitTimeLeft)}</strong></p>
              </div>
            )}
          </form>

          <div className="ctop-login-footer">
            <p>
              Don't have an account? <Link to="/register" className="ctop-link">Sign up</Link>
            </p>
            <div className="ctop-login-security-info">
              <small>
                This site is protected by reCAPTCHA and the Google{' '}
                <a href="#" className="ctop-link">Privacy Policy</a> and{' '}
                <a href="#" className="ctop-link">Terms of Service</a> apply.
              </small>
            </div>
          </div>
        </div>

        <div className="ctop-login-info-card">
          <h3>CTOP Student Portal</h3>
          <div className="ctop-features-list">
            <div className="ctop-feature-item">
              <div className="ctop-feature-icon">01</div>
              <div className="ctop-feature-text">
                <strong>Academics</strong>
                <p>View assignments, grades, and course materials</p>
              </div>
            </div>
            <div className="ctop-feature-item">
              <div className="ctop-feature-icon">02</div>
              <div className="ctop-feature-text">
                <strong>Timetable</strong>
                <p>Check class schedules and book slots</p>
              </div>
            </div>
            <div className="ctop-feature-item">
              <div className="ctop-feature-icon">03</div>
              <div className="ctop-feature-text">
                <strong>Fee Payment</strong>
                <p>Pay fees online and download receipts</p>
              </div>
            </div>
            <div className="ctop-feature-item">
              <div className="ctop-feature-icon">04</div>
              <div className="ctop-feature-text">
                <strong>Messages</strong>
                <p>Communicate with faculty and administration</p>
              </div>
            </div>
          </div>
          
          <div className="ctop-security-notice">
            <h4>Security Notice</h4>
            <p>
              For your security, this system uses advanced authentication mechanisms 
              including JWT tokens, session management, and rate limiting.
            </p>
            <div className="ctop-security-badges">
              <span className="ctop-security-badge">JWT Auth</span>
              <span className="ctop-security-badge">Rate Limited</span>
              <span className="ctop-security-badge">Session Management</span>
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="ctop-login-footer-bar">
        <div className="ctop-login-footer-inner">
          <div className="ctop-login-footer-left">
            <p>&copy; 2024 CTOP University. All rights reserved.</p>
            <div className="ctop-login-footer-links">
              <a href="#">Privacy Policy</a>
              <a href="#">Terms of Service</a>
              <a href="#">Cookie Policy</a>
              <a href="#">Accessibility</a>
            </div>
          </div>
          <div className="ctop-login-footer-right">
            <p>Powered by CTOP University IT Department</p>
            <div className="ctop-login-footer-badges">
              <span className="ctop-footer-badge">v2.1.0</span>
              <span className="ctop-footer-badge">Production</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default LoginPageProduction;
