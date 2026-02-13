import React, { useState, useEffect } from 'react';
import CtopHeader from '../components/CtopHeader';
import CtopSidebar from '../components/CtopSidebar';
import { getUser, changePassword, forgotPassword, resetPassword } from '../api';

function CtopSettings() {
  const [activeSection, setActiveSection] = useState('account');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const user = getUser();

  const [passwordForm, setPasswordForm] = useState({ current: '', newPass: '', confirm: '' });
  const [resetEmail, setResetEmail] = useState(user?.email || '');
  const [resetToken, setResetToken] = useState('');
  const [resetNewPassword, setResetNewPassword] = useState('');
  const [showResetForm, setShowResetForm] = useState(false);

  const [notifications, setNotifications] = useState({
    email_assignments: true,
    email_grades: true,
    email_announcements: true,
    email_fee_reminders: true,
    sms_exam: true,
    sms_attendance: false,
    push_messages: true,
    push_events: true,
  });

  const [privacy, setPrivacy] = useState({
    show_email: true,
    show_phone: false,
    show_cgpa: false,
    profile_visibility: 'classmates',
  });

  const [appearance, setAppearance] = useState({
    theme: 'light',
    language: 'english',
    font_size: 'medium',
    compact_view: false,
  });

  const showMsg = (text) => { setMessage(text); setTimeout(() => setMessage(''), 4000); };
  const showErr = (text) => { setError(text); setTimeout(() => setError(''), 4000); };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    setError('');
    if (passwordForm.newPass !== passwordForm.confirm) {
      showErr('New passwords do not match');
      return;
    }
    if (passwordForm.newPass.length < 3) {
      showErr('Password must be at least 3 characters');
      return;
    }
    setLoading(true);
    try {
      await changePassword(user?.user_id, passwordForm.newPass);
      showMsg('Password changed successfully');
      setPasswordForm({ current: '', newPass: '', confirm: '' });
    } catch (err) {
      showErr(err.error || 'Failed to change password');
    } finally {
      setLoading(false);
    }
  };

  const handleForgotPassword = async () => {
    setLoading(true);
    setError('');
    try {
      const data = await forgotPassword(resetEmail);
      if (data.reset_token) {
        setResetToken(data.reset_token);
      }
      showMsg('Password reset link has been sent to your email');
      setShowResetForm(true);
    } catch (err) {
      showErr(err.error || 'Failed to send reset link');
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async () => {
    if (!resetToken || !resetNewPassword) {
      showErr('Please enter the reset token and new password');
      return;
    }
    setLoading(true);
    try {
      await resetPassword(resetToken, resetNewPassword);
      showMsg('Password has been reset successfully');
      setShowResetForm(false);
      setResetToken('');
      setResetNewPassword('');
    } catch (err) {
      showErr(err.error || 'Failed to reset password');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveNotifications = () => {
    showMsg('Notification preferences saved');
  };

  const handleSavePrivacy = () => {
    showMsg('Privacy settings saved');
  };

  const handleSaveAppearance = () => {
    showMsg('Appearance settings saved');
  };

  const sections = [
    { id: 'account', label: 'Account & Security', icon: '🔒' },
    { id: 'notifications', label: 'Notifications', icon: '🔔' },
    { id: 'privacy', label: 'Privacy', icon: '👁️' },
    { id: 'appearance', label: 'Appearance', icon: '🎨' },
    { id: 'sessions', label: 'Active Sessions', icon: '💻' },
  ];

  return (
    <div className="ctop-app">
      <CtopHeader />
      <div className="ctop-main-container">
        <CtopSidebar />
        <div className="ctop-content-area">
          <div className="ctop-page-title">
            <h2>Settings</h2>
            <p style={{ color: '#757575', fontSize: '0.85rem' }}>
              Manage your account preferences and security settings
            </p>
          </div>

          {message && <div className="ctop-alert success">{message}</div>}
          {error && <div className="ctop-alert error">{error}</div>}

          <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: '1.5rem' }}>
            {/* Settings Navigation */}
            <div className="ctop-card">
              <div style={{ padding: '0.5rem 0' }}>
                {sections.map(s => (
                  <div
                    key={s.id}
                    onClick={() => setActiveSection(s.id)}
                    className={`settings-nav-item ${activeSection === s.id ? 'active' : ''}`}
                  >
                    <span>{s.icon}</span> {s.label}
                  </div>
                ))}
              </div>
            </div>

            {/* Settings Content */}
            <div>
              {/* Account & Security */}
              {activeSection === 'account' && (
                <div>
                  <div className="ctop-card" style={{ marginBottom: '1.5rem' }}>
                    <div className="ctop-section-header"><h3>Account Information</h3></div>
                    <div className="ctop-card-body">
                      <div className="ctop-profile-info">
                        <div className="ctop-profile-row">
                          <span className="ctop-profile-label">Username</span>
                          <span className="ctop-profile-value">{user?.username || '—'}</span>
                        </div>
                        <div className="ctop-profile-row">
                          <span className="ctop-profile-label">Email</span>
                          <span className="ctop-profile-value">{user?.email || '—'}</span>
                        </div>
                        <div className="ctop-profile-row">
                          <span className="ctop-profile-label">Role</span>
                          <span className="ctop-profile-value">{user?.role || 'student'}</span>
                        </div>
                        <div className="ctop-profile-row">
                          <span className="ctop-profile-label">User ID</span>
                          <span className="ctop-profile-value">{user?.user_id || '—'}</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="ctop-card" style={{ marginBottom: '1.5rem' }}>
                    <div className="ctop-section-header"><h3>Change Password</h3></div>
                    <div className="ctop-card-body">
                      <form onSubmit={handleChangePassword}>
                        <div className="ctop-form-group" style={{ marginBottom: '1rem' }}>
                          <label>Current Password</label>
                          <input
                            type="password"
                            value={passwordForm.current}
                            onChange={(e) => setPasswordForm({ ...passwordForm, current: e.target.value })}
                            className="ctop-form-input"
                            placeholder="Enter current password"
                          />
                        </div>
                        <div className="ctop-form-row" style={{ marginBottom: '1rem' }}>
                          <div className="ctop-form-group">
                            <label>New Password</label>
                            <input
                              type="password"
                              value={passwordForm.newPass}
                              onChange={(e) => setPasswordForm({ ...passwordForm, newPass: e.target.value })}
                              className="ctop-form-input"
                              placeholder="Enter new password"
                            />
                          </div>
                          <div className="ctop-form-group">
                            <label>Confirm New Password</label>
                            <input
                              type="password"
                              value={passwordForm.confirm}
                              onChange={(e) => setPasswordForm({ ...passwordForm, confirm: e.target.value })}
                              className="ctop-form-input"
                              placeholder="Confirm new password"
                            />
                          </div>
                        </div>
                        <button type="submit" className="ctop-action-btn primary" disabled={loading}>
                          {loading ? 'Updating...' : 'Update Password'}
                        </button>
                      </form>
                    </div>
                  </div>

                  <div className="ctop-card">
                    <div className="ctop-section-header"><h3>Forgot Password</h3></div>
                    <div className="ctop-card-body">
                      <p style={{ fontSize: '0.85rem', color: '#757575', marginBottom: '1rem' }}>
                        If you've forgotten your password, enter your email to receive a reset link.
                      </p>
                      <div className="ctop-form-group" style={{ marginBottom: '1rem' }}>
                        <label>Email Address</label>
                        <input
                          type="email"
                          value={resetEmail}
                          onChange={(e) => setResetEmail(e.target.value)}
                          className="ctop-form-input"
                          placeholder="Enter your registered email"
                        />
                      </div>
                      <button className="ctop-action-btn secondary" onClick={handleForgotPassword} disabled={loading}>
                        {loading ? 'Sending...' : 'Send Reset Link'}
                      </button>

                      {showResetForm && (
                        <div style={{ marginTop: '1.5rem', paddingTop: '1.5rem', borderTop: '1px solid #e0e0e0' }}>
                          <p style={{ fontSize: '0.85rem', color: '#757575', marginBottom: '1rem' }}>
                            Enter the reset token from your email and your new password.
                          </p>
                          <div className="ctop-form-group" style={{ marginBottom: '1rem' }}>
                            <label>Reset Token</label>
                            <input
                              type="text"
                              value={resetToken}
                              onChange={(e) => setResetToken(e.target.value)}
                              className="ctop-form-input"
                              placeholder="Enter reset token"
                            />
                          </div>
                          <div className="ctop-form-group" style={{ marginBottom: '1rem' }}>
                            <label>New Password</label>
                            <input
                              type="password"
                              value={resetNewPassword}
                              onChange={(e) => setResetNewPassword(e.target.value)}
                              className="ctop-form-input"
                              placeholder="Enter new password"
                            />
                          </div>
                          <button className="ctop-action-btn primary" onClick={handleResetPassword} disabled={loading}>
                            {loading ? 'Resetting...' : 'Reset Password'}
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* Notifications */}
              {activeSection === 'notifications' && (
                <div className="ctop-card">
                  <div className="ctop-section-header"><h3>Notification Preferences</h3></div>
                  <div className="ctop-card-body">
                    <h4 style={{ fontSize: '0.95rem', marginBottom: '1rem', color: '#333' }}>Email Notifications</h4>
                    {[
                      { key: 'email_assignments', label: 'Assignment updates and deadlines' },
                      { key: 'email_grades', label: 'Grade publications and result updates' },
                      { key: 'email_announcements', label: 'University announcements' },
                      { key: 'email_fee_reminders', label: 'Fee payment reminders' },
                    ].map(item => (
                      <div key={item.key} className="settings-row">
                        <span>{item.label}</span>
                        <label className="toggle-switch">
                          <input
                            type="checkbox"
                            checked={notifications[item.key]}
                            onChange={(e) => setNotifications({ ...notifications, [item.key]: e.target.checked })}
                          />
                          <span className="toggle-track">
                            <span className="toggle-thumb" />
                          </span>
                        </label>
                      </div>
                    ))}

                    <h4 style={{ fontSize: '0.95rem', margin: '1.5rem 0 1rem', color: '#333' }}>SMS Notifications</h4>
                    {[
                      { key: 'sms_exam', label: 'Examination schedule alerts' },
                      { key: 'sms_attendance', label: 'Attendance shortage warnings' },
                    ].map(item => (
                      <div key={item.key} className="settings-row">
                        <span>{item.label}</span>
                        <label className="toggle-switch">
                          <input
                            type="checkbox"
                            checked={notifications[item.key]}
                            onChange={(e) => setNotifications({ ...notifications, [item.key]: e.target.checked })}
                          />
                          <span className="toggle-track">
                            <span className="toggle-thumb" />
                          </span>
                        </label>
                      </div>
                    ))}

                    <h4 style={{ fontSize: '0.95rem', margin: '1.5rem 0 1rem', color: '#333' }}>Push Notifications</h4>
                    {[
                      { key: 'push_messages', label: 'New messages from faculty' },
                      { key: 'push_events', label: 'Event and seminar reminders' },
                    ].map(item => (
                      <div key={item.key} className="settings-row">
                        <span>{item.label}</span>
                        <label className="toggle-switch">
                          <input
                            type="checkbox"
                            checked={notifications[item.key]}
                            onChange={(e) => setNotifications({ ...notifications, [item.key]: e.target.checked })}
                          />
                          <span className="toggle-track">
                            <span className="toggle-thumb" />
                          </span>
                        </label>
                      </div>
                    ))}

                    <button className="ctop-action-btn primary" onClick={handleSaveNotifications} style={{ marginTop: '1.5rem' }}>
                      Save Preferences
                    </button>
                  </div>
                </div>
              )}

              {/* Privacy */}
              {activeSection === 'privacy' && (
                <div className="ctop-card">
                  <div className="ctop-section-header"><h3>Privacy Settings</h3></div>
                  <div className="ctop-card-body">
                    <div className="ctop-form-group" style={{ marginBottom: '1.5rem' }}>
                      <label>Profile Visibility</label>
                      <select
                        value={privacy.profile_visibility}
                        onChange={(e) => setPrivacy({ ...privacy, profile_visibility: e.target.value })}
                        className="ctop-form-select"
                      >
                        <option value="everyone">Everyone</option>
                        <option value="classmates">Classmates Only</option>
                        <option value="faculty">Faculty Only</option>
                        <option value="private">Private</option>
                      </select>
                    </div>

                    {[
                      { key: 'show_email', label: 'Show email address on profile' },
                      { key: 'show_phone', label: 'Show phone number on profile' },
                      { key: 'show_cgpa', label: 'Show CGPA on profile' },
                    ].map(item => (
                      <div key={item.key} className="settings-row">
                        <span>{item.label}</span>
                        <label className="toggle-switch">
                          <input
                            type="checkbox"
                            checked={privacy[item.key]}
                            onChange={(e) => setPrivacy({ ...privacy, [item.key]: e.target.checked })}
                          />
                          <span className="toggle-track">
                            <span className="toggle-thumb" />
                          </span>
                        </label>
                      </div>
                    ))}

                    <button className="ctop-action-btn primary" onClick={handleSavePrivacy} style={{ marginTop: '1.5rem' }}>
                      Save Privacy Settings
                    </button>
                  </div>
                </div>
              )}

              {/* Appearance */}
              {activeSection === 'appearance' && (
                <div className="ctop-card">
                  <div className="ctop-section-header"><h3>Appearance</h3></div>
                  <div className="ctop-card-body">
                    <div className="ctop-form-group" style={{ marginBottom: '1.5rem' }}>
                      <label>Theme</label>
                      <select value={appearance.theme} onChange={(e) => setAppearance({ ...appearance, theme: e.target.value })} className="ctop-form-select">
                        <option value="light">Light</option>
                        <option value="dark">Dark</option>
                        <option value="auto">Auto (System)</option>
                      </select>
                    </div>
                    <div className="ctop-form-group" style={{ marginBottom: '1.5rem' }}>
                      <label>Language</label>
                      <select value={appearance.language} onChange={(e) => setAppearance({ ...appearance, language: e.target.value })} className="ctop-form-select">
                        <option value="english">English</option>
                        <option value="hindi">Hindi</option>
                        <option value="tamil">Tamil</option>
                        <option value="telugu">Telugu</option>
                      </select>
                    </div>
                    <div className="ctop-form-group" style={{ marginBottom: '1.5rem' }}>
                      <label>Font Size</label>
                      <select value={appearance.font_size} onChange={(e) => setAppearance({ ...appearance, font_size: e.target.value })} className="ctop-form-select">
                        <option value="small">Small</option>
                        <option value="medium">Medium</option>
                        <option value="large">Large</option>
                      </select>
                    </div>
                    <div className="settings-row">
                      <span>Compact View</span>
                      <label className="toggle-switch">
                        <input type="checkbox" checked={appearance.compact_view} onChange={(e) => setAppearance({ ...appearance, compact_view: e.target.checked })} />
                        <span className="toggle-track">
                          <span className="toggle-thumb" />
                        </span>
                      </label>
                    </div>
                    <button className="ctop-action-btn primary" onClick={handleSaveAppearance} style={{ marginTop: '1.5rem' }}>
                      Save Appearance
                    </button>
                  </div>
                </div>
              )}

              {/* Active Sessions */}
              {activeSection === 'sessions' && (
                <div className="ctop-card">
                  <div className="ctop-section-header"><h3>Active Sessions</h3></div>
                  <div className="ctop-card-body">
                    <p style={{ fontSize: '0.85rem', color: '#757575', marginBottom: '1.5rem' }}>
                      These are the devices currently logged into your account.
                    </p>
                    {[
                      { device: 'Chrome on Windows', ip: '192.168.1.105', location: 'Chennai, India', time: 'Active now', current: true },
                      { device: 'Safari on iPhone', ip: '10.0.0.42', location: 'Chennai, India', time: '2 hours ago', current: false },
                      { device: 'Firefox on Linux', ip: '172.16.0.88', location: 'Vellore, India', time: '1 day ago', current: false },
                    ].map((session, index) => (
                      <div key={index} className="session-item">
                        <div>
                          <div className="session-device">
                            {session.device}
                            {session.current && <span className="ctop-badge ctop-badge-current">Current</span>}
                          </div>
                          <div className="session-meta">
                            {session.ip} · {session.location} · {session.time}
                          </div>
                        </div>
                        {!session.current && (
                          <button className="ctop-action-btn danger" style={{ fontSize: '0.75rem' }}>
                            Revoke
                          </button>
                        )}
                      </div>
                    ))}
                    <button className="ctop-action-btn danger" style={{ marginTop: '1.5rem' }}>
                      Revoke All Other Sessions
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default CtopSettings;
