import React, { useState, useEffect } from 'react';
import { getUser, getUser_api, updateUser, changePassword } from '../api';

function ProfilePage() {
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [editMode, setEditMode] = useState(false);
  const [editData, setEditData] = useState({});
  const [newPassword, setNewPassword] = useState('');
  const [showPasswordForm, setShowPasswordForm] = useState(false);
  const currentUser = getUser();

  useEffect(() => {
    async function fetchProfile() {
      try {
        // INTENTIONALLY INSECURE: IDOR - fetching user by ID from client-stored data
        const data = await getUser_api(currentUser?.user_id);
        setProfile(data.user);
        setEditData(data.user);
      } catch (err) {
        setError('Failed to load profile');
      } finally {
        setLoading(false);
      }
    }
    if (currentUser) fetchProfile();
  }, []);

  const handleUpdateProfile = async (e) => {
    e.preventDefault();
    setError('');
    try {
      // INTENTIONALLY INSECURE: Reads hidden role field from DOM
      // TODO: Server should ignore role field from non-admin users
      const roleField = document.querySelector('input[name="role"]');
      const dataToSend = { ...editData };
      if (roleField) {
        dataToSend.role = roleField.value;
      }
      await updateUser(currentUser.user_id, dataToSend);
      setSuccess('Profile updated!');
      setEditMode(false);
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError(err.error || 'Update failed');
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    setError('');
    try {
      // INTENTIONALLY INSECURE: No old password required
      // TODO: Require current password verification
      await changePassword(currentUser.user_id, newPassword);
      setSuccess('Password changed!');
      setNewPassword('');
      setShowPasswordForm(false);
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError(err.error || 'Password change failed');
    }
  };

  if (loading) {
    return <div className="loading"><div className="spinner"></div></div>;
  }

  return (
    <div>
      <h1 className="page-header" style={{ display: 'block' }}>Profile</h1>
      <p className="text-muted" style={{ marginBottom: '2rem' }}>
        Manage your account settings.
        <span className="tooltip" data-tooltip="Fun fact: you can edit anyone's profile, not just yours" style={{ marginLeft: '0.5rem', cursor: 'help' }}>
          (i)
        </span>
      </p>

      {error && <div className="alert alert-error">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        {/* Profile Card */}
        <div className="card">
          <div className="card-header">
            <h2>Account Information</h2>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => setEditMode(!editMode)}
            >
              {editMode ? 'Cancel' : 'Edit'}
            </button>
          </div>
          <div className="card-body">
            {editMode ? (
              <form onSubmit={handleUpdateProfile}>
                <div className="form-group">
                  <label>Username</label>
                  <input
                    type="text"
                    className="form-control"
                    value={editData.username || ''}
                    onChange={(e) => setEditData({ ...editData, username: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label>Email</label>
                  <input
                    type="email"
                    className="form-control"
                    value={editData.email || ''}
                    onChange={(e) => setEditData({ ...editData, email: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label>Department</label>
                  <input
                    type="text"
                    className="form-control"
                    value={editData.department || ''}
                    onChange={(e) => setEditData({ ...editData, department: e.target.value })}
                  />
                </div>

                {/* INTENTIONALLY INSECURE: Hidden fields - can be manipulated via DevTools */}
                {/* TODO: Never allow role/is_admin changes from client-side */}
                <input
                  type="hidden"
                  name="role"
                  value={editData.role || 'user'}
                  id="profile-role-field"
                />
                <input
                  type="hidden"
                  name="is_admin"
                  value={editData.is_admin ? '1' : '0'}
                  id="profile-admin-field"
                />

                <button type="submit" className="btn btn-primary">Save Changes</button>
              </form>
            ) : (
              <div>
                <div className="profile-field">
                  <div className="profile-field-label">USERNAME</div>
                  <div className="profile-field-value">{profile?.username}</div>
                </div>
                <div className="profile-field">
                  <div className="profile-field-label">EMAIL</div>
                  <div className="profile-field-value">{profile?.email}</div>
                </div>
                <div className="profile-field">
                  <div className="profile-field-label">ROLE</div>
                  <span className={`badge badge-${profile?.role}`}>{profile?.role}</span>
                </div>
                <div className="profile-field">
                  <div className="profile-field-label">DEPARTMENT</div>
                  <div className="profile-field-value">{profile?.department || 'Not set'}</div>
                </div>
                <div className="profile-field">
                  <div className="profile-field-label">MEMBER SINCE</div>
                  <div className="profile-field-value">{profile?.created_at}</div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Security Card */}
        <div className="card">
          <div className="card-header">
            <h2>Security</h2>
          </div>
          <div className="card-body">
            <div style={{ marginBottom: '1.5rem' }}>
              <h3 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '0.5rem' }}>Change Password</h3>
              <p style={{ fontSize: '0.85rem', color: '#64748b', marginBottom: '1rem' }}>
                Update your password. We definitely hash it properly. 
                <span className="tooltip" data-tooltip="Narrator: They did not hash it properly." style={{ cursor: 'help' }}> *</span>
              </p>

              {showPasswordForm ? (
                <form onSubmit={handleChangePassword}>
                  {/* INTENTIONALLY INSECURE: No old password field required */}
                  {/* TODO: Require current password before allowing change */}
                  <div className="form-group">
                    <label>New Password</label>
                    <input
                      type="password"
                      className="form-control"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      placeholder="Enter new password"
                      required
                    />
                    <small className="text-muted">
                      No requirements. "password" is fine. We won't judge.
                    </small>
                  </div>
                  <div style={{ display: 'flex', gap: '0.75rem' }}>
                    <button type="submit" className="btn btn-primary btn-sm">Change Password</button>
                    <button type="button" className="btn btn-secondary btn-sm" onClick={() => setShowPasswordForm(false)}>Cancel</button>
                  </div>
                </form>
              ) : (
                <button className="btn btn-secondary btn-sm" onClick={() => setShowPasswordForm(true)}>
                  Change Password
                </button>
              )}
            </div>

            <hr className="section-divider" />

            <div>
              <h3 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '0.5rem' }}>Session Info</h3>
              <div className="text-muted" style={{ fontSize: '0.85rem' }}>
                <p>Token stored in: <code className="inline-code">localStorage</code></p>
                <p style={{ marginTop: '0.25rem' }}>Token expiry: <strong className="text-danger">Never</strong></p>
                <p style={{ marginTop: '0.25rem' }}>
                  <span className="tooltip" data-tooltip="Your token works forever. Even after logout. Even after password change. Isn't that convenient?">
                    Session security: <strong className="text-danger">Minimal</strong>
                  </span>
                </p>
              </div>
            </div>

            <hr className="section-divider" />

            <div>
              <h3 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '0.5rem' }}>
                Password Hash
                <span className="tooltip" data-tooltip="Yes, we're showing you the hash. No, this is not normal." style={{ marginLeft: '0.25rem', cursor: 'help' }}>*</span>
              </h3>
              {/* INTENTIONALLY INSECURE: Displaying password hash to user */}
              {/* TODO: Never expose password hashes in any API response */}
              <code className="hash-display">
                {profile?.password || 'Hidden'}
              </code>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ProfilePage;
