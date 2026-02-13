import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import CtopHeader from '../components/CtopHeader';
import CtopSidebar from '../components/CtopSidebar';
import { getUser, getMySQLProfile, updateMySQLProfile, changePassword } from '../api';

/**
 * CTOP Profile Page
 * View and manage student profile information from MySQL database
 * 
 * INTENTIONALLY INSECURE: IDOR Vulnerability
 * Access any user's profile by changing URL: /profile/1, /profile/2, /profile/3...
 */
function CtopProfile() {
  const { id } = useParams(); // Read user ID from URL
  const navigate = useNavigate();
  const [profile, setProfile] = useState(null);
  const [editData, setEditData] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [editMode, setEditMode] = useState(false);
  const [newPassword, setNewPassword] = useState('');
  const [showPasswordForm, setShowPasswordForm] = useState(false);
  const currentUser = getUser();

  // INTENTIONALLY INSECURE: Fetch any user's profile based on URL parameter
  // No authorization check to prevent viewing other users' profiles
  useEffect(() => {
    // Redirect to user's own profile URL if no ID specified
    if (!id) {
      const currentUserData = getUser();
      if (currentUserData) {
        const userId = currentUserData.user_id || currentUserData.id;
        navigate(`/profile/${userId}`, { replace: true });
      }
      return;
    }

    async function fetchProfile() {
      try {
        // Fetch profile for the ID in the URL (IDOR vulnerability)
        console.log(`[IDOR] Fetching profile for user ID: ${id}`);
        
        const data = await getMySQLProfile(id);
        setProfile(data.user);
        setEditData(data.user);
      } catch (err) {
        console.error('Profile fetch error:', err);
        setError('Failed to load profile: ' + (err.error || err.details || 'Unknown error'));
      } finally {
        setLoading(false);
      }
    }
    
    fetchProfile();
  }, [id]); // Only re-fetch when URL ID changes

  const handleUpdateProfile = async (e) => {
    e.preventDefault();
    setError('');
    try {
      // INTENTIONALLY INSECURE: Update any user's profile based on URL parameter
      // Should check if currentUser matches the profile being edited
      const targetId = id || currentUser.user_id || currentUser.id;
      console.log(`[IDOR] Updating profile for user ID: ${targetId}`);
      
      await updateMySQLProfile(targetId, editData);
      setSuccess('Profile updated successfully!');
      setEditMode(false);
      const data = await getMySQLProfile(targetId);
      setProfile(data.user);
      setTimeout(() => setSuccess(''), 5000);
    } catch (err) {
      setError(err.error || err.details || 'Update failed');
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    setError('');
    try {
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
    return (
      <div className="ctop-app">
        <CtopHeader />
        <div className="ctop-main-container">
          <CtopSidebar />
          <div className="ctop-content-area"><div className="ctop-loading">Loading profile...</div></div>
        </div>
      </div>
    );
  }

  return (
    <div className="ctop-app">
      <CtopHeader />
      <div className="ctop-main-container">
        <CtopSidebar />
        <div className="ctop-content-area">
          <div className="ctop-page-title">
            <h2>Student Profile</h2>
            <p style={{ color: '#757575', fontSize: '0.85rem' }}>View and manage your account information</p>
          </div>

          {error && <div className="ctop-alert error">{error}</div>}
          {success && <div className="ctop-alert success">{success}</div>}

          <div style={{ maxWidth: '800px' }}>
            {/* Profile Info Card */}
            <div className="ctop-card">
              <div className="ctop-section-header">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <h3>PERSONAL INFORMATION</h3>
                  <span style={{ fontSize: '0.75rem', color: '#999', fontFamily: 'monospace' }}>
                    {window.location.pathname}
                  </span>
                </div>
              </div>
              <div className="ctop-card-body">
                {!editMode ? (
                  <div className="ctop-profile-info">
                    <div className="ctop-profile-row">
                      <span className="ctop-profile-label">Student ID:</span>
                      <span className="ctop-profile-value">{profile?.student_id}</span>
                    </div>
                    <div className="ctop-profile-row">
                      <span className="ctop-profile-label">Full Name:</span>
                      <span className="ctop-profile-value">{profile?.full_name}</span>
                    </div>
                    <div className="ctop-profile-row">
                      <span className="ctop-profile-label">Username:</span>
                      <span className="ctop-profile-value">{profile?.username}</span>
                    </div>
                    <div className="ctop-profile-row">
                      <span className="ctop-profile-label">Email:</span>
                      <span className="ctop-profile-value">{profile?.email}</span>
                    </div>
                    <div className="ctop-profile-row">
                      <span className="ctop-profile-label">Program:</span>
                      <span className="ctop-profile-value">{profile?.program}</span>
                    </div>
                    <div className="ctop-profile-row">
                      <span className="ctop-profile-label">Semester:</span>
                      <span className="ctop-profile-value">{profile?.semester}</span>
                    </div>
                    <div className="ctop-profile-row">
                      <span className="ctop-profile-label">CGPA:</span>
                      <span className="ctop-profile-value">{profile?.cgpa}</span>
                    </div>
                    <div className="ctop-profile-row">
                      <span className="ctop-profile-label">Admin Status:</span>
                      <span className="ctop-profile-value">
                        <span className={`ctop-badge ${profile?.is_admin ? 'ctop-badge-success' : 'ctop-badge-danger'}`}>
                          {profile?.is_admin ? 'ADMIN' : 'STUDENT'}
                        </span>
                      </span>
                    </div>
                    <div className="ctop-profile-row">
                      <span className="ctop-profile-label">User ID:</span>
                      <span className="ctop-profile-value">#{profile?.id}</span>
                    </div>
                    <div style={{ marginTop: '1rem', display: 'flex', gap: '0.5rem' }}>
                      <button className="ctop-action-btn primary" onClick={() => setEditMode(true)}>Edit Profile</button>
                      <button className="ctop-action-btn secondary" onClick={() => setShowPasswordForm(!showPasswordForm)}>Change Password</button>
                    </div>
                  </div>
                ) : (
                  <form onSubmit={handleUpdateProfile}>
                    <div className="ctop-form-group">
                      <label>Full Name</label>
                      <input type="text" value={editData.full_name || ''} onChange={(e) => setEditData({...editData, full_name: e.target.value})} />
                    </div>
                    <div className="ctop-form-group">
                      <label>Email</label>
                      <input type="email" value={editData.email || ''} onChange={(e) => setEditData({...editData, email: e.target.value})} />
                    </div>
                    <div className="ctop-form-group">
                      <label>Program</label>
                      <input type="text" value={editData.program || ''} onChange={(e) => setEditData({...editData, program: e.target.value})} />
                    </div>
                    <div className="ctop-form-group">
                      <label>Semester</label>
                      <input type="number" value={editData.semester || ''} onChange={(e) => setEditData({...editData, semester: parseInt(e.target.value)})} />
                    </div>
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <button type="submit" className="ctop-action-btn primary">Save</button>
                      <button type="button" className="ctop-action-btn secondary" onClick={() => setEditMode(false)}>Cancel</button>
                    </div>
                  </form>
                )}

                {/* Password Change Form */}
                {showPasswordForm && (
                  <form onSubmit={handleChangePassword} style={{ marginTop: '1rem', padding: '1rem', background: '#f5f5f5', borderRadius: '4px' }}>
                    <div className="ctop-form-group">
                      <label>New Password</label>
                      <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="Enter new password" required />
                    </div>
                    <button type="submit" className="ctop-action-btn primary">Update Password</button>
                  </form>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default CtopProfile;
