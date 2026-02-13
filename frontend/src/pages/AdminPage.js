import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { getAdminStats, getAdminUsers, changeUserRole, runDiagnostic, rawQuery, fetchReport, getUser } from '../api';

/**
 * Admin Page
 * INTENTIONALLY INSECURE: This page exists but is NOT linked in the navigation.
 * Security by obscurity - anyone who knows the URL /admin can access it.
 * TODO: Implement proper server-side role verification on every admin endpoint.
 */
function AdminPage() {
  const [stats, setStats] = useState(null);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [diagnosticCmd, setDiagnosticCmd] = useState('');
  const [diagnosticOutput, setDiagnosticOutput] = useState('');
  const [sqlQuery, setSqlQuery] = useState('');
  const [sqlResult, setSqlResult] = useState(null);
  const [ssrfUrl, setSsrfUrl] = useState('');
  const [ssrfResult, setSsrfResult] = useState(null);
  const currentUser = getUser();

  useEffect(() => {
    async function fetchData() {
      try {
        const [statsData, usersData] = await Promise.all([
          getAdminStats(),
          getAdminUsers().catch(() => ({ users: [] })),
        ]);
        setStats(statsData);
        setUsers(usersData.users || []);
      } catch (err) {
        setError('Failed to load admin data');
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  const handleRoleChange = async (userId, newRole) => {
    try {
      await changeUserRole(userId, newRole);
      setSuccess(`User ${userId} role changed to ${newRole}`);
      const usersData = await getAdminUsers().catch(() => ({ users: [] }));
      setUsers(usersData.users || []);
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError(err.error || 'Role change failed');
    }
  };

  const handleDiagnostic = async (e) => {
    e.preventDefault();
    setDiagnosticOutput('Running...');
    try {
      const result = await runDiagnostic(diagnosticCmd);
      setDiagnosticOutput(result.output || 'No output');
    } catch (err) {
      setDiagnosticOutput(err.output || err.error || 'Command failed');
    }
  };

  const handleSqlQuery = async (e) => {
    e.preventDefault();
    try {
      const result = await rawQuery(sqlQuery);
      setSqlResult(result);
    } catch (err) {
      setSqlResult({ error: err.error || 'Query failed' });
    }
  };

  const handleSsrf = async (e) => {
    e.preventDefault();
    try {
      const result = await fetchReport(ssrfUrl);
      setSsrfResult(result);
    } catch (err) {
      setSsrfResult({ error: err.error || 'Request failed' });
    }
  };

  if (loading) {
    return <div className="loading"><div className="spinner"></div></div>;
  }

  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '2rem' }}>
      {/* Sarcastic Warning */}
      <div className="admin-warning">
        <h3>Warning — Admin Panel</h3>
        <p>
          Congratulations on finding the secret admin page! It's not linked anywhere in the UI 
          because that's how security works, right? Just hide things and hope nobody finds them. 
          This is fine. Everything is fine.
        </p>
        <p style={{ marginTop: '0.5rem', fontStyle: 'italic' }}>
          "Security through obscurity is a perfectly valid strategy" — No security expert ever
        </p>
      </div>

      <div className="page-header">
        <div>
          <h1>Admin Dashboard</h1>
          <p>
            Logged in as: <strong>{currentUser?.username}</strong> ({currentUser?.role})
          </p>
        </div>
        <Link to="/dashboard" className="btn btn-secondary">← Back to Dashboard</Link>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}

      {/* Stats */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Total Users</div>
          <div className="stat-value">{stats?.total_users || 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Total Tasks</div>
          <div className="stat-value">{stats?.total_tasks || 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Security Score</div>
          <div className="stat-value" style={{ color: '#ef4444' }}>{stats?.security_score || 'F-'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Last Audit</div>
          <div className="stat-value" style={{ fontSize: '1rem', color: '#ef4444' }}>{stats?.last_security_audit || 'Never'}</div>
        </div>
      </div>

      {/* User Management */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <h2>User Management</h2>
        </div>
        <div className="card-body">
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Username</th>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Password Hash</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => (
                  <tr key={user.id}>
                    <td>#{user.id}</td>
                    <td style={{ fontWeight: 500 }}>{user.username}</td>
                    <td>{user.email}</td>
                    <td><span className={`badge badge-${user.role}`}>{user.role}</span></td>
                    <td>
                      {/* INTENTIONALLY INSECURE: Showing password hashes */}
                      <code className="text-muted">
                        {user.password?.substring(0, 16)}...
                      </code>
                    </td>
                    <td>
                      <select
                        className="form-control"
                        style={{ width: '120px', padding: '0.3rem' }}
                        value={user.role}
                        onChange={(e) => handleRoleChange(user.id, e.target.value)}
                      >
                        <option value="user">User</option>
                        <option value="manager">Manager</option>
                        <option value="admin">Admin</option>
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* System Diagnostic (Command Injection) */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <h2>
            System Diagnostic
            <span className="tooltip" data-tooltip="This runs commands directly on the server. What could go wrong?" style={{ marginLeft: '0.5rem', cursor: 'help' }}>*</span>
          </h2>
        </div>
        <div className="card-body">
          <form onSubmit={handleDiagnostic}>
            <div className="form-group">
              <label>Command</label>
              <input
                type="text"
                className="form-control"
                value={diagnosticCmd}
                onChange={(e) => setDiagnosticCmd(e.target.value)}
                placeholder='Try: echo "hello" or whoami or ls -la'
              />
              <small className="text-muted">
                Runs directly on the server with shell=True. Totally safe. Trust us.
              </small>
            </div>
            <button type="submit" className="btn btn-danger btn-sm">Run Command</button>
          </form>
          {diagnosticOutput && (
            <pre className="code-output code-output-dark">
              {diagnosticOutput}
            </pre>
          )}
        </div>
      </div>

      {/* Raw SQL Query */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <h2>
            Database Console
            <span className="tooltip" data-tooltip="Raw SQL access. Because ORMs are for cowards." style={{ marginLeft: '0.5rem', cursor: 'help' }}>*</span>
          </h2>
        </div>
        <div className="card-body">
          <form onSubmit={handleSqlQuery}>
            <div className="form-group">
              <label>SQL Query</label>
              <textarea
                className="form-control"
                value={sqlQuery}
                onChange={(e) => setSqlQuery(e.target.value)}
                placeholder="SELECT * FROM users"
                rows={3}
              />
            </div>
            <button type="submit" className="btn btn-danger btn-sm">Execute Query</button>
          </form>
          {sqlResult && (
            <pre className="code-output code-output-light">
              {JSON.stringify(sqlResult, null, 2)}
            </pre>
          )}
        </div>
      </div>

      {/* SSRF Test */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <h2>
            Report Fetcher
            <span className="tooltip" data-tooltip="Fetches any URL from the server. Including internal ones. Oops." style={{ marginLeft: '0.5rem', cursor: 'help' }}>*</span>
          </h2>
        </div>
        <div className="card-body">
          <form onSubmit={handleSsrf}>
            <div className="form-group">
              <label>Report URL</label>
              <input
                type="text"
                className="form-control"
                value={ssrfUrl}
                onChange={(e) => setSsrfUrl(e.target.value)}
                placeholder="Try: http://localhost:5000/api/internal/health or http://localhost:5000/api/admin/secret-config"
              />
              <small className="text-muted">
                The server will fetch this URL for you. No validation. No restrictions. YOLO.
              </small>
            </div>
            <button type="submit" className="btn btn-primary btn-sm">Fetch Report</button>
          </form>
          {ssrfResult && (
            <pre className="code-output code-output-light">
              {JSON.stringify(ssrfResult, null, 2)}
            </pre>
          )}
        </div>
      </div>

      {/* Footer */}
      <div className="page-footer">
        <p>CToP Admin Panel — "With great power comes great irresponsibility"</p>
      </div>
    </div>
  );
}

export default AdminPage;
