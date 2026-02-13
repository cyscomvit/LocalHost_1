import React, { useState, useEffect } from 'react';
import CtopHeader from '../components/CtopHeader';
import CtopSidebar from '../components/CtopSidebar';
import { getAdminStats, getAdminUsers, changeUserRole, runDiagnostic, rawQuery, fetchReport, getUser } from '../api';

/**
 * CTOP Admin Page
 * University administration panel
 */
function CtopAdmin() {
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
    return (
      <div className="ctop-app">
        <CtopHeader />
        <div className="ctop-main-container">
          <CtopSidebar />
          <div className="ctop-content-area"><div className="ctop-loading">Loading admin panel...</div></div>
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
            <h2>Administration Panel</h2>
            <p style={{ color: '#757575', fontSize: '0.85rem' }}>
              System administration and diagnostics
            </p>
          </div>

          {error && <div className="ctop-alert error">{error}</div>}
          {success && <div className="ctop-alert success">{success}</div>}

          {/* Stats Grid */}
          <div className="ctop-stats-grid">
            <div className="ctop-stat-card">
              <div className="ctop-stat-label">Total Students</div>
              <div className="ctop-stat-value">{stats?.total_users || 0}</div>
            </div>
            <div className="ctop-stat-card">
              <div className="ctop-stat-label">Total Assignments</div>
              <div className="ctop-stat-value">{stats?.total_tasks || 0}</div>
            </div>
            <div className="ctop-stat-card">
              <div className="ctop-stat-label">Security Score</div>
              <div className="ctop-stat-value" style={{ color: '#f44336' }}>{stats?.security_score || 'F-'}</div>
            </div>
            <div className="ctop-stat-card">
              <div className="ctop-stat-label">Last Audit</div>
              <div className="ctop-stat-value" style={{ fontSize: '1rem', color: '#f44336' }}>{stats?.last_security_audit || 'Never'}</div>
            </div>
          </div>

          {/* User Management */}
          <div className="ctop-card">
            <div className="ctop-section-header"><h3>USER MANAGEMENT</h3></div>
            <div className="ctop-card-body">
              <div className="ctop-table-container">
                <table className="ctop-course-table">
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
                      <tr key={user.id} className={user.id % 2 === 0 ? 'even-row' : 'odd-row'}>
                        <td className="course-code">#{user.id}</td>
                        <td style={{ fontWeight: 500 }}>{user.username}</td>
                        <td>{user.email}</td>
                        <td>
                          <span className={`ctop-badge ctop-badge-${user.role}`}>
                            {user.role}
                          </span>
                        </td>
                        <td>
                          <code className="text-muted">
                            {user.password?.substring(0, 16)}...
                          </code>
                        </td>
                        <td>
                          <select
                            className="ctop-filter-select"
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

          <div className="ctop-card">
            <div className="ctop-section-header">
              <h3>SYSTEM DIAGNOSTICS</h3>
            </div>
            <div className="ctop-card-body">
              <form onSubmit={handleDiagnostic}>
                <div className="ctop-form-group">
                  <label>Diagnostic Command</label>
                  <input
                    type="text"
                    className="ctop-search-input"
                    value={diagnosticCmd}
                    onChange={(e) => setDiagnosticCmd(e.target.value)}
                    placeholder="Enter system diagnostic command"
                  />
                </div>
                <button type="submit" className="ctop-action-btn primary">Run Diagnostic</button>
              </form>
              {diagnosticOutput && (
                <pre className="code-output code-output-dark">
                  {diagnosticOutput}
                </pre>
              )}
            </div>
          </div>

          <div className="ctop-card">
            <div className="ctop-section-header">
              <h3>DATABASE CONSOLE</h3>
            </div>
            <div className="ctop-card-body">
              <form onSubmit={handleSqlQuery}>
                <div className="ctop-form-group">
                  <label>SQL Query</label>
                  <textarea
                    className="ctop-search-input"
                    value={sqlQuery}
                    onChange={(e) => setSqlQuery(e.target.value)}
                    placeholder="Enter SQL query"
                    rows={3}
                    style={{ fontFamily: 'monospace' }}
                  />
                </div>
                <button type="submit" className="ctop-action-btn primary">Execute Query</button>
              </form>
              {sqlResult && (
                <pre className="code-output code-output-light">
                  {JSON.stringify(sqlResult, null, 2)}
                </pre>
              )}
            </div>
          </div>

          <div className="ctop-card">
            <div className="ctop-section-header">
              <h3>REPORT FETCHER</h3>
            </div>
            <div className="ctop-card-body">
              <form onSubmit={handleSsrf}>
                <div className="ctop-form-group">
                  <label>Report URL</label>
                  <input
                    type="text"
                    className="ctop-search-input"
                    value={ssrfUrl}
                    onChange={(e) => setSsrfUrl(e.target.value)}
                    placeholder="Enter report URL to fetch"
                  />
                </div>
                <button type="submit" className="ctop-action-btn primary">Fetch Report</button>
              </form>
              {ssrfResult && (
                <pre className="code-output code-output-light">
                  {JSON.stringify(ssrfResult, null, 2)}
                </pre>
              )}
            </div>
          </div>

          <div className="page-footer">
            <p>CTOP Administration Panel v1.0</p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default CtopAdmin;
