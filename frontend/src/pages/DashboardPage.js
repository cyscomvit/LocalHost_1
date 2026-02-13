import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { getAdminStats, getTasks, getUser } from '../api';

function DashboardPage() {
  const [stats, setStats] = useState(null);
  const [recentTasks, setRecentTasks] = useState([]);
  const [loading, setLoading] = useState(true);
  const user = getUser();

  useEffect(() => {
    async function fetchData() {
      try {
        const [statsData, tasksData] = await Promise.all([
          getAdminStats(),
          getTasks(),
        ]);
        setStats(statsData);
        setRecentTasks(tasksData.tasks ? tasksData.tasks.slice(0, 5) : []);
      } catch (err) {
        console.error('Dashboard load failed:', err);
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner"></div>
      </div>
    );
  }

  return (
    <div>
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 700 }}>
          Welcome back, {user?.username || 'friend'}
        </h1>
        <p className="text-muted" style={{ marginTop: '0.25rem' }}>
          Here's what's happening at CToP today.
          <span className="tooltip" data-tooltip="Spoiler: everything is on fire" style={{ marginLeft: '0.5rem', cursor: 'help' }}>
            (i)
          </span>
        </p>
      </div>

      {/* Stats Grid */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Total Tasks</div>
          <div className="stat-value">{stats?.total_tasks || 0}</div>
          <div className="stat-change">↑ 12% from last week</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Pending Tasks</div>
          <div className="stat-value">{stats?.pending_tasks || 0}</div>
          <div className="stat-change text-warning">→ Same as yesterday</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Team Members</div>
          <div className="stat-value">{stats?.total_users || 0}</div>
          <div className="stat-change">↑ 2 new this month</div>
        </div>
        <div className="stat-card">
          <div className="stat-label tooltip" data-tooltip="We've never actually done one">
            Security Score
          </div>
          <div className="stat-value text-danger">{stats?.security_score || 'F'}</div>
          <div className="stat-change text-danger">↓ Getting worse</div>
        </div>
      </div>

      {/* Fake Metrics Row */}
      <div className="stats-grid" style={{ marginBottom: '2rem' }}>
        <div className="stat-card">
          <div className="stat-label">Deployment Status</div>
          <div className="stat-value text-warning" style={{ fontSize: '1.25rem' }}>
            {stats?.deployment_status || 'YOLO mode'}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Server Uptime</div>
          <div className="stat-value" style={{ fontSize: '1.25rem' }}>
            {stats?.server_uptime || '42 days'}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label tooltip" data-tooltip="We keep meaning to schedule one...">
            Last Security Audit
          </div>
          <div className="stat-value text-danger" style={{ fontSize: '1.25rem' }}>
            {stats?.last_security_audit || 'Never'}
          </div>
        </div>
      </div>

      {/* Recent Tasks */}
      <div className="card">
        <div className="card-header">
          <h2>Recent Tasks</h2>
          <Link to="/tasks" className="btn btn-secondary btn-sm">View All</Link>
        </div>
        <div className="card-body">
          {recentTasks.length === 0 ? (
            <div className="empty-state">
              <div className="emoji">--</div>
              <p>No tasks yet. Time to procrastinate productively!</p>
            </div>
          ) : (
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Task</th>
                    <th>Status</th>
                    <th>Priority</th>
                    <th>Assigned To</th>
                  </tr>
                </thead>
                <tbody>
                  {recentTasks.map((task) => (
                    <tr key={task.id}>
                      <td style={{ fontWeight: 500 }}>{task.title}</td>
                      <td>
                        <span className={`badge badge-${task.status?.replace('_', '-')}`}>
                          {task.status}
                        </span>
                      </td>
                      <td>
                        <span className={`badge badge-${task.priority}`}>
                          {task.priority}
                        </span>
                      </td>
                      <td className="text-muted">User #{task.assigned_to}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Fun Footer */}
      <div className="page-footer">
        <p>CToP v1.0.0 — "Ship it and pray" edition</p>
        <p style={{ marginTop: '0.25rem' }}>
          <span className="tooltip" data-tooltip="No really, please don't.">
            Definitely production-ready™
          </span>
        </p>
      </div>
    </div>
  );
}

export default DashboardPage;
