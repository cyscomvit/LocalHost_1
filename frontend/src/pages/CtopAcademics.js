import React, { useState, useEffect } from 'react';
import CtopHeader from '../components/CtopHeader';
import CtopSidebar from '../components/CtopSidebar';
import { getTasks, createTask, updateTask, deleteTask } from '../api';

/**
 * CTOP Academics Page
 * Maps to the Tasks backend - demonstrates SQL Injection, IDOR, broken access control
 * Styled as a course/assignment management portal
 */
function CtopAcademics() {
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [editingTask, setEditingTask] = useState(null);
  const [newTask, setNewTask] = useState({ title: '', description: '', status: 'pending', priority: 'medium' });

  const fetchTasks = async () => {
    setLoading(true);
    try {
      // INTENTIONALLY INSECURE: Search parameter sent directly to backend SQL query
      // TODO: Sanitize search input, use parameterized queries
      const data = await getTasks(search, statusFilter);
      setTasks(data.tasks || []);
    } catch (err) {
      setError(err.error || 'Failed to load academic records');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTasks();
  }, [statusFilter]);

  const handleSearch = (e) => {
    e.preventDefault();
    fetchTasks();
  };

  const handleCreateTask = async (e) => {
    e.preventDefault();
    setError('');
    try {
      await createTask(newTask);
      setSuccess('Assignment created successfully!');
      setShowCreateForm(false);
      setNewTask({ title: '', description: '', status: 'pending', priority: 'medium' });
      fetchTasks();
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError(err.error || 'Failed to create assignment');
    }
  };

  const handleUpdateTask = async (e) => {
    e.preventDefault();
    setError('');
    try {
      // INTENTIONALLY INSECURE: IDOR - can update any task by ID
      await updateTask(editingTask.id, editingTask);
      setSuccess('Assignment updated!');
      setEditingTask(null);
      fetchTasks();
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError(err.error || 'Failed to update assignment');
    }
  };

  const handleDeleteTask = async (id) => {
    if (!window.confirm('Delete this assignment?')) return;
    try {
      // INTENTIONALLY INSECURE: IDOR - can delete any task by ID
      await deleteTask(id);
      setSuccess('Assignment deleted');
      fetchTasks();
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError(err.error || 'Failed to delete assignment');
    }
  };

  const getPriorityColor = (priority) => {
    switch (priority) {
      case 'high': return '#f44336';
      case 'medium': return '#ff9800';
      case 'low': return '#4caf50';
      default: return '#757575';
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'completed': return { bg: '#e8f5e9', color: '#2e7d32', text: 'Completed' };
      case 'in_progress': return { bg: '#e3f2fd', color: '#1565c0', text: 'In Progress' };
      case 'pending': return { bg: '#fff3e0', color: '#e65100', text: 'Pending' };
      default: return { bg: '#f5f5f5', color: '#757575', text: status };
    }
  };

  return (
    <div className="ctop-app">
      <CtopHeader />
      <div className="ctop-main-container">
        <CtopSidebar />
        <div className="ctop-content-area">
          {/* Page Title */}
          <div className="ctop-page-title">
            <h2>Academics — Course Assignments & Tasks</h2>
            <p style={{ color: '#757575', fontSize: '0.85rem' }}>
              Manage your academic assignments and coursework
            </p>
          </div>

          {error && <div className="ctop-alert error">{error}</div>}
          {success && <div className="ctop-alert success">{success}</div>}

          {/* Search & Filter Bar */}
          <div className="ctop-filter-bar">
            <form onSubmit={handleSearch} className="ctop-search-form">
              <input
                type="text"
                placeholder="Search assignments by title or description..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="ctop-search-input"
              />
              <button type="submit" className="ctop-search-btn">Search</button>
            </form>
            <div className="ctop-filter-group">
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="ctop-filter-select"
              >
                <option value="">All Status</option>
                <option value="pending">Pending</option>
                <option value="in_progress">In Progress</option>
                <option value="completed">Completed</option>
              </select>
              <button className="ctop-action-btn primary" onClick={() => setShowCreateForm(!showCreateForm)}>
                + New Assignment
              </button>
            </div>
          </div>

          {/* Create Form */}
          {showCreateForm && (
            <div className="ctop-card" style={{ marginBottom: '1.5rem' }}>
              <div className="ctop-section-header"><h3>Create New Assignment</h3></div>
              <div className="ctop-card-body">
                <form onSubmit={handleCreateTask}>
                  <div className="ctop-form-row">
                    <div className="ctop-form-group">
                      <label>Title</label>
                      <input type="text" value={newTask.title} onChange={(e) => setNewTask({...newTask, title: e.target.value})} required placeholder="Assignment title" />
                    </div>
                    <div className="ctop-form-group">
                      <label>Priority</label>
                      <select value={newTask.priority} onChange={(e) => setNewTask({...newTask, priority: e.target.value})}>
                        <option value="low">Low</option>
                        <option value="medium">Medium</option>
                        <option value="high">High</option>
                      </select>
                    </div>
                  </div>
                  <div className="ctop-form-group">
                    <label>Description</label>
                    <textarea value={newTask.description} onChange={(e) => setNewTask({...newTask, description: e.target.value})} placeholder="Assignment details..." rows={3} />
                  </div>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <button type="submit" className="ctop-action-btn primary">Create</button>
                    <button type="button" className="ctop-action-btn secondary" onClick={() => setShowCreateForm(false)}>Cancel</button>
                  </div>
                </form>
              </div>
            </div>
          )}

          {/* Edit Form */}
          {editingTask && (
            <div className="ctop-card" style={{ marginBottom: '1.5rem' }}>
              <div className="ctop-section-header"><h3>Edit Assignment #{editingTask.id}</h3></div>
              <div className="ctop-card-body">
                <form onSubmit={handleUpdateTask}>
                  <div className="ctop-form-row">
                    <div className="ctop-form-group">
                      <label>Title</label>
                      <input type="text" value={editingTask.title || ''} onChange={(e) => setEditingTask({...editingTask, title: e.target.value})} required />
                    </div>
                    <div className="ctop-form-group">
                      <label>Status</label>
                      <select value={editingTask.status || ''} onChange={(e) => setEditingTask({...editingTask, status: e.target.value})}>
                        <option value="pending">Pending</option>
                        <option value="in_progress">In Progress</option>
                        <option value="completed">Completed</option>
                      </select>
                    </div>
                    <div className="ctop-form-group">
                      <label>Priority</label>
                      <select value={editingTask.priority || ''} onChange={(e) => setEditingTask({...editingTask, priority: e.target.value})}>
                        <option value="low">Low</option>
                        <option value="medium">Medium</option>
                        <option value="high">High</option>
                      </select>
                    </div>
                  </div>
                  <div className="ctop-form-group">
                    <label>Description</label>
                    <textarea value={editingTask.description || ''} onChange={(e) => setEditingTask({...editingTask, description: e.target.value})} rows={3} />
                  </div>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <button type="submit" className="ctop-action-btn primary">Save Changes</button>
                    <button type="button" className="ctop-action-btn secondary" onClick={() => setEditingTask(null)}>Cancel</button>
                  </div>
                </form>
              </div>
            </div>
          )}

          {/* Assignments Table */}
          <div className="ctop-card">
            <div className="ctop-section-header">
              <h3>ASSIGNMENT RECORDS — {tasks.length} Total</h3>
            </div>
            <div className="ctop-table-container">
              {loading ? (
                <div className="ctop-loading">Loading assignments...</div>
              ) : tasks.length === 0 ? (
                <div style={{ padding: '2rem', textAlign: 'center', color: '#757575' }}>No assignments found</div>
              ) : (
                <table className="ctop-course-table">
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Assignment Title</th>
                      <th>Description</th>
                      <th>Status</th>
                      <th>Priority</th>
                      <th>Created By</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tasks.map((task, index) => {
                      const statusBadge = getStatusBadge(task.status);
                      return (
                        <tr key={task.id} className={index % 2 === 0 ? 'even-row' : 'odd-row'}>
                          <td className="course-code">#{task.id}</td>
                          <td className="course-name">{task.title}</td>
                          <td style={{ maxWidth: '250px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {task.description || '—'}
                          </td>
                          <td>
                            <span className={`ctop-badge ctop-badge-${task.status === 'completed' ? 'success' : task.status === 'in_progress' ? 'info' : 'warning'}`}>
                              {statusBadge.text}
                            </span>
                          </td>
                          <td>
                            <span style={{ color: getPriorityColor(task.priority), fontWeight: 'bold', fontSize: '0.8rem' }}>
                              {task.priority?.toUpperCase()}
                            </span>
                          </td>
                          <td style={{ fontSize: '0.8rem', color: '#757575' }}>{task.created_by || task.user_id || '—'}</td>
                          <td>
                            <div style={{ display: 'flex', gap: '0.25rem' }}>
                              <button className="ctop-table-btn edit" onClick={() => setEditingTask({...task})}>Edit</button>
                              <button className="ctop-table-btn delete" onClick={() => handleDeleteTask(task.id)}>Del</button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default CtopAcademics;
