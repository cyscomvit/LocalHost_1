import React, { useState, useEffect } from 'react';
import { getTasks, createTask, updateTask, deleteTask, getUser } from '../api';

function TasksPage() {
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editingTask, setEditingTask] = useState(null);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const user = getUser();

  // New task form state
  const [newTask, setNewTask] = useState({
    title: '',
    description: '',
    priority: 'medium',
    assigned_to: '',
    status: 'pending',
  });

  const fetchTasks = async () => {
    setLoading(true);
    try {
      // INTENTIONALLY INSECURE: Search parameter sent directly to backend SQL query
      // TODO: Sanitize search input on both client and server
      const data = await getTasks(search, statusFilter);
      setTasks(data.tasks || []);
    } catch (err) {
      setError(err.error || 'Failed to load tasks');
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
      await createTask({
        ...newTask,
        assigned_to: newTask.assigned_to ? parseInt(newTask.assigned_to) : null,
      });
      setSuccess('Task created successfully!');
      setShowCreateModal(false);
      setNewTask({ title: '', description: '', priority: 'medium', assigned_to: '', status: 'pending' });
      fetchTasks();
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError(err.error || 'Failed to create task');
    }
  };

  const handleUpdateTask = async (e) => {
    e.preventDefault();
    setError('');
    try {
      // INTENTIONALLY INSECURE: IDOR - any user can update any task
      await updateTask(editingTask.id, editingTask);
      setSuccess('Task updated!');
      setEditingTask(null);
      fetchTasks();
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError(err.error || 'Failed to update task');
    }
  };

  const handleDeleteTask = async (taskId) => {
    if (!window.confirm('Delete this task? This cannot be undone.')) return;
    try {
      // INTENTIONALLY INSECURE: IDOR - any user can delete any task
      await deleteTask(taskId);
      setSuccess('Task deleted');
      fetchTasks();
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError(err.error || 'Failed to delete task');
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 700 }}>Tasks</h1>
          <p style={{ color: '#64748b', marginTop: '0.25rem' }}>
            Manage your team's work.
            <span className="tooltip" data-tooltip="Or anyone else's work. Access control is just a suggestion here." style={{ marginLeft: '0.5rem', cursor: 'help' }}>
              *
            </span>
          </p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowCreateModal(true)}>
          + New Task
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}

      {/* Search & Filter */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-body" style={{ display: 'flex', gap: '1rem', alignItems: 'end' }}>
          <form onSubmit={handleSearch} style={{ flex: 1, display: 'flex', gap: '0.75rem' }}>
            <div style={{ flex: 1 }}>
              <label style={{ fontSize: '0.8rem', fontWeight: 500, color: '#64748b', display: 'block', marginBottom: '0.25rem' }}>
                Search Tasks
                <span className="tooltip" data-tooltip="Try: ' OR 1=1 -- for a fun surprise" style={{ marginLeft: '0.25rem', cursor: 'help' }}>*</span>
              </label>
              <input
                type="text"
                className="form-control"
                placeholder="Search by title..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <button type="submit" className="btn btn-secondary" style={{ alignSelf: 'end' }}>Search</button>
          </form>
          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 500, color: '#64748b', display: 'block', marginBottom: '0.25rem' }}>Status</label>
            <select
              className="form-control"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              style={{ width: '160px' }}
            >
              <option value="">All</option>
              <option value="pending">Pending</option>
              <option value="in_progress">In Progress</option>
              <option value="completed">Completed</option>
            </select>
          </div>
        </div>
      </div>

      {/* Tasks Table */}
      <div className="card">
        <div className="card-body">
          {loading ? (
            <div className="loading"><div className="spinner"></div></div>
          ) : tasks.length === 0 ? (
            <div className="empty-state">
              <div className="emoji">--</div>
              <p>No tasks found. Either you're done or the SQL injection worked too well.</p>
            </div>
          ) : (
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Status</th>
                    <th>Priority</th>
                    <th>Assigned To</th>
                    <th>Created By</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {tasks.map((task) => (
                    <tr key={task.id}>
                      <td style={{ color: '#94a3b8' }}>#{task.id}</td>
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
                      <td style={{ color: '#64748b' }}>User #{task.assigned_to}</td>
                      <td style={{ color: '#64748b' }}>User #{task.created_by}</td>
                      <td>
                        <div style={{ display: 'flex', gap: '0.5rem' }}>
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => setEditingTask({ ...task })}
                          >
                            Edit
                          </button>
                          <button
                            className="btn btn-danger btn-sm"
                            onClick={() => handleDeleteTask(task.id)}
                          >
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Create Task Modal */}
      {showCreateModal && (
        <div className="modal-overlay" onClick={() => setShowCreateModal(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h2>Create New Task</h2>
            <form onSubmit={handleCreateTask}>
              <div className="form-group">
                <label>Title</label>
                <input
                  type="text"
                  className="form-control"
                  value={newTask.title}
                  onChange={(e) => setNewTask({ ...newTask, title: e.target.value })}
                  placeholder="What needs to be done?"
                  required
                />
              </div>
              <div className="form-group">
                <label>Description</label>
                <textarea
                  className="form-control"
                  value={newTask.description}
                  onChange={(e) => setNewTask({ ...newTask, description: e.target.value })}
                  placeholder="Add some details..."
                />
              </div>
              <div style={{ display: 'flex', gap: '1rem' }}>
                <div className="form-group" style={{ flex: 1 }}>
                  <label>Priority</label>
                  <select
                    className="form-control"
                    value={newTask.priority}
                    onChange={(e) => setNewTask({ ...newTask, priority: e.target.value })}
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                  </select>
                </div>
                <div className="form-group" style={{ flex: 1 }}>
                  <label>
                    Assign To (User ID)
                    <span className="tooltip" data-tooltip="Just type any user ID. We don't check permissions" style={{ marginLeft: '0.25rem', cursor: 'help' }}>*</span>
                  </label>
                  <input
                    type="number"
                    className="form-control"
                    value={newTask.assigned_to}
                    onChange={(e) => setNewTask({ ...newTask, assigned_to: e.target.value })}
                    placeholder="User ID"
                  />
                </div>
              </div>
              <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end', marginTop: '1rem' }}>
                <button type="button" className="btn btn-secondary" onClick={() => setShowCreateModal(false)}>Cancel</button>
                <button type="submit" className="btn btn-primary">Create Task</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Task Modal */}
      {editingTask && (
        <div className="modal-overlay" onClick={() => setEditingTask(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h2>Edit Task #{editingTask.id}</h2>
            <form onSubmit={handleUpdateTask}>
              <div className="form-group">
                <label>Title</label>
                <input
                  type="text"
                  className="form-control"
                  value={editingTask.title}
                  onChange={(e) => setEditingTask({ ...editingTask, title: e.target.value })}
                  required
                />
              </div>
              <div className="form-group">
                <label>Description</label>
                <textarea
                  className="form-control"
                  value={editingTask.description || ''}
                  onChange={(e) => setEditingTask({ ...editingTask, description: e.target.value })}
                />
              </div>
              <div style={{ display: 'flex', gap: '1rem' }}>
                <div className="form-group" style={{ flex: 1 }}>
                  <label>Status</label>
                  <select
                    className="form-control"
                    value={editingTask.status}
                    onChange={(e) => setEditingTask({ ...editingTask, status: e.target.value })}
                  >
                    <option value="pending">Pending</option>
                    <option value="in_progress">In Progress</option>
                    <option value="completed">Completed</option>
                  </select>
                </div>
                <div className="form-group" style={{ flex: 1 }}>
                  <label>Priority</label>
                  <select
                    className="form-control"
                    value={editingTask.priority}
                    onChange={(e) => setEditingTask({ ...editingTask, priority: e.target.value })}
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                  </select>
                </div>
              </div>
              <div className="form-group">
                <label>Assigned To (User ID)</label>
                <input
                  type="number"
                  className="form-control"
                  value={editingTask.assigned_to || ''}
                  onChange={(e) => setEditingTask({ ...editingTask, assigned_to: e.target.value ? parseInt(e.target.value) : null })}
                />
              </div>
              <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end', marginTop: '1rem' }}>
                <button type="button" className="btn btn-secondary" onClick={() => setEditingTask(null)}>Cancel</button>
                <button type="submit" className="btn btn-primary">Save Changes</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default TasksPage;
