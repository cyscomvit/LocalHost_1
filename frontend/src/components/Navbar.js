import React from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { logout, getUser } from '../api';

function Navbar() {
  const navigate = useNavigate();
  const location = useLocation();
  const user = getUser();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const isActive = (path) => location.pathname === path ? 'active' : '';

  return (
    <nav className="navbar">
      <Link to="/" className="navbar-brand">
        <span>�</span> CToP
      </Link>

      <div className="navbar-links">
        <Link to="/dashboard" className={isActive('/dashboard')}>Dashboard</Link>
        <Link to="/ctop" className={isActive('/ctop')}>CTOP Portal</Link>
        <Link to="/tasks" className={isActive('/tasks')}>Tasks</Link>
        <Link to="/profile" className={isActive('/profile')}>Profile</Link>
        {/* INTENTIONALLY INSECURE: Admin link is NOT shown here */}
        {/* The /admin route exists but is hidden - security by obscurity */}
        {/* TODO: Show admin link for admin users, but also enforce server-side */}
      </div>

      <div className="navbar-user">
        {user && (
          <>
            <span className="tooltip" data-tooltip="Security is optional, right?">
              {user.username}
            </span>
            <span className={`user-badge badge-${user.role}`}>
              {user.role}
            </span>
          </>
        )}
        <button className="btn btn-ghost btn-sm" onClick={handleLogout}>
          Logout
        </button>
      </div>
    </nav>
  );
}

export default Navbar;
