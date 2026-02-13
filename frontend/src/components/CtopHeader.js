import React from 'react';
import { useNavigate } from 'react-router-dom';
import { logout, getUser } from '../api';

function CtopHeader() {
  const navigate = useNavigate();
  const user = getUser();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <header className="ctop-header">
      <div className="ctop-header-top">
        <div className="ctop-logo">
          <div className="ctop-logo-icon">🔒</div>
          <div className="ctop-logo-text">
            <div className="ctop-logo-main">CTOP</div>
            <div className="ctop-logo-sub">Cyscom On Top</div>
          </div>
        </div>
        
        <div className="ctop-quick-links">
          <div className="dropdown">
            <button className="dropdown-toggle">
              Quick Links ▼
            </button>
            <div className="dropdown-menu">
              <a href="#" className="dropdown-item">Academic Calendar</a>
              <a href="#" className="dropdown-item">Course Registration</a>
              <a href="#" className="dropdown-item">Exam Schedule</a>
              <a href="#" className="dropdown-item">Fee Payment</a>
              <a href="#" className="dropdown-item">Library</a>
            </div>
          </div>
        </div>

        <div className="ctop-user-info">
          <div className="ctop-user-details">
            <div className="ctop-user-id">{user?.username?.toUpperCase() || 'STUDENT'}</div>
            <div className="ctop-user-role">{user?.role?.toUpperCase() || 'USER'}</div>
          </div>
          <div className="ctop-user-avatar">
            <img 
              src={`https://ui-avatars.com/api/?name=${user?.username || 'User'}&background=0d47a1&color=fff&size=40`}
              alt="User Avatar"
            />
          </div>
          <button className="ctop-logout-btn" onClick={handleLogout}>
            Logout
          </button>
        </div>
      </div>
      
      <div className="ctop-header-bottom">
        <div className="ctop-breadcrumb">
          Home / Dashboard
        </div>
        <div className="ctop-header-title">
          Student Dashboard
        </div>
      </div>
    </header>
  );
}

export default CtopHeader;
