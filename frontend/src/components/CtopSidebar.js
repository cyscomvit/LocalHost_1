import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { logout, getUser } from '../api';

function CtopSidebar() {
  const location = useLocation();
  const navigate = useNavigate();
  const [expanded, setExpanded] = useState(false);
  const user = getUser();
  const isAdmin = user?.role === 'admin';

  const menuItems = [
    { icon: '🏠', label: 'Dashboard', path: '/' },
    { icon: '📚', label: 'Academics', path: '/academics' },
    { icon: '📅', label: 'Timetable', path: '/timetable' },
    { icon: '📊', label: 'Results', path: '/results' },
    { icon: '💰', label: 'Fee Payment', path: '/fee-payment' },
    { icon: '👤', label: 'My Profile', path: '/profile' },
    { icon: '📧', label: 'Messages', path: '/messages' },
    { icon: '🚨', label: 'Announcements', path: '/xss-demo' },
    
    { icon: '⚙️', label: 'Settings', path: '/settings' },
    { icon: '🔧', label: 'System Admin', path: '/system-admin', adminOnly: true },
  ];

  const handleMenuClick = async (path) => {
    navigate(path);
  };

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <aside className={`ctop-sidebar ${expanded ? 'expanded' : ''}`}
      onMouseEnter={() => setExpanded(true)}
      onMouseLeave={() => setExpanded(false)}
    >
      <div className="ctop-sidebar-nav">
        {menuItems.filter(item => !item.adminOnly || isAdmin).map((item, index) => (
          <div
            key={index}
            className={`ctop-sidebar-item ${location.pathname === item.path ? 'active' : ''}`}
            onClick={() => handleMenuClick(item.path)}
            title={item.label}
          >
            <div className="ctop-sidebar-icon">{item.icon}</div>
            {expanded && <div className="ctop-sidebar-label">{item.label}</div>}
          </div>
        ))}
        <div className="ctop-sidebar-item logout" onClick={handleLogout} title="Logout">
          <div className="ctop-sidebar-icon">🚪</div>
          {expanded && <div className="ctop-sidebar-label">Logout</div>}
        </div>
      </div>
    </aside>
  );
}

export default CtopSidebar;
