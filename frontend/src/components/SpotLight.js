import React, { useState, useEffect } from 'react';

function SpotLight() {
  const [notices, setNotices] = useState([]);

  useEffect(() => {
    // Mock spotlight notices - in real app, this would come from backend
    const mockNotices = [
      {
        id: 1,
        title: 'Nature of Malpractice Vs Punishment',
        type: 'warning',
        date: '2024-02-10',
        important: true
      },
      {
        id: 2,
        title: 'Make-up Examination Registration (Circular)',
        type: 'info',
        date: '2024-02-09',
        important: false
      },
      {
        id: 3,
        title: 'Last Date for Course Add/Drop - February 15th',
        type: 'deadline',
        date: '2024-02-08',
        important: true
      },
      {
        id: 4,
        title: 'Security Workshop: Ethical Hacking Basics',
        type: 'event',
        date: '2024-02-07',
        important: false
      },
      {
        id: 5,
        title: 'Fee Payment Deadline Extended',
        type: 'info',
        date: '2024-02-06',
        important: false
      }
    ];
    setNotices(mockNotices);
  }, []);

  const getTypeIcon = (type) => {
    switch (type) {
      case 'warning': return '!';
      case 'info': return 'i';
      case 'deadline': return 'D';
      case 'event': return 'E';
      default: return '-';
    }
  };

  const getTypeColor = (type) => {
    switch (type) {
      case 'warning': return '#ff9800';
      case 'info': return '#2196f3';
      case 'deadline': return '#f44336';
      case 'event': return '#4caf50';
      default: return '#666';
    }
  };

  return (
    <div className="ctop-spotlight">
      <div className="ctop-section-header">
        <h3>SPOT-LIGHT</h3>
      </div>
      
      <div className="ctop-spotlight-content">
        {notices.map((notice) => (
          <div key={notice.id} className="ctop-spotlight-item">
            <div className="spotlight-bullet" style={{ color: getTypeColor(notice.type) }}>
              {getTypeIcon(notice.type)}
            </div>
            <div className="spotlight-content">
              <div className="spotlight-title">
                {notice.important && <span className="important-badge">IMPORTANT</span>}
                {notice.title}
              </div>
              <div className="spotlight-date">
                {new Date(notice.date).toLocaleDateString('en-US', { 
                  month: 'long', 
                  day: 'numeric', 
                  year: 'numeric' 
                })}
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="ctop-spotlight-footer">
        <button className="view-all-notices-btn">
          View All Notices →
        </button>
      </div>
    </div>
  );
}

export default SpotLight;
