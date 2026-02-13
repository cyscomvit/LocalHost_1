import React, { useState, useEffect } from 'react';

function ProctorMessage() {
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Mock proctor messages - in real app, this would come from backend
    const mockMessages = [
      {
        id: 1,
        title: 'Exam Schedule Update',
        message: 'The mid-semester examination schedule has been revised. Please check the updated timetable.',
        timestamp: '2024-02-11 09:30 AM',
        priority: 'high',
        read: false
      },
      {
        id: 2,
        title: 'Library Fine Reminder',
        message: 'You have pending library fines. Please clear them before the end of this semester.',
        timestamp: '2024-02-10 02:15 PM',
        priority: 'medium',
        read: true
      },
      {
        id: 3,
        title: 'Workshop Registration Open',
        message: 'Registration for the upcoming cybersecurity workshop is now open. Limited seats available.',
        timestamp: '2024-02-09 11:00 AM',
        priority: 'low',
        read: true
      }
    ];
    setMessages(mockMessages);
    setLoading(false);
  }, []);

  const getPriorityColor = (priority) => {
    switch (priority) {
      case 'high': return '#f44336';
      case 'medium': return '#ff9800';
      case 'low': return '#4caf50';
      default: return '#666';
    }
  };

  const getPriorityIcon = (priority) => {
    switch (priority) {
      case 'high': return '!';
      case 'medium': return '-';
      case 'low': return '~';
      default: return ' ';
    }
  };

  if (loading) {
    return <div className="ctop-loading">Loading messages...</div>;
  }

  return (
    <div className="ctop-proctor-message">
      <div className="ctop-section-header">
        <h3>PROCTOR Message</h3>
      </div>
      
      <div className="ctop-proctor-content">
        {messages.length > 0 ? (
          messages.map((message) => (
            <div key={message.id} className={`ctop-proctor-item ${message.read ? 'read' : 'unread'}`}>
              <div className="proctor-priority">
                <span className="priority-icon">{getPriorityIcon(message.priority)}</span>
              </div>
              <div className="proctor-message-content">
                <div className="proctor-message-header">
                  <div className="proctor-title">{message.title}</div>
                  <div className="proctor-timestamp">{message.timestamp}</div>
                </div>
                <div className="proctor-message-text">
                  {message.message}
                </div>
                <div className="proctor-message-actions">
                  <button className="proctor-action-btn mark-read">
                    {message.read ? 'Mark as Unread' : 'Mark as Read'}
                  </button>
                  <button className="proctor-action-btn delete">Delete</button>
                </div>
              </div>
            </div>
          ))
        ) : (
          <div className="no-messages">
            <div className="no-messages-icon">No mail</div>
            <div className="no-messages-text">No new messages</div>
          </div>
        )}
      </div>

      <div className="ctop-proctor-footer">
        <button className="view-all-messages-btn">
          View All Messages →
        </button>
      </div>
    </div>
  );
}

export default ProctorMessage;
