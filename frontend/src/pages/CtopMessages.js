import React, { useState, useEffect } from 'react';
import CtopHeader from '../components/CtopHeader';
import CtopSidebar from '../components/CtopSidebar';
import { getUser, getMessages } from '../api';

function CtopMessages() {
  const [messages, setMessages] = useState([]);
  const [selectedMessage, setSelectedMessage] = useState(null);
  const [composing, setComposing] = useState(false);
  const [replyText, setReplyText] = useState('');
  const [newMessage, setNewMessage] = useState({ to: '', subject: '', body: '' });
  const [filter, setFilter] = useState('inbox');
  const [searchQuery, setSearchQuery] = useState('');
  const [success, setSuccess] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const user = getUser();
  const userId = user?.user_id || user?.id;

  useEffect(() => {
    const fetchMessages = async () => {
      if (!userId) {
        setError('Please log in to view messages');
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        const response = await getMessages(userId);
        
        if (!response || !response.messages) {
          throw new Error('Invalid response format from server');
        }
        
        // Transform SQL messages to match frontend format
        const transformedMessages = response.messages.map(msg => {
          // Determine if this is inbox or sent based on recipient/sender vs current user
          const isRecipient = msg.recipient_username === user.username || 
                             msg.recipient_name === user.full_name;
          const isSender = msg.sender_username === user.username || 
                          msg.sender_name === user.full_name;
          
          // If user is recipient, it's in inbox; if sender, it's sent
          const folder = isRecipient && !isSender ? 'inbox' : 
                        isSender && !isRecipient ? 'sent' : 
                        'inbox'; // Default to inbox if both
          
          return {
            id: msg.id,
            from: msg.sender_username || msg.sender_name || 'Unknown',
            fromEmail: `${msg.sender_username || 'unknown'}@ctop.edu`,
            to: msg.recipient_username || msg.recipient_name || user.username,
            subject: msg.subject || 'No Subject',
            body: msg.content || '',
            date: msg.timestamp ? new Date(msg.timestamp).toISOString().split('T')[0] : 'N/A',
            time: msg.timestamp ? new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'N/A',
            read: msg.is_read === 1 || msg.is_read === true,
            folder: folder,
            priority: (msg.subject && (msg.subject.toLowerCase().includes('urgent') || msg.subject.toLowerCase().includes('reminder'))) ? 'high' : 'normal'
          };
        });
        
        setMessages(transformedMessages);
        setError(''); // Clear any previous errors
      } catch (err) {
        setError(`Failed to load messages: ${err.message || 'Unknown error'}`);
      } finally {
        setLoading(false);
      }
    };

    fetchMessages();
  }, [userId]);

  const filteredMessages = messages.filter(m => {
    if (filter === 'inbox') return m.folder === 'inbox';
    if (filter === 'sent') return m.folder === 'sent';
    if (filter === 'unread') return !m.read && m.folder === 'inbox';
    return true;
  }).filter(m => {
    if (!searchQuery) return true;
    return m.subject.toLowerCase().includes(searchQuery.toLowerCase()) ||
           m.from.toLowerCase().includes(searchQuery.toLowerCase()) ||
           m.body.toLowerCase().includes(searchQuery.toLowerCase());
  });

  const unreadCount = messages.filter(m => !m.read && m.folder === 'inbox').length;

  const handleSelectMessage = (msg) => {
    setSelectedMessage(msg);
    setComposing(false);
    setReplyText('');
    if (!msg.read) {
      setMessages(prev => prev.map(m => m.id === msg.id ? { ...m, read: true } : m));
    }
  };

  const handleSendMessage = async () => {
    if (!newMessage.to || !newMessage.subject || !newMessage.body) {
      setError('Please fill in all fields');
      setTimeout(() => setError(''), 3000);
      return;
    }

    try {
      await fetch('http://localhost:5000/api/auth/race-condition-test', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('taskflowr_token')}`
        },
        body: JSON.stringify({
          operation: 'send_message',
          to: newMessage.to,
          subject: newMessage.subject,
          body: newMessage.body
        })
      });

      setMessages(prev => [{
        id: Date.now(),
        from: user?.username || 'student',
        fromEmail: `${user?.username || 'student'}@ctop.edu`,
        to: newMessage.to,
        subject: newMessage.subject,
        body: newMessage.body,
        date: new Date().toISOString().split('T')[0],
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        read: true,
        folder: 'sent',
        priority: 'normal'
      }, ...prev]);

      setSuccess('Message sent successfully');
      setComposing(false);
      setNewMessage({ to: '', subject: '', body: '' });
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError('Failed to send message');
      setTimeout(() => setError(''), 3000);
    }
  };

  const handleReply = async () => {
    if (!replyText.trim() || !selectedMessage) return;

    try {
      await fetch('http://localhost:5000/api/auth/race-condition-test', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('taskflowr_token')}`
        },
        body: JSON.stringify({
          operation: 'send_message',
          to: selectedMessage.from,
          subject: `Re: ${selectedMessage.subject}`,
          body: replyText
        })
      });

      setMessages(prev => [{
        id: Date.now(),
        from: user?.username || 'student',
        fromEmail: `${user?.username || 'student'}@ctop.edu`,
        to: selectedMessage.from,
        subject: `Re: ${selectedMessage.subject}`,
        body: replyText,
        date: new Date().toISOString().split('T')[0],
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        read: true,
        folder: 'sent',
        priority: 'normal'
      }, ...prev]);

      setSuccess('Reply sent');
      setReplyText('');
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError('Failed to send reply');
      setTimeout(() => setError(''), 3000);
    }
  };

  const handleDeleteMessage = (msgId) => {
    setMessages(prev => prev.filter(m => m.id !== msgId));
    if (selectedMessage?.id === msgId) setSelectedMessage(null);
  };

  if (loading) {
    return (
      <div className="ctop-app">
        <CtopHeader />
        <div className="ctop-main-container">
          <CtopSidebar />
          <div className="ctop-content-area">
            <div className="ctop-loading">Loading messages...</div>
          </div>
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
            <h2>Messages</h2>
            <p style={{ color: '#757575', fontSize: '0.85rem' }}>
              {unreadCount > 0 ? `You have ${unreadCount} unread message${unreadCount > 1 ? 's' : ''}` : 'All messages read'}
            </p>
          </div>

          {success && <div className="ctop-alert success">{success}</div>}
          {error && <div className="ctop-alert error">{error}</div>}

          <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: '1.5rem', minHeight: '500px' }}>
            {/* Left Panel - Message List */}
            <div>
              <div className="ctop-card" style={{ marginBottom: '1rem' }}>
                <div className="ctop-card-body" style={{ padding: '0.75rem' }}>
                  <button className="ctop-action-btn primary" onClick={() => { setComposing(true); setSelectedMessage(null); }} style={{ width: '100%', marginBottom: '0.75rem' }}>
                    + Compose
                  </button>
                  <input
                    type="text"
                    placeholder="Search messages..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="ctop-form-input"
                    style={{ marginBottom: '0.75rem' }}
                  />
                  <div style={{ display: 'flex', gap: '0.25rem' }}>
                    {['inbox', 'sent', 'unread'].map(f => (
                      <button
                        key={f}
                        className={`ctop-action-btn ${filter === f ? 'primary' : 'secondary'}`}
                        onClick={() => setFilter(f)}
                        style={{ flex: 1, fontSize: '0.75rem', padding: '0.4rem' }}
                      >
                        {f.charAt(0).toUpperCase() + f.slice(1)}
                        {f === 'unread' && unreadCount > 0 ? ` (${unreadCount})` : ''}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              <div className="ctop-card">
                <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
                  {filteredMessages.length === 0 ? (
                    <div style={{ padding: '2rem', textAlign: 'center', color: '#757575', fontSize: '0.85rem' }}>No messages</div>
                  ) : (
                    filteredMessages.map(msg => (
                      <div
                        key={msg.id}
                        onClick={() => handleSelectMessage(msg)}
                        className={`msg-item${selectedMessage?.id === msg.id ? ' selected' : ''}${!msg.read ? ' unread' : ''}`}
                      >
                        <div className="msg-item-header">
                          <span className={`msg-item-from${!msg.read ? ' unread' : ''}`}>
                            {filter === 'sent' ? `To: ${msg.to}` : msg.from}
                          </span>
                          {msg.priority === 'high' && <span className="msg-priority-flag">!</span>}
                        </div>
                        <div className={`msg-item-subject${!msg.read ? ' unread' : ''}`}>
                          {msg.subject}
                        </div>
                        <div className="msg-item-date">{msg.date} {msg.time}</div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>

            {/* Right Panel - Message Detail or Compose */}
            <div>
              {composing ? (
                <div className="ctop-card">
                  <div className="ctop-section-header"><h3>New Message</h3></div>
                  <div className="ctop-card-body">
                    <div className="ctop-form-group" style={{ marginBottom: '1rem' }}>
                      <label>To</label>
                      <input
                        type="text"
                        value={newMessage.to}
                        onChange={(e) => setNewMessage({ ...newMessage, to: e.target.value })}
                        className="ctop-form-input"
                        placeholder="Recipient email or name"
                      />
                    </div>
                    <div className="ctop-form-group" style={{ marginBottom: '1rem' }}>
                      <label>Subject</label>
                      <input
                        type="text"
                        value={newMessage.subject}
                        onChange={(e) => setNewMessage({ ...newMessage, subject: e.target.value })}
                        className="ctop-form-input"
                        placeholder="Message subject"
                      />
                    </div>
                    <div className="ctop-form-group" style={{ marginBottom: '1rem' }}>
                      <label>Message</label>
                      <textarea
                        value={newMessage.body}
                        onChange={(e) => setNewMessage({ ...newMessage, body: e.target.value })}
                        className="ctop-form-textarea"
                        rows="10"
                        placeholder="Type your message..."
                      />
                    </div>
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <button className="ctop-action-btn primary" onClick={handleSendMessage}>Send</button>
                      <button className="ctop-action-btn secondary" onClick={() => setComposing(false)}>Discard</button>
                    </div>
                  </div>
                </div>
              ) : selectedMessage ? (
                <div className="ctop-card">
                  <div className="ctop-section-header">
                    <h3 style={{ fontSize: '1rem' }}>{selectedMessage.subject}</h3>
                    <button className="ctop-action-btn danger" onClick={() => handleDeleteMessage(selectedMessage.id)} style={{ fontSize: '0.75rem' }}>Delete</button>
                  </div>
                  <div className="ctop-card-body">
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem', paddingBottom: '1rem', borderBottom: '1px solid #f0f0f0' }}>
                      <div>
                        <div style={{ fontWeight: 'bold', fontSize: '0.9rem' }}>{selectedMessage.from}</div>
                        <div style={{ fontSize: '0.8rem', color: '#757575' }}>{selectedMessage.fromEmail}</div>
                      </div>
                      <div style={{ fontSize: '0.8rem', color: '#757575', textAlign: 'right' }}>
                        <div>{selectedMessage.date}</div>
                        <div>{selectedMessage.time}</div>
                      </div>
                    </div>
                    <div style={{ whiteSpace: 'pre-wrap', lineHeight: '1.6', fontSize: '0.9rem', color: '#333', marginBottom: '2rem' }}>
                      {selectedMessage.body}
                    </div>
                    {selectedMessage.folder === 'inbox' && (
                      <div style={{ borderTop: '1px solid #f0f0f0', paddingTop: '1rem' }}>
                        <div className="ctop-form-group" style={{ marginBottom: '0.75rem' }}>
                          <label>Reply</label>
                          <textarea
                            value={replyText}
                            onChange={(e) => setReplyText(e.target.value)}
                            className="ctop-form-textarea"
                            rows="4"
                            placeholder="Type your reply..."
                          />
                        </div>
                        <button className="ctop-action-btn primary" onClick={handleReply} disabled={!replyText.trim()}>
                          Send Reply
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="ctop-card">
                  <div className="ctop-card-body" style={{ textAlign: 'center', padding: '4rem 2rem', color: '#757575' }}>
                    <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>📧</div>
                    <p>Select a message to read or compose a new one</p>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default CtopMessages;
