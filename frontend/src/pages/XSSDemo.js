import React, { useState, useEffect } from 'react';
import CtopHeader from '../components/CtopHeader';
import CtopSidebar from '../components/CtopSidebar';

function XSSDemo() {
  const [announcements, setAnnouncements] = useState([]);
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [message, setMessage] = useState('');

  useEffect(() => {
    fetchAnnouncements();
  }, []);

  const fetchAnnouncements = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/xss/announcements');
      const data = await response.json();
      setAnnouncements(data.announcements || []);
    } catch (error) {
      console.error('Error:', error);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await fetch('http://localhost:5000/api/xss/announcements', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title, content })
      });
      setMessage('Posted!');
      setTitle('');
      setContent('');
      fetchAnnouncements();
      setTimeout(() => setMessage(''), 3000);
    } catch (error) {
      setMessage('Error!');
    }
  };

  const handleDelete = async (id) => {
    await fetch(`http://localhost:5000/api/xss/announcements/${id}`, { method: 'DELETE' });
    fetchAnnouncements();
  };

  return (
    <div className="ctop-app">
      <CtopHeader />
      <div className="ctop-main-container">
        <CtopSidebar />
        <div className="ctop-content-area">
          <h1 style={{ fontSize: '24px', fontWeight: 'bold', marginBottom: '10px' }}>Announcements</h1>

          {message && <div className="flash-msg">{message}</div>}

          <div className="form-card">
            <h3>Post Announcement</h3>
            <form onSubmit={handleSubmit}>
              <input
                type="text"
                placeholder="Title"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
              />
              <textarea
                placeholder="Content "
                value={content}
                onChange={(e) => setContent(e.target.value)}
                rows="4"
              />
              <button type="submit">
                Post Announcement
              </button>
            </form>
          </div>

          <div>
            <h3>Announcements</h3>
            {announcements.map((ann) => (
              <div key={ann.id} className="announcement-card">
                <div className="announcement-header">
                  {/* VULNERABLE: dangerouslySetInnerHTML renders raw HTML - XSS! */}
                  <h4 dangerouslySetInnerHTML={{ __html: ann.title }}></h4>
                  <button onClick={() => handleDelete(ann.id)} className="btn-delete-sm">
                    Delete
                  </button>
                </div>
                {/* VULNERABLE: renders raw HTML - XSS! */}
                <div className="announcement-body" dangerouslySetInnerHTML={{ __html: ann.content }}></div>
                <small className="announcement-meta">By {ann.author} at {ann.created_at}</small>
              </div>
            ))}
          </div>

          {/* SECURE VERSION (commented out)
          <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(ann.content) }}></div>
          OR simply use: <div>{ann.content}</div>
          */}
        </div>
      </div>
    </div>
  );
}

export default XSSDemo;
