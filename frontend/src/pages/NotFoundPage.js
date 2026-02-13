import React from 'react';
import { Link } from 'react-router-dom';

function NotFoundPage() {
  return (
    <div className="not-found not-found-page">
      <h1>404</h1>
      <h2>Oops! This page took a sick day.</h2>
      <p>
        The page you're looking for doesn't exist. Maybe it was deployed on a Friday 
        and nobody noticed it broke. Classic CToP move.
      </p>
      <p className="not-found-sub">
        Fun fact: Our 404 page is more secure than our login page.
      </p>
      <div style={{ display: 'flex', gap: '1rem' }}>
        <Link to="/dashboard" className="btn btn-primary">Go to Dashboard</Link>
        <Link to="/login" className="btn btn-secondary">Back to Login</Link>
      </div>
      <div className="not-found-deco">---</div>
      <p className="not-found-quote">
        "This is fine." — CToP Engineering Team
      </p>
    </div>
  );
}

export default NotFoundPage;
