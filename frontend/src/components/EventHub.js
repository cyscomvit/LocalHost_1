import React, { useState, useEffect } from 'react';

function EventHub() {
  const [events, setEvents] = useState([]);

  useEffect(() => {
    // Mock events data - in real app, this would come from backend
    const mockEvents = [
      {
        date: '2024-02-11',
        type: 'ongoing',
        title: 'Mid-Semester Examination',
        time: '10:00 AM - 1:00 PM',
        venue: 'Exam Hall A'
      },
      {
        date: '2024-02-12',
        type: 'upcoming',
        title: 'Guest Lecture on Cybersecurity',
        time: '2:00 PM - 4:00 PM',
        venue: 'Auditorium'
      },
      {
        date: '2024-02-15',
        type: 'upcoming',
        title: 'Workshop: Secure Coding Practices',
        time: '9:00 AM - 5:00 PM',
        venue: 'Lab Complex'
      },
      {
        date: '2024-02-18',
        type: 'upcoming',
        title: 'Project Submission Deadline',
        time: '11:59 PM',
        venue: 'Online'
      }
    ];
    setEvents(mockEvents);
  }, []);

  const ongoingEvents = events.filter(event => event.type === 'ongoing');
  const upcomingEvents = events.filter(event => event.type === 'upcoming');

  return (
    <div className="ctop-event-hub">
      <div className="ctop-section-header">
        <h3>Event Hub: Events Scheduled</h3>
      </div>
      
      <div className="ctop-event-section">
        <div className="ctop-event-subheader">
          <span className="event-date">Today: {new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}</span>
          <span className="event-type ongoing">Ongoing Events</span>
        </div>
        <div className="ctop-event-list">
          {ongoingEvents.length > 0 ? (
            ongoingEvents.map((event, index) => (
              <div key={index} className="ctop-event-item ongoing">
                <div className="event-time">{event.time}</div>
                <div className="event-details">
                  <div className="event-title">{event.title}</div>
                  <div className="event-venue">{event.venue}</div>
                </div>
              </div>
            ))
          ) : (
            <div className="no-events">No ongoing events today</div>
          )}
        </div>
      </div>

      <div className="ctop-event-section">
        <div className="ctop-event-subheader">
          <span className="event-type upcoming">Forthcoming Events</span>
        </div>
        <div className="ctop-event-list">
          {upcomingEvents.map((event, index) => (
            <div key={index} className="ctop-event-item upcoming">
              <div className="event-date-badge">
                {new Date(event.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
              </div>
              <div className="event-details">
                <div className="event-title">{event.title}</div>
                <div className="event-meta">
                  <span className="event-time">{event.time}</span>
                  <span className="event-venue">{event.venue}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default EventHub;
