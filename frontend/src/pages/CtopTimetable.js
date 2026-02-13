import React, { useState, useEffect } from 'react';
import CtopHeader from '../components/CtopHeader';
import CtopSidebar from '../components/CtopSidebar';
import { getUser } from '../api';

function CtopTimetable() {
  const [selectedSlot, setSelectedSlot] = useState(null);
  const [bookedSlots, setBookedSlots] = useState({});
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [semester, setSemester] = useState('Fall 2024');
  const user = getUser();

  const timeSlots = [
    '08:00 - 08:50', '09:00 - 09:50', '10:00 - 10:50',
    '11:00 - 11:50', '12:00 - 12:50', '14:00 - 14:50',
    '15:00 - 15:50', '16:00 - 16:50'
  ];

  const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'];

  const courses = {
    'CSE1001': { name: 'Problem Solving & Programming', faculty: 'Dr. Sharma', room: 'AB1-301', color: '#e3f2fd' },
    'CSE1002': { name: 'Digital Logic Design', faculty: 'Dr. Patel', room: 'AB2-105', color: '#f3e5f5' },
    'MAT1001': { name: 'Calculus & Linear Algebra', faculty: 'Dr. Kumar', room: 'AB1-201', color: '#e8f5e9' },
    'PHY1001': { name: 'Engineering Physics', faculty: 'Dr. Reddy', room: 'SJT-302', color: '#fff3e0' },
    'ENG1001': { name: 'Technical English', faculty: 'Prof. Nair', room: 'TT-401', color: '#fce4ec' },
    'CSE1003': { name: 'Computer Architecture', faculty: 'Dr. Iyer', room: 'AB1-102', color: '#e0f2f1' },
  };

  const defaultSchedule = {
    'Monday-0': 'CSE1001', 'Monday-1': 'CSE1001', 'Monday-3': 'MAT1001', 'Monday-5': 'PHY1001', 'Monday-6': 'ENG1001',
    'Tuesday-0': 'CSE1002', 'Tuesday-2': 'MAT1001', 'Tuesday-3': 'MAT1001', 'Tuesday-5': 'CSE1003', 'Tuesday-7': 'PHY1001',
    'Wednesday-1': 'CSE1001', 'Wednesday-2': 'CSE1001', 'Wednesday-4': 'ENG1001', 'Wednesday-6': 'CSE1002',
    'Thursday-0': 'PHY1001', 'Thursday-1': 'PHY1001', 'Thursday-3': 'CSE1003', 'Thursday-5': 'MAT1001', 'Thursday-7': 'CSE1002',
    'Friday-0': 'ENG1001', 'Friday-2': 'CSE1003', 'Friday-3': 'CSE1003', 'Friday-5': 'CSE1001', 'Friday-6': 'CSE1002',
  };

  useEffect(() => {
    setBookedSlots(defaultSchedule);
  }, []);

  const handleSlotClick = (day, slotIndex) => {
    const key = `${day}-${slotIndex}`;
    if (bookedSlots[key]) {
      setSelectedSlot({ key, day, slotIndex, course: bookedSlots[key] });
    } else {
      setSelectedSlot({ key, day, slotIndex, course: null });
    }
  };

  const handleBookSlot = async (courseCode) => {
    if (!selectedSlot) return;
    setLoading(true);
    setMessage('');
    try {
      const response = await fetch('http://localhost:5000/api/auth/race-condition-test', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('taskflowr_token')}`
        },
        body: JSON.stringify({
          operation: 'book_slot',
          slot: selectedSlot.key,
          course: courseCode,
          user_id: user?.user_id
        })
      });
      const data = await response.json();
      setBookedSlots(prev => ({ ...prev, [selectedSlot.key]: courseCode }));
      setMessage(`Slot booked for ${courses[courseCode]?.name || courseCode}`);
      setSelectedSlot(null);
    } catch (err) {
      setMessage('Failed to book slot. Please try again.');
    } finally {
      setLoading(false);
      setTimeout(() => setMessage(''), 3000);
    }
  };

  const handleRemoveSlot = () => {
    if (!selectedSlot) return;
    setBookedSlots(prev => {
      const updated = { ...prev };
      delete updated[selectedSlot.key];
      return updated;
    });
    setMessage('Slot cleared');
    setSelectedSlot(null);
    setTimeout(() => setMessage(''), 3000);
  };

  return (
    <div className="ctop-app">
      <CtopHeader />
      <div className="ctop-main-container">
        <CtopSidebar />
        <div className="ctop-content-area">
          <div className="ctop-page-title">
            <h2>My Timetable</h2>
            <p style={{ color: '#757575', fontSize: '0.85rem' }}>
              View and manage your class schedule for {semester}
            </p>
          </div>

          {message && <div className="ctop-alert success">{message}</div>}

          <div className="ctop-card" style={{ marginBottom: '1.5rem' }}>
            <div className="ctop-section-header">
              <h3>Semester Schedule</h3>
              <select value={semester} onChange={(e) => setSemester(e.target.value)} className="ctop-filter-select">
                <option>Fall 2024</option>
                <option>Spring 2025</option>
              </select>
            </div>
            <div className="ctop-table-container" style={{ overflowX: 'auto' }}>
              <table className="ctop-course-table">
                <thead>
                  <tr>
                    <th style={{ minWidth: '100px' }}>Time</th>
                    {days.map(day => <th key={day}>{day}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {timeSlots.map((slot, slotIndex) => (
                    <tr key={slotIndex}>
                      <td style={{ fontWeight: 'bold', fontSize: '0.8rem', whiteSpace: 'nowrap' }}>{slot}</td>
                      {days.map(day => {
                        const key = `${day}-${slotIndex}`;
                        const courseCode = bookedSlots[key];
                        const course = courseCode ? courses[courseCode] : null;
                        const isSelected = selectedSlot?.key === key;
                        return (
                          <td
                            key={key}
                            onClick={() => handleSlotClick(day, slotIndex)}
                            style={{
                              background: course ? course.color : (isSelected ? '#e8eaf6' : 'transparent'),
                              cursor: 'pointer',
                              border: isSelected ? '2px solid #1976d2' : '1px solid #e0e0e0',
                              padding: '0.4rem',
                              minWidth: '120px',
                              fontSize: '0.75rem',
                              transition: 'all 0.2s'
                            }}
                          >
                            {course ? (
                              <div>
                                <div style={{ fontWeight: 'bold', color: '#333' }}>{courseCode}</div>
                                <div style={{ color: '#666', fontSize: '0.7rem' }}>{course.name}</div>
                                <div style={{ color: '#999', fontSize: '0.65rem' }}>{course.room}</div>
                              </div>
                            ) : (
                              <div style={{ color: '#ccc', textAlign: 'center' }}>—</div>
                            )}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {selectedSlot && (
            <div className="ctop-card" style={{ marginBottom: '1.5rem' }}>
              <div className="ctop-section-header">
                <h3>Slot: {selectedSlot.day}, {timeSlots[selectedSlot.slotIndex]}</h3>
              </div>
              <div className="ctop-card-body">
                {selectedSlot.course ? (
                  <div>
                    <p><strong>Current Course:</strong> {courses[selectedSlot.course]?.name} ({selectedSlot.course})</p>
                    <p><strong>Faculty:</strong> {courses[selectedSlot.course]?.faculty}</p>
                    <p><strong>Room:</strong> {courses[selectedSlot.course]?.room}</p>
                    <button className="ctop-action-btn danger" onClick={handleRemoveSlot} style={{ marginTop: '1rem' }}>
                      Remove from Slot
                    </button>
                  </div>
                ) : (
                  <div>
                    <p style={{ marginBottom: '1rem' }}>Select a course to book this slot:</p>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                      {Object.entries(courses).map(([code, course]) => (
                        <button
                          key={code}
                          className="ctop-action-btn primary"
                          onClick={() => handleBookSlot(code)}
                          disabled={loading}
                          style={{ fontSize: '0.8rem' }}
                        >
                          {code} — {course.name}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="ctop-card">
            <div className="ctop-section-header"><h3>Registered Courses</h3></div>
            <div className="ctop-card-body">
              <div className="course-card-grid">
                {Object.entries(courses).map(([code, course]) => (
                  <div key={code} className="course-card-item" style={{ background: course.color }}>
                    <div className="course-code-label">{code}</div>
                    <div className="course-name-label">{course.name}</div>
                    <div className="course-detail">Faculty: {course.faculty}</div>
                    <div className="course-detail">Room: {course.room}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default CtopTimetable;
