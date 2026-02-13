import React, { useState, useEffect } from 'react';
import { getTasks } from '../api';

function CourseRegistrationTable() {
  const [courses, setCourses] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchCourses = async () => {
      try {
        const data = await getTasks();
        // Map tasks to course-like structure for demonstration
        const mappedCourses = data.tasks?.map((task, index) => {
          const attendance = Math.floor(Math.random() * 30) + 70;
          return {
            courseCode: `CS${String(index + 1001).padStart(4, '0')}`,
            courseName: task.title || `Course ${index + 1}`,
            courseType: index % 3 === 0 ? 'Theory' : index % 3 === 1 ? 'Lab' : 'Project',
            credits: index % 3 === 0 ? 3 : index % 3 === 1 ? 1 : 2,
            attendance: attendance,
            remarks: getRemark(attendance),
            faculty: task.assigned_to || 'TBA'
          };
        }) || [];
        setCourses(mappedCourses);
      } catch (error) {
        console.error('Failed to fetch courses:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchCourses();
  }, []);

  const getRemark = (attendance) => {
    if (attendance >= 80) return { text: 'Excellent - Keep going', color: '#4caf50' };
    if (attendance >= 75) return { text: 'Cautious', color: '#ff9800' };
    return { text: 'Need improvement', color: '#f44336' };
  };

  if (loading) {
    return <div className="ctop-loading">Loading course details...</div>;
  }

  return (
    <div className="ctop-course-registration">
      <div className="ctop-section-header">
        <h3>CURRENT SEMESTER COURSE REGISTRATION DETAILS</h3>
      </div>
      <div className="ctop-table-container">
        <table className="ctop-course-table">
          <thead>
            <tr>
              <th>Course Code</th>
              <th>Course Name</th>
              <th>Type</th>
              <th>Credits</th>
              <th>Attendance %</th>
              <th>Faculty</th>
              <th>Remarks</th>
            </tr>
          </thead>
          <tbody>
            {courses.map((course, index) => (
              <tr key={index} className={index % 2 === 0 ? 'even-row' : 'odd-row'}>
                <td className="course-code">{course.courseCode}</td>
                <td className="course-name">{course.courseName}</td>
                <td className="course-type">{course.courseType}</td>
                <td className="credits">{course.credits}</td>
                <td className="attendance">
                  <div className="attendance-bar">
                    <div 
                      className="attendance-fill"
                      style={{ 
                        width: `${course.attendance}%`,
                        backgroundColor: course.attendance >= 75 ? '#4caf50' : '#f44336'
                      }}
                    />
                    <span className="attendance-text">{course.attendance}%</span>
                  </div>
                </td>
                <td className="faculty">{course.faculty}</td>
                <td className="remarks">
                  <span style={{ color: course.remarks.color, fontWeight: 'bold' }}>
                    {course.remarks.text}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default CourseRegistrationTable;
