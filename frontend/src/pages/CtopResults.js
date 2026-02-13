import React, { useState, useEffect } from 'react';
import CtopHeader from '../components/CtopHeader';
import CtopSidebar from '../components/CtopSidebar';
import { getUser } from '../api';

function CtopResults() {
  const [selectedSemester, setSelectedSemester] = useState('Fall 2024');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const user = getUser();

  const semesterResults = {
    'Fall 2024': [
      { code: 'CSE1001', name: 'Problem Solving & Programming', credits: 4, grade: 'A', gradePoint: 9, type: 'Theory', faculty: 'Dr. Sharma' },
      { code: 'CSE1002', name: 'Digital Logic Design', credits: 4, grade: 'A+', gradePoint: 10, type: 'Theory', faculty: 'Dr. Patel' },
      { code: 'MAT1001', name: 'Calculus & Linear Algebra', credits: 4, grade: 'B+', gradePoint: 8, type: 'Theory', faculty: 'Dr. Kumar' },
      { code: 'PHY1001', name: 'Engineering Physics', credits: 3, grade: 'A', gradePoint: 9, type: 'Theory', faculty: 'Dr. Reddy' },
      { code: 'ENG1001', name: 'Technical English', credits: 2, grade: 'A+', gradePoint: 10, type: 'Theory', faculty: 'Prof. Nair' },
      { code: 'CSE1003', name: 'Computer Architecture', credits: 3, grade: 'B', gradePoint: 7, type: 'Theory', faculty: 'Dr. Iyer' },
    ],
    'Spring 2024': [
      { code: 'CSE2001', name: 'Data Structures & Algorithms', credits: 4, grade: 'A+', gradePoint: 10, type: 'Theory', faculty: 'Dr. Menon' },
      { code: 'CSE2002', name: 'Operating Systems', credits: 4, grade: 'A', gradePoint: 9, type: 'Theory', faculty: 'Dr. Gupta' },
      { code: 'MAT2001', name: 'Discrete Mathematics', credits: 3, grade: 'A', gradePoint: 9, type: 'Theory', faculty: 'Dr. Rao' },
      { code: 'CSE2003', name: 'Database Management Systems', credits: 4, grade: 'B+', gradePoint: 8, type: 'Theory', faculty: 'Dr. Singh' },
      { code: 'HUM1001', name: 'Ethics in Engineering', credits: 2, grade: 'A+', gradePoint: 10, type: 'Theory', faculty: 'Prof. Das' },
    ],
  };

  useEffect(() => {
    // Load results for current user's default semester
    loadResults(selectedSemester);
  }, []);

  const loadResults = (sem) => {
    setLoading(true);
    setTimeout(() => {
      setResults(semesterResults[sem] || []);
      setLoading(false);
    }, 300);
  };

  const handleSemesterChange = (sem) => {
    setSelectedSemester(sem);
    loadResults(sem);
  };

  const calculateSGPA = (courseList) => {
    if (!courseList.length) return '0.00';
    const totalCredits = courseList.reduce((sum, c) => sum + c.credits, 0);
    const totalPoints = courseList.reduce((sum, c) => sum + (c.credits * c.gradePoint), 0);
    return (totalPoints / totalCredits).toFixed(2);
  };

  const totalCredits = results.reduce((sum, c) => sum + c.credits, 0);
  const sgpa = calculateSGPA(results);

  const getGradeColor = (grade) => {
    if (grade === 'A+' || grade === 'S') return '#2e7d32';
    if (grade === 'A') return '#1565c0';
    if (grade === 'B+') return '#f57f17';
    if (grade === 'B') return '#e65100';
    if (grade === 'C') return '#bf360c';
    return '#757575';
  };

  return (
    <div className="ctop-app">
      <CtopHeader />
      <div className="ctop-main-container">
        <CtopSidebar />
        <div className="ctop-content-area">
          <div className="ctop-page-title">
            <h2>Examination Results</h2>
            <p style={{ color: '#757575', fontSize: '0.85rem' }}>
              View your semester-wise examination results and grade history
            </p>
          </div>

          {error && <div className="ctop-alert error">{error}</div>}

          {/* Semester Selection */}
          <div className="ctop-card" style={{ marginBottom: '1.5rem' }}>
            <div className="ctop-section-header">
              <h3>Select Semester</h3>
            </div>
            <div className="ctop-card-body">
              <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', flexWrap: 'wrap' }}>
                <div className="ctop-form-group" style={{ flex: '0 0 250px' }}>
                  <label>Semester</label>
                  <select
                    value={selectedSemester}
                    onChange={(e) => handleSemesterChange(e.target.value)}
                    className="ctop-form-select"
                  >
                    <option>Fall 2024</option>
                    <option>Spring 2024</option>
                  </select>
                </div>
              </div>
            </div>
          </div>

          {/* SGPA Summary */}
          <div className="ctop-stats-grid" style={{ marginBottom: '1.5rem' }}>
            <div className="ctop-stat-card">
              <div className="ctop-stat-label">SGPA</div>
              <div className="ctop-stat-value" style={{ color: '#1976d2' }}>{sgpa}</div>
            </div>
            <div className="ctop-stat-card">
              <div className="ctop-stat-label">Credits Earned</div>
              <div className="ctop-stat-value">{totalCredits}</div>
            </div>
            <div className="ctop-stat-card">
              <div className="ctop-stat-label">Courses</div>
              <div className="ctop-stat-value">{results.length}</div>
            </div>
            <div className="ctop-stat-card">
              <div className="ctop-stat-label">CGPA</div>
              <div className="ctop-stat-value" style={{ color: '#2e7d32' }}>8.45</div>
            </div>
          </div>

          {/* Results Table */}
          <div className="ctop-card">
            <div className="ctop-section-header">
              <h3>Grade Sheet — {selectedSemester}</h3>
            </div>
            <div className="ctop-table-container">
              {loading ? (
                <div className="ctop-loading">Loading results...</div>
              ) : results.length === 0 ? (
                <div style={{ padding: '2rem', textAlign: 'center', color: '#757575' }}>No results available for this semester</div>
              ) : (
                <table className="ctop-course-table">
                  <thead>
                    <tr>
                      <th>Sl. No.</th>
                      <th>Course Code</th>
                      <th>Course Title</th>
                      <th>Type</th>
                      <th>Credits</th>
                      <th>Grade</th>
                      <th>Grade Points</th>
                      <th>Faculty</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.map((course, index) => (
                      <tr key={course.code} className={index % 2 === 0 ? 'even-row' : 'odd-row'}>
                        <td>{index + 1}</td>
                        <td className="course-code">{course.code}</td>
                        <td className="course-name">{course.name}</td>
                        <td>{course.type}</td>
                        <td style={{ textAlign: 'center' }}>{course.credits}</td>
                        <td style={{ textAlign: 'center' }}>
                          <span style={{
                            color: getGradeColor(course.grade),
                            fontWeight: 'bold',
                            fontSize: '1rem'
                          }}>
                            {course.grade}
                          </span>
                        </td>
                        <td style={{ textAlign: 'center' }}>{course.gradePoint}</td>
                        <td style={{ fontSize: '0.8rem', color: '#666' }}>{course.faculty}</td>
                      </tr>
                    ))}
                    <tr style={{ background: '#e3f2fd', fontWeight: 'bold' }}>
                      <td colSpan="4" style={{ textAlign: 'right' }}>Total</td>
                      <td style={{ textAlign: 'center' }}>{totalCredits}</td>
                      <td colSpan="3" style={{ textAlign: 'center' }}>SGPA: {sgpa}</td>
                    </tr>
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default CtopResults;
