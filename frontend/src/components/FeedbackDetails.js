import React, { useState, useEffect } from 'react';

function FeedbackDetails() {
  const [feedbacks, setFeedbacks] = useState([]);

  useEffect(() => {
    // Mock feedback data - in real app, this would come from backend
    const mockFeedbacks = [
      {
        id: 1,
        feedback: 'Course Content and Structure',
        category: 'Academic',
        status: 'Completed',
        submittedDate: '2024-02-05'
      },
      {
        id: 2,
        feedback: 'Faculty Teaching Evaluation',
        category: 'Faculty',
        status: 'Pending',
        submittedDate: '2024-02-01'
      },
      {
        id: 3,
        feedback: 'Laboratory Facilities',
        category: 'Infrastructure',
        status: 'Completed',
        submittedDate: '2024-01-28'
      },
      {
        id: 4,
        feedback: 'Library Services',
        category: 'Infrastructure',
        status: 'Completed',
        submittedDate: '2024-01-25'
      },
      {
        id: 5,
        feedback: 'Campus Security',
        category: 'Administration',
        status: 'Pending',
        submittedDate: '2024-01-20'
      }
    ];
    setFeedbacks(mockFeedbacks);
  }, []);

  const getStatusColor = (status) => {
    return status === 'Completed' ? '#4caf50' : '#ff9800';
  };

  const getCategoryColor = (category) => {
    switch (category) {
      case 'Academic': return '#2196f3';
      case 'Faculty': return '#9c27b0';
      case 'Infrastructure': return '#009688';
      case 'Administration': return '#795548';
      default: return '#666';
    }
  };

  return (
    <div className="ctop-feedback-details">
      <div className="ctop-section-header">
        <h3>Last Five Feedback Details</h3>
      </div>
      
      <div className="ctop-feedback-table-container">
        <table className="ctop-feedback-table">
          <thead>
            <tr>
              <th>Feedback</th>
              <th>Category</th>
              <th>Status</th>
              <th>Submitted</th>
            </tr>
          </thead>
          <tbody>
            {feedbacks.map((feedback) => (
              <tr key={feedback.id} className="feedback-row">
                <td className="feedback-name">{feedback.feedback}</td>
                <td className="feedback-category">
                  <span 
                    className="category-badge"
                    style={{ backgroundColor: getCategoryColor(feedback.category) }}
                  >
                    {feedback.category}
                  </span>
                </td>
                <td className="feedback-status">
                  <span 
                    className="status-badge"
                    style={{ color: getStatusColor(feedback.status) }}
                  >
                    {feedback.status}
                  </span>
                </td>
                <td className="feedback-date">
                  {new Date(feedback.submittedDate).toLocaleDateString('en-US', {
                    month: 'short',
                    day: 'numeric',
                    year: 'numeric'
                  })}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="ctop-feedback-footer">
        <button className="view-all-feedback-btn">
          View All Feedback History →
        </button>
      </div>
    </div>
  );
}

export default FeedbackDetails;
