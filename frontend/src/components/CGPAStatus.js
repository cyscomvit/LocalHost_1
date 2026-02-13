import React, { useState, useEffect } from 'react';

function CGPAStatus() {
  const [cgpaData, setCgpaData] = useState({
    totalCredits: 160,
    earnedCredits: 124,
    currentCGPA: 8.45,
    nonGradedCore: 2
  });

  useEffect(() => {
    // Mock CGPA data - in real app, this would come from backend
    // For now, we'll use static data to match the VTOP style
  }, []);

  const creditPercentage = (cgpaData.earnedCredits / cgpaData.totalCredits) * 100;

  return (
    <div className="ctop-cgpa-status">
      <div className="ctop-section-header">
        <h3>CGPA and CREDIT Status</h3>
      </div>
      
      <div className="ctop-cgpa-grid">
        <div className="ctop-cgpa-item total-credits">
          <div className="cgpa-label">Total Credits Required</div>
          <div className="cgpa-value">{cgpaData.totalCredits}</div>
        </div>
        
        <div className="ctop-cgpa-item earned-credits">
          <div className="cgpa-label">Earned Credits</div>
          <div className="cgpa-value">{cgpaData.earnedCredits}</div>
          <div className="cgpa-progress">
            <div 
              className="cgpa-progress-fill"
              style={{ width: `${creditPercentage}%` }}
            />
          </div>
        </div>
        
        <div className="ctop-cgpa-item current-cgpa">
          <div className="cgpa-label">Current CGPA</div>
          <div className="cgpa-value cgpa-highlight">{cgpaData.currentCGPA}</div>
        </div>
        
        <div className="ctop-cgpa-item non-graded">
          <div className="cgpa-label">Non-graded Core Requirement</div>
          <div className="cgpa-value non-graded-value">{cgpaData.nonGradedCore}</div>
        </div>
      </div>

      <div className="ctop-cgpa-summary">
        <div className="cgpa-summary-item">
          <span className="summary-label">Credits Completed:</span>
          <span className="summary-value">{creditPercentage.toFixed(1)}%</span>
        </div>
        <div className="cgpa-summary-item">
          <span className="summary-label">Academic Standing:</span>
          <span className="summary-value standing-excellent">Excellent</span>
        </div>
      </div>
    </div>
  );
}

export default CGPAStatus;
