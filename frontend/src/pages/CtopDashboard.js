import React, { useState, useEffect } from 'react';
import CtopHeader from '../components/CtopHeader';
import CtopSidebar from '../components/CtopSidebar';
import CourseRegistrationTable from '../components/CourseRegistrationTable';
import EventHub from '../components/EventHub';
import SpotLight from '../components/SpotLight';
import CGPAStatus from '../components/CGPAStatus';
import FeedbackDetails from '../components/FeedbackDetails';
import ProctorMessage from '../components/ProctorMessage';
import { getTasks, getAdminStats } from '../api';

/**
 * CTOP Dashboard
 * Main student portal dashboard with real backend data integration
 */
function CtopDashboard() {
  const [tasks, setTasks] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        // Fetch tasks for course registration table
        const tasksData = await getTasks();
        setTasks(tasksData.tasks || []);

        // Try to fetch admin stats for dashboard metrics
        try {
          const statsData = await getAdminStats();
          setStats(statsData);
        } catch {
          // Admin stats might fail for non-admin users, that's okay
          setStats({
            total_users: 5,
            total_tasks: tasksData.tasks?.length || 0,
            security_score: 'F-',
            last_security_audit: 'Never'
          });
        }
      } catch (error) {
        console.error('Failed to fetch dashboard data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  if (loading) {
    return (
      <div className="ctop-app">
        <CtopHeader />
        <div className="ctop-main-container">
          <CtopSidebar />
          <div className="ctop-content-area">
            <div className="ctop-loading">Loading dashboard...</div>
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
          {/* Welcome Banner */}
          <div className="ctop-welcome-banner">
            <h2>Welcome to CTOP Dashboard</h2>
            <p>Manage your academic journey with Cyscom On Top</p>
            <div className="ctop-quick-stats">
              <div className="ctop-quick-stat">
                <span className="stat-number">{stats?.total_tasks || 0}</span>
                <span className="stat-label">Active Courses</span>
              </div>
              <div className="ctop-quick-stat">
                <span className="stat-number">{stats?.total_users || 0}</span>
                <span className="stat-label">Total Students</span>
              </div>
              <div className="ctop-quick-stat">
                <span className="stat-number">8.45</span>
                <span className="stat-label">Current CGPA</span>
              </div>
            </div>
          </div>

          <div className="ctop-content-grid">
            {/* Main Content - Left Side */}
            <div className="ctop-main-content">
              <CourseRegistrationTable />
              <div className="ctop-content-row">
                <div className="ctop-content-half">
                  <EventHub />
                </div>
                <div className="ctop-content-half">
                  <SpotLight />
                </div>
              </div>
            </div>
            
            {/* Sidebar Content - Right Side */}
            <div className="ctop-sidebar-content">
              <ProctorMessage />
              <CGPAStatus />
              <FeedbackDetails />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default CtopDashboard;
