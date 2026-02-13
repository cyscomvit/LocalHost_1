import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import CtopDashboard from './pages/CtopDashboard';
import CtopAcademics from './pages/CtopAcademics';
import CtopTimetable from './pages/CtopTimetable';
import CtopResults from './pages/CtopResults';
import CtopFeePayment from './pages/CtopFeePayment';
import CtopProfile from './pages/CtopProfile';
import CtopMessages from './pages/CtopMessages';
import CtopSettings from './pages/CtopSettings';
import CtopAdmin from './pages/CtopAdmin';
import CtopSystemAdmin from './pages/CtopSystemAdmin';
import NotFoundPage from './pages/NotFoundPage';
import XSSDemo from './pages/XSSDemo';
import { getToken } from './api';

function PrivateRoute() {
  return getToken() ? <Outlet /> : <Navigate to="/login" />;
}

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route element={<PrivateRoute />}>
          <Route path="/" element={<CtopDashboard />} />
          <Route path="/dashboard" element={<CtopDashboard />} />
          <Route path="/academics" element={<CtopAcademics />} />
          <Route path="/timetable" element={<CtopTimetable />} />
          <Route path="/results" element={<CtopResults />} />
          <Route path="/fee-payment" element={<CtopFeePayment />} />
          <Route path="/profile" element={<CtopProfile />} />
          <Route path="/profile/:id" element={<CtopProfile />} />
          <Route path="/messages" element={<CtopMessages />} />
          <Route path="/settings" element={<CtopSettings />} />
          <Route path="/admin" element={<CtopAdmin />} />
          <Route path="/system-admin" element={<CtopSystemAdmin />} />
          <Route path="/xss-demo" element={<XSSDemo />} />
        </Route>
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </Router>
  );
}

export default App;
