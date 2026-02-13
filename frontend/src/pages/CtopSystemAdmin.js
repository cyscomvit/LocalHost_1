import React, { useState, useEffect } from 'react';
import CtopHeader from '../components/CtopHeader';
import CtopSidebar from '../components/CtopSidebar';
import { getUser } from '../api';

function CtopSystemAdmin() {
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState('');
  const user = getUser();

  const [scanData, setScanData] = useState({
    scan_type: 'basic',
    target: 'localhost',
    url: '',
    pattern: '',
    file: 'access.log'
  });

  const [ldapData, setLdapData] = useState({
    query: '',
    search_type: 'user'
  });

  const [cryptoData, setCryptoData] = useState({
    text: '',
    algorithm: 'md5'
  });

  const showMsg = (text) => { setError(''); setResults(text); };
  const showErr = (text) => { setError(text); setResults(null); };

  const handleSystemScan = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await fetch('http://localhost:5000/api/security/system-scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('taskflowr_token')}`
        },
        body: JSON.stringify(scanData)
      });
      const data = await response.json();
      if (response.ok) {
        showMsg(data);
      } else {
        showErr(data.error || 'Scan failed');
      }
    } catch (err) {
      showErr('Network error during scan');
    } finally {
      setLoading(false);
    }
  };

  const handleLdapQuery = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await fetch('http://localhost:5000/api/security/ldap-query', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('taskflowr_token')}`
        },
        body: JSON.stringify(ldapData)
      });
      const data = await response.json();
      if (response.ok) {
        showMsg(data);
      } else {
        showErr(data.error || 'LDAP query failed');
      }
    } catch (err) {
      showErr('LDAP service unavailable');
    } finally {
      setLoading(false);
    }
  };

  const handleLogAnalysis = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await fetch('http://localhost:5000/api/security/log-analysis', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('taskflowr_token')}`
        },
        body: JSON.stringify(scanData)
      });
      const data = await response.json();
      if (response.ok) {
        showMsg(data);
      } else {
        showErr(data.error || 'Log analysis failed');
      }
    } catch (err) {
      showErr('Log service unavailable');
    } finally {
      setLoading(false);
    }
  };

  const handleCryptoTest = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await fetch('http://localhost:5000/api/security/crypto-analysis', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('taskflowr_token')}`
        },
        body: JSON.stringify(cryptoData)
      });
      const data = await response.json();
      if (response.ok) {
        showMsg(data);
      } else {
        showErr(data.error || 'Crypto analysis failed');
      }
    } catch (err) {
      showErr('Crypto service unavailable');
    } finally {
      setLoading(false);
    }
  };

  const loadDependencyCheck = async () => {
    setLoading(true);
    try {
      const response = await fetch('http://localhost:5000/api/security/dependency-check', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('taskflowr_token')}`
        }
      });
      const data = await response.json();
      if (response.ok) {
        showMsg(data);
      } else {
        showErr('Dependency check failed');
      }
    } catch (err) {
      showErr('Service unavailable');
    } finally {
      setLoading(false);
    }
  };

  const loadSessionAnalysis = async () => {
    setLoading(true);
    try {
      const response = await fetch('http://localhost:5000/api/security/session-analysis', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('taskflowr_token')}`
        }
      });
      const data = await response.json();
      if (response.ok) {
        showMsg(data);
      } else {
        showErr('Session analysis failed');
      }
    } catch (err) {
      showErr('Service unavailable');
    } finally {
      setLoading(false);
    }
  };

  const loadCsrfTest = async () => {
    setLoading(true);
    try {
      const response = await fetch('http://localhost:5000/api/security/csrf-test', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('taskflowr_token')}`
        }
      });
      const data = await response.json();
      if (response.ok) {
        showMsg(data);
      } else {
        showErr('CSRF test failed');
      }
    } catch (err) {
      showErr('Service unavailable');
    } finally {
      setLoading(false);
    }
  };

  const loadCorsAnalysis = async () => {
    setLoading(true);
    try {
      const response = await fetch('http://localhost:5000/api/security/cors-analysis', {
        method: 'OPTIONS',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('taskflowr_token')}`
        }
      });
      const data = await response.json();
      if (response.ok) {
        showMsg(data);
      } else {
        showErr('CORS analysis failed');
      }
    } catch (err) {
      showErr('Service unavailable');
    } finally {
      setLoading(false);
    }
  };

  const loadHiddenEndpoints = async () => {
    setLoading(true);
    try {
      const response = await fetch('http://localhost:5000/api/security/hidden-endpoints', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('taskflowr_token')}`
        }
      });
      const data = await response.json();
      if (response.ok) {
        showMsg(data);
      } else {
        showErr('Endpoint discovery failed');
      }
    } catch (err) {
      showErr('Service unavailable');
    } finally {
      setLoading(false);
    }
  };

  const testPrototypePollution = async () => {
    setLoading(true);
    try {
      const response = await fetch('http://localhost:5000/api/security/prototype-pollution', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('taskflowr_token')}`
        },
        body: JSON.stringify({
          '__proto__': { 'admin': true },
          'constructor': { 'prototype': { 'isAdmin': true } }
        })
      });
      const data = await response.json();
      if (response.ok) {
        showMsg(data);
      } else {
        showErr('Prototype pollution test failed');
      }
    } catch (err) {
      showErr('Service unavailable');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'dependencies') loadDependencyCheck();
    if (activeTab === 'session') loadSessionAnalysis();
    if (activeTab === 'csrf') loadCsrfTest();
    if (activeTab === 'cors') loadCorsAnalysis();
    if (activeTab === 'hidden') loadHiddenEndpoints();
  }, [activeTab]);

  return (
    <div className="ctop-app">
      <CtopHeader />
      <div className="ctop-main-container">
        <CtopSidebar />
        <div className="ctop-content-area">
          <div className="ctop-page-title">
            <h2>System Administration</h2>
            <p style={{ color: '#757575', fontSize: '0.85rem' }}>
              Security monitoring and system management tools
            </p>
          </div>

          {error && <div className="ctop-alert error">{error}</div>}

          {/* Tab Navigation */}
          <div className="ctop-card" style={{ marginBottom: '1.5rem' }}>
            <div className="ctop-card-body">
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                {[
                  { id: 'overview', label: 'Overview' },
                  { id: 'scan', label: 'System Scan' },
                  { id: 'ldap', label: 'Directory Search' },
                  { id: 'logs', label: 'Log Analysis' },
                  { id: 'crypto', label: 'Crypto Tools' },
                  { id: 'dependencies', label: 'Dependencies' },
                  { id: 'session', label: 'Session Analysis' },
                  { id: 'csrf', label: 'CSRF Test' },
                  { id: 'cors', label: 'CORS Analysis' },
                  { id: 'hidden', label: 'Endpoint Discovery' },
                  { id: 'pollution', label: 'Prototype Test' }
                ].map(tab => (
                  <button
                    key={tab.id}
                    className={`ctop-action-btn ${activeTab === tab.id ? 'primary' : 'secondary'}`}
                    onClick={() => setActiveTab(tab.id)}
                    style={{ fontSize: '0.8rem' }}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Overview Tab */}
          {activeTab === 'overview' && (
            <div className="ctop-card">
              <div className="ctop-section-header"><h3>System Security Overview</h3></div>
              <div className="ctop-card-body">
                <div className="ctop-stats-grid">
                  <div className="ctop-stat-card">
                    <div className="ctop-stat-label">Security Score</div>
                    <div className="ctop-stat-value" style={{ color: '#f44336' }}>C-</div>
                  </div>
                  <div className="ctop-stat-card">
                    <div className="ctop-stat-label">Active Sessions</div>
                    <div className="ctop-stat-value">47</div>
                  </div>
                  <div className="ctop-stat-card">
                    <div className="ctop-stat-label">Failed Logins (24h)</div>
                    <div className="ctop-stat-value" style={{ color: '#ff9800' }}>23</div>
                  </div>
                  <div className="ctop-stat-card">
                    <div className="ctop-stat-label">Vulnerable Dependencies</div>
                    <div className="ctop-stat-value" style={{ color: '#f44336' }}>5</div>
                  </div>
                </div>
                <div style={{ marginTop: '1.5rem' }}>
                  <h4>Recent Security Events</h4>
                  <div style={{ background: '#fff3e0', padding: '1rem', borderRadius: '4px', marginTop: '0.5rem' }}>
                    <p>- Multiple failed admin login attempts detected</p>
                    <p>- Outdated dependencies with known CVEs</p>
                    <p>- CORS configuration allows all origins</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* System Scan Tab */}
          {activeTab === 'scan' && (
            <div className="ctop-card">
              <div className="ctop-section-header"><h3>Security Scanning Tools</h3></div>
              <div className="ctop-card-body">
                <div className="ctop-form-row" style={{ marginBottom: '1rem' }}>
                  <div className="ctop-form-group">
                    <label>Scan Type</label>
                    <select value={scanData.scan_type} onChange={(e) => setScanData({...scanData, scan_type: e.target.value})} className="ctop-form-select">
                      <option value="basic">Basic Scan</option>
                      <option value="port">Port Scan</option>
                      <option value="web">Web Scan</option>
                    </select>
                  </div>
                  <div className="ctop-form-group">
                    <label>Target</label>
                    <input type="text" value={scanData.target} onChange={(e) => setScanData({...scanData, target: e.target.value})} className="ctop-form-input" placeholder="localhost or IP address" />
                  </div>
                </div>
                {scanData.scan_type === 'web' && (
                  <div className="ctop-form-group" style={{ marginBottom: '1rem' }}>
                    <label>URL</label>
                    <input type="url" value={scanData.url} onChange={(e) => setScanData({...scanData, url: e.target.value})} className="ctop-form-input" placeholder="http://target-url" />
                  </div>
                )}
                <button className="ctop-action-btn primary" onClick={handleSystemScan} disabled={loading}>
                  {loading ? 'Scanning...' : 'Start Scan'}
                </button>
              </div>
            </div>
          )}

          {/* LDAP Tab */}
          {activeTab === 'ldap' && (
            <div className="ctop-card">
              <div className="ctop-section-header"><h3>Directory Search</h3></div>
              <div className="ctop-card-body">
                <div className="ctop-form-row" style={{ marginBottom: '1rem' }}>
                  <div className="ctop-form-group">
                    <label>Search Type</label>
                    <select value={ldapData.search_type} onChange={(e) => setLdapData({...ldapData, search_type: e.target.value})} className="ctop-form-select">
                      <option value="user">User Search</option>
                      <option value="group">Group Search</option>
                      <option value="all">All Objects</option>
                    </select>
                  </div>
                  <div className="ctop-form-group">
                    <label>Query</label>
                    <input type="text" value={ldapData.query} onChange={(e) => setLdapData({...ldapData, query: e.target.value})} className="ctop-form-input" placeholder="Name, email, or filter" />
                  </div>
                </div>
                <button className="ctop-action-btn primary" onClick={handleLdapQuery} disabled={loading}>
                  {loading ? 'Searching...' : 'Search Directory'}
                </button>
              </div>
            </div>
          )}

          {/* Log Analysis Tab */}
          {activeTab === 'logs' && (
            <div className="ctop-card">
              <div className="ctop-section-header"><h3>Log Analysis</h3></div>
              <div className="ctop-card-body">
                <div className="ctop-form-row" style={{ marginBottom: '1rem' }}>
                  <div className="ctop-form-group">
                    <label>Log File</label>
                    <input type="text" value={scanData.file} onChange={(e) => setScanData({...scanData, file: e.target.value})} className="ctop-form-input" placeholder="access.log" />
                  </div>
                  <div className="ctop-form-group">
                    <label>Search Pattern</label>
                    <input type="text" value={scanData.pattern} onChange={(e) => setScanData({...scanData, pattern: e.target.value})} className="ctop-form-input" placeholder="error, failed, admin" />
                  </div>
                </div>
                <button className="ctop-action-btn primary" onClick={handleLogAnalysis} disabled={loading}>
                  {loading ? 'Analyzing...' : 'Analyze Logs'}
                </button>
              </div>
            </div>
          )}

          {/* Crypto Tab */}
          {activeTab === 'crypto' && (
            <div className="ctop-card">
              <div className="ctop-section-header"><h3>Cryptography Tools</h3></div>
              <div className="ctop-card-body">
                <div className="ctop-form-row" style={{ marginBottom: '1rem' }}>
                  <div className="ctop-form-group">
                    <label>Algorithm</label>
                    <select value={cryptoData.algorithm} onChange={(e) => setCryptoData({...cryptoData, algorithm: e.target.value})} className="ctop-form-select">
                      <option value="md5">MD5</option>
                      <option value="sha1">SHA1</option>
                      <option value="base64">Base64</option>
                    </select>
                  </div>
                  <div className="ctop-form-group">
                    <label>Text</label>
                    <input type="text" value={cryptoData.text} onChange={(e) => setCryptoData({...cryptoData, text: e.target.value})} className="ctop-form-input" placeholder="Text to hash/encode" />
                  </div>
                </div>
                <button className="ctop-action-btn primary" onClick={handleCryptoTest} disabled={loading}>
                  {loading ? 'Processing...' : 'Process Text'}
                </button>
              </div>
            </div>
          )}

          {/* Results Display */}
          {results && (
            <div className="ctop-card" style={{ marginTop: '1.5rem' }}>
              <div className="ctop-section-header"><h3>Results</h3></div>
              <div className="ctop-card-body">
                <pre style={{
                  background: '#f5f5f5',
                  padding: '1rem',
                  borderRadius: '4px',
                  fontSize: '0.8rem',
                  overflow: 'auto',
                  maxHeight: '400px',
                  whiteSpace: 'pre-wrap'
                }}>
                  {JSON.stringify(results, null, 2)}
                </pre>
              </div>
            </div>
          )}

          {/* Prototype Pollution Tab */}
          {activeTab === 'pollution' && (
            <div className="ctop-card">
              <div className="ctop-section-header"><h3>JavaScript Security Test</h3></div>
              <div className="ctop-card-body">
                <p style={{ marginBottom: '1rem', color: '#757575' }}>
                  Test for JavaScript prototype pollution vulnerabilities
                </p>
                <button className="ctop-action-btn primary" onClick={testPrototypePollution} disabled={loading}>
                  {loading ? 'Testing...' : 'Test Prototype Pollution'}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default CtopSystemAdmin;
