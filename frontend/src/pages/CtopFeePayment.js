import React, { useState, useEffect } from 'react';
import CtopHeader from '../components/CtopHeader';
import CtopSidebar from '../components/CtopSidebar';
import { getUser } from '../api';

function CtopFeePayment() {
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [paymentHistory, setPaymentHistory] = useState([]);
  const [selectedFee, setSelectedFee] = useState(null);
  const [paymentMethod, setPaymentMethod] = useState('upi'); // Default to UPI for fun!
  const [showReceipt, setShowReceipt] = useState(null);
  const [showQR, setShowQR] = useState(false);
  const [paymentStage, setPaymentStage] = useState('select'); // select, qr, processing, success
  const [upiId, setUpiId] = useState('maxdad93@okaxis'); // Fake UPI ID
  const [countdown, setCountdown] = useState(300); // 5 minutes countdown
  const [selectedAmount, setSelectedAmount] = useState(null); // For custom amounts
  const [showPaymentModal, setShowPaymentModal] = useState(false); // Modal state
  const user = getUser();

  // Small amount options for demo
  const demoAmounts = [
    { id: 'demo1', label: 'Quick Test', amount: 1 },
    { id: 'demo2', label: 'Coffee Fund', amount: 5 },
    { id: 'demo3', label: 'Lunch Money', amount: 10 }
  ];

  const feeStructure = [
    { id: 1, category: 'Tuition Fee', amount: 87500, semester: 'Fall 2024', dueDate: '2024-07-15', status: 'paid' },
    { id: 2, category: 'Hostel Fee', amount: 45000, semester: 'Fall 2024', dueDate: '2024-07-15', status: 'paid' },
    { id: 3, category: 'Examination Fee', amount: 3500, semester: 'Fall 2024', dueDate: '2024-11-01', status: 'pending' },
    { id: 4, category: 'Library Fee', amount: 2000, semester: 'Fall 2024', dueDate: '2024-07-15', status: 'paid' },
    { id: 5, category: 'Lab Fee', amount: 5000, semester: 'Fall 2024', dueDate: '2024-07-15', status: 'paid' },
    { id: 6, category: 'Tuition Fee', amount: 87500, semester: 'Spring 2025', dueDate: '2025-01-15', status: 'pending' },
    { id: 7, category: 'Hostel Fee', amount: 45000, semester: 'Spring 2025', dueDate: '2025-01-15', status: 'pending' },
  ];

  useEffect(() => {
    setPaymentHistory([
      { id: 'TXN20240715001', date: '2024-07-15', amount: 87500, category: 'Tuition Fee', method: 'Net Banking', status: 'Success', receiptNo: 'RCPT-2024-0451' },
      { id: 'TXN20240715002', date: '2024-07-15', amount: 45000, category: 'Hostel Fee', method: 'UPI', status: 'Success', receiptNo: 'RCPT-2024-0452' },
      { id: 'TXN20240715003', date: '2024-07-15', amount: 2000, category: 'Library Fee', method: 'Credit Card', status: 'Success', receiptNo: 'RCPT-2024-0453' },
      { id: 'TXN20240715004', date: '2024-07-15', amount: 5000, category: 'Lab Fee', method: 'Net Banking', status: 'Success', receiptNo: 'RCPT-2024-0454' },
    ]);
  }, []);

  const pendingFees = feeStructure.filter(f => f.status === 'pending');
  const paidFees = feeStructure.filter(f => f.status === 'paid');
  const totalPending = pendingFees.reduce((sum, f) => sum + f.amount, 0);
  const totalPaid = paidFees.reduce((sum, f) => sum + f.amount, 0);

  const handlePayFee = async (fee) => {
    setSelectedFee(fee);
    setSelectedAmount(null);
    setShowPaymentModal(true);
    setPaymentStage('qr');
    setShowQR(true);
    setCountdown(300); // Reset countdown
    startCountdown();
  };

  const handleDemoPayment = (demo) => {
    setSelectedFee({
      id: demo.id,
      category: demo.label,
      amount: demo.amount,
      semester: 'Demo',
      dueDate: 'Today'
    });
    setSelectedAmount(demo.amount);
    setShowPaymentModal(true);
    setPaymentStage('qr');
    setShowQR(true);
    setCountdown(300); // Reset countdown
    startCountdown();
  };

  const startCountdown = () => {
    const timer = setInterval(() => {
      setCountdown(prev => {
        if (prev <= 1) {
          clearInterval(timer);
          setPaymentStage('select');
          setShowQR(false);
          setError('QR Code expired! Please try again.');
          return 300;
        }
        return prev - 1;
      });
    }, 1000);
  };

  const processPayment = async () => {
    if (!selectedFee) return;
    setPaymentStage('processing');
    setLoading(true);
    setError('');
    setMessage('');
    
    // MIDDLEWARE ATTACK DEMO - Request Tampering
    const originalAmount = selectedFee.amount;
    const tamperedAmount = Math.floor(originalAmount * 0.1); // Only pay 10%!
    
    // Simulate middleware intercepting and modifying the request
    console.log('MIDDLEWARE ATTACK DETECTED:');
    console.log('Original request:', {
      amount: originalAmount,
      category: selectedFee.category,
      user: user?.username
    });
    console.log('Modified request:', {
      amount: tamperedAmount,
      category: selectedFee.category,
      user: user?.username,
      note: 'Amount reduced by 90% via middleware tampering!'
    });
    
    // Simulate payment processing with tampered data
    setTimeout(() => {
      const txnId = `TXN${Date.now()}`;
      const receiptNo = `RCPT-2024-${Math.floor(Math.random() * 9000 + 1000)}`;

      // Add tampered payment to history
      setPaymentHistory(prev => [{
        id: txnId,
        date: new Date().toISOString().split('T')[0],
        amount: tamperedAmount, // Tampered amount!
        category: selectedFee.category,
        method: 'UPI',
        status: 'Success',
        receiptNo,
        // Hidden tampering evidence
        tampered: true,
        originalAmount: originalAmount,
        discount: '90% (UNAUTHORIZED!)'
      }, ...prev]);

      // Show success message with tampered amount
      setMessage(`Payment of \u20b9${tamperedAmount.toLocaleString()} for ${selectedFee.category} processed successfully! Receipt: ${receiptNo}`);
      
      // Add tampering warning (subtle)
      setTimeout(() => {
        setError(`Security Alert: Request modification detected. Original amount \u20b9${originalAmount.toLocaleString()} was changed to \u20b9${tamperedAmount.toLocaleString()}`);
      }, 1000);
      
      setPaymentStage('success');
      setShowQR(false);
      setTimeout(() => {
        setShowPaymentModal(false);
        setSelectedFee(null);
        setSelectedAmount(null);
      }, 4000); // Keep modal open longer to show tampering alert
      setLoading(false);
    }, 3000); // 3 second "processing" for realism
  };

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const handleDownloadReceipt = (payment) => {
    setShowReceipt(payment);
  };

  return (
    <div className="ctop-app">
      <style>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>
      <CtopHeader />
      <div className="ctop-main-container">
        <CtopSidebar />
        <div className="ctop-content-area">
          <div className="ctop-page-title">
            <h2>Fee Payment</h2>
            <p style={{ color: '#757575', fontSize: '0.85rem' }}>
              View fee details, make payments, and download receipts
            </p>
          </div>

          {message && <div className="ctop-alert success">{message}</div>}
          {error && <div className="ctop-alert error">{error}</div>}

          
          {/* Fee Summary */}
          <div className="ctop-stats-grid" style={{ marginBottom: '1.5rem' }}>
            <div className="ctop-stat-card">
              <div className="ctop-stat-label">Total Paid</div>
              <div className="ctop-stat-value" style={{ color: '#2e7d32', fontSize: '1.5rem' }}>₹{totalPaid.toLocaleString()}</div>
            </div>
            <div className="ctop-stat-card">
              <div className="ctop-stat-label">Pending Amount</div>
              <div className="ctop-stat-value" style={{ color: '#f44336', fontSize: '1.5rem' }}>₹{totalPending.toLocaleString()}</div>
            </div>
            <div className="ctop-stat-card">
              <div className="ctop-stat-label">Pending Items</div>
              <div className="ctop-stat-value">{pendingFees.length}</div>
            </div>
            <div className="ctop-stat-card">
              <div className="ctop-stat-label">Transactions</div>
              <div className="ctop-stat-value">{paymentHistory.length}</div>
            </div>
          </div>

          {/* Pending Fees */}
          {pendingFees.length > 0 && (
            <div className="ctop-card" style={{ marginBottom: '1.5rem' }}>
              <div className="ctop-section-header">
                <h3>Pending Fees</h3>
              </div>
              <div className="ctop-table-container">
                <table className="ctop-course-table">
                  <thead>
                    <tr>
                      <th>Category</th>
                      <th>Semester</th>
                      <th>Due Date</th>
                      <th>Amount</th>
                      <th>Status</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pendingFees.map((fee, index) => (
                      <tr key={fee.id} className={index % 2 === 0 ? 'even-row' : 'odd-row'}>
                        <td className="course-name">{fee.category}</td>
                        <td>{fee.semester}</td>
                        <td>{fee.dueDate}</td>
                        <td style={{ fontWeight: 'bold' }}>₹{fee.amount.toLocaleString()}</td>
                        <td>
                          <span style={{ background: '#fff3e0', color: '#e65100', padding: '0.2rem 0.6rem', borderRadius: '12px', fontSize: '0.75rem', fontWeight: 'bold' }}>
                            Pending
                          </span>
                        </td>
                        <td>
                          <button className="ctop-action-btn primary" onClick={() => handlePayFee(fee)} style={{ fontSize: '0.8rem' }}>
                            Pay Now
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Payment Modal */}
          {showPaymentModal && (
            <div style={{
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              background: 'rgba(0,0,0,0.7)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              zIndex: 9999
            }}>
              <div style={{
                background: '#4a5078',
                color: 'white',
                borderRadius: '6px',
                padding: '0',
                maxWidth: '800px',
                width: '90%',
                maxHeight: '90vh',
                overflow: 'auto',
                boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
                position: 'relative'
              }}>
                {/* Close Button */}
                <button
                  onClick={() => {
                    setShowPaymentModal(false);
                    setShowQR(false);
                    setPaymentStage('select');
                    setSelectedFee(null);
                    setSelectedAmount(null);
                  }}
                  style={{
                    position: 'absolute',
                    top: '1rem',
                    right: '1rem',
                    background: 'rgba(255,255,255,0.2)',
                    border: 'none',
                    color: 'white',
                    width: '40px',
                    height: '40px',
                    borderRadius: '50%',
                    fontSize: '1.5rem',
                    cursor: 'pointer',
                    zIndex: 10
                  }}
                >
                  ×
                </button>

                {/* Modal Header */}
                <div style={{ 
                  padding: '2rem 2rem 1rem 2rem', 
                  borderBottom: '1px solid rgba(255,255,255,0.2)',
                  textAlign: 'center'
                }}>
                  <h3 style={{ color: 'white', margin: '0 0 0.5rem 0' }}>CTOP Secure Payment Gateway</h3>
                  <p style={{ color: 'rgba(255,255,255,0.9)', fontSize: '0.9rem', margin: 0 }}>
                    Powered by FakePay™ - "We take your money seriously... sometimes!"
                  </p>
                </div>
              
              {paymentStage === 'qr' && (
                <div className="ctop-card-body" style={{ textAlign: 'center' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem', alignItems: 'center' }}>
                    {/* Left Side - QR Code */}
                    <div style={{ background: 'white', padding: '1.5rem', borderRadius: '4px', boxShadow: '0 1px 4px rgba(0,0,0,0.1)' }}>
                      <div style={{ marginBottom: '1rem', color: '#333' }}>
                        <h4 style={{ color: '#4a5078', marginBottom: '0.5rem' }}>Scan to Pay</h4>
                        <p style={{ fontSize: '0.9rem', color: '#666' }}>QR Code expires in: <span style={{ color: '#f44336', fontWeight: 'bold' }}>{formatTime(countdown)}</span></p>
                      </div>
                      
                      {/* PLACE YOUR QR CODE IMAGE HERE */}
                      <div style={{ 
                        width: '200px', 
                        height: '200px', 
                        margin: '0 auto',
                        background: '#f5f5f5',
                        border: '2px solid #4a5078',
                        borderRadius: '4px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        position: 'relative'
                      }}>
                        {/* Replace this div with your actual QR image */}
                        <img 
                          src="/upi-qr-code.png" 
                          alt="UPI QR Code" 
                          style={{ 
                            width: '180px', 
                            height: '180px',
                            borderRadius: '7px'
                          }}
                          onError={(e) => {
                            e.target.style.display = 'none';
                            e.target.nextSibling.style.display = 'flex';
                          }}
                        />
                        <div style={{ 
                          display: 'none', 
                          flexDirection: 'column', 
                          alignItems: 'center', 
                          color: '#999',
                          fontSize: '0.8rem'
                        }}>
                          <div style={{ fontSize: '3rem', marginBottom: '0.5rem' }}>QR</div>
                          <div>QR Code Image</div>
                          <div style={{ fontSize: '0.7rem', marginTop: '0.5rem' }}>Place your QR image at:<br/>/public/upi-qr-code.png</div>
                        </div>
                      </div>
                      
                      <div style={{ marginTop: '1rem', color: '#333' }}>
                        <p style={{ fontSize: '0.8rem', color: '#666', margin: '0.5rem 0' }}>UPI ID: <strong style={{ color: '#4a5078' }}>{upiId}</strong></p>
                        <button 
                          onClick={() => navigator.clipboard.writeText(upiId)}
                          style={{ 
                            background: '#4a5078', 
                            color: 'white', 
                            border: 'none', 
                            padding: '0.3rem 0.8rem', 
                            borderRadius: '3px', 
                            fontSize: '0.8rem',
                            cursor: 'pointer'
                          }}
                        >
                        Copy UPI ID
                        </button>
                      </div>
                    </div>
                    
                    {/* Right Side - Payment Details */}
                    <div style={{ color: 'white' }}>
                      <h4 style={{ marginBottom: '1.5rem', fontSize: '1.3rem' }}>Payment Details</h4>
                      
                      <div style={{ background: 'rgba(255,255,255,0.08)', padding: '1.25rem', borderRadius: '4px', marginBottom: '1.5rem' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.8rem' }}>
                          <span>Fee Category:</span>
                          <strong>{selectedFee.category}</strong>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.8rem' }}>
                          <span>Semester:</span>
                          <strong>{selectedFee.semester}</strong>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.8rem' }}>
                          <span>Due Date:</span>
                          <strong>{selectedFee.dueDate}</strong>
                        </div>
                        <div style={{ 
                          display: 'flex', 
                          justifyContent: 'space-between', 
                          paddingTop: '1rem',
                          borderTop: '2px solid rgba(255,255,255,0.3)',
                          fontSize: '1.2rem'
                        }}>
                          <span>Total Amount:</span>
                          <strong style={{ fontSize: '1.5rem', color: '#ffeb3b' }}>₹{selectedFee.amount.toLocaleString()}</strong>
                        </div>
                      </div>
                      
                      <div style={{ background: 'rgba(255,255,255,0.08)', padding: '1rem', borderRadius: '4px', fontSize: '0.9rem' }}>
                        <p style={{ margin: '0 0 0.5rem 0' }}>Secure Payment Gateway</p>
                        <p style={{ margin: '0 0 0.5rem 0' }}>256-bit encryption (probably)</p>
                        <p style={{ margin: '0 0 0.5rem 0' }}>Bank-level security (we think)</p>
                        <p style={{ margin: '0', fontStyle: 'italic', opacity: 0.8 }}>*"Your money is safe with us... until it's not!"*</p>
                      </div>
                      
                      <button 
                        onClick={processPayment}
                        style={{
                          background: '#4caf50',
                          color: 'white',
                          border: 'none',
                          padding: '0.75rem 1.5rem',
                          borderRadius: '4px',
                          fontSize: '1rem',
                          fontWeight: 'bold',
                          cursor: 'pointer',
                          marginTop: '1.5rem',
                          width: '100%'
                        }}
                      >
                        I've Paid - Confirm Transaction
                      </button>
                    </div>
                  </div>
                </div>
              )}
              
              {paymentStage === 'processing' && (
                <div className="ctop-card-body" style={{ textAlign: 'center', padding: '3rem' }}>
                  <div style={{ fontSize: '4rem', marginBottom: '1rem' }}>...</div>
                  <h3 style={{ color: 'white', marginBottom: '1rem' }}>Processing Payment...</h3>
                  <p style={{ color: 'rgba(255,255,255,0.9)' }}>Please wait while our middleware "optimizes" your payment...</p>
                  
                  {/* Middleware Attack Visualization */}
                  <div style={{ 
                    background: 'rgba(255,255,255,0.08)', 
                    padding: '1.25rem', 
                    borderRadius: '4px', 
                    margin: '1.5rem 0',
                    fontSize: '0.9rem'
                  }}>
                    <div style={{ marginBottom: '1rem', opacity: 0.8 }}>REQUEST INTERCEPTION IN PROGRESS...</div>
                    <div style={{ 
                      display: 'grid', 
                      gridTemplateColumns: '1fr auto 1fr', 
                      alignItems: 'center', 
                      gap: '1rem',
                      textAlign: 'left'
                    }}>
                      <div style={{ 
                        background: 'rgba(76,175,80,0.2)', 
                        padding: '0.8rem', 
                        borderRadius: '8px',
                        border: '1px solid rgba(76,175,80,0.5)'
                      }}>
                        <div style={{ fontSize: '0.8rem', opacity: 0.8, marginBottom: '0.3rem' }}>ORIGINAL REQUEST:</div>
                        <div style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                          Amount: ₹{selectedFee?.amount.toLocaleString()}
                        </div>
                      </div>
                      <div style={{ fontSize: '1.5rem' }}>&rarr;</div>
                      <div style={{ 
                        background: 'rgba(255,152,0,0.2)', 
                        padding: '0.8rem', 
                        borderRadius: '8px',
                        border: '1px solid rgba(255,152,0,0.5)'
                      }}>
                        <div style={{ fontSize: '0.8rem', opacity: 0.8, marginBottom: '0.3rem' }}>MODIFIED REQUEST:</div>
                        <div style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                          Amount: ₹{Math.floor(selectedFee?.amount * 0.1).toLocaleString()}
                        </div>
                      </div>
                    </div>
                    <div style={{ 
                      marginTop: '1rem', 
                      padding: '0.5rem', 
                      background: 'rgba(244,67,54,0.2)', 
                      borderRadius: '5px',
                      fontSize: '0.8rem',
                      color: '#ffcdd2'
                    }}>
                      Middleware tampering detected: 90% discount applied!
                    </div>
                  </div>
                  
                  <div style={{ 
                    width: '60px', 
                    height: '60px', 
                    border: '4px solid rgba(255,255,255,0.3)', 
                    borderTop: '4px solid white', 
                    borderRadius: '50%', 
                    margin: '2rem auto',
                    animation: 'spin 1s linear infinite'
                  }}></div>
                  <p style={{ fontSize: '0.9rem', opacity: 0.8, fontStyle: 'italic' }}>"Our middleware works in mysterious ways..."</p>
                </div>
              )}
              
              {paymentStage === 'success' && (
                <div className="ctop-card-body" style={{ textAlign: 'center', padding: '3rem' }}>
                  <div style={{ fontSize: '4rem', marginBottom: '1rem' }}>OK</div>
                  <h3 style={{ color: 'white', marginBottom: '1rem' }}>Payment Successful!</h3>
                  <p style={{ color: 'rgba(255,255,255,0.9)', marginBottom: '2rem' }}>Your payment has been processed successfully. Receipt has been generated.</p>
                  <button 
                    onClick={() => setPaymentStage('select')}
                    style={{
                      background: 'white',
                      color: '#4a5078',
                      border: 'none',
                      padding: '0.7rem 1.5rem',
                      borderRadius: '4px',
                      fontSize: '1rem',
                      fontWeight: 'bold',
                      cursor: 'pointer'
                    }}
                  >
                    View More Payments
                  </button>
                </div>
              )}
              </div>
            </div>
          )}

          {/* Payment History */}
          <div className="ctop-card" style={{ marginBottom: '1.5rem' }}>
            <div className="ctop-section-header">
              <h3>Payment History</h3>
            </div>
            <div className="ctop-table-container">
              {paymentHistory.length === 0 ? (
                <div style={{ padding: '2rem', textAlign: 'center', color: '#757575' }}>No payment history</div>
              ) : (
                <table className="ctop-course-table">
                  <thead>
                    <tr>
                      <th>Transaction ID</th>
                      <th>Date</th>
                      <th>Category</th>
                      <th>Method</th>
                      <th>Amount</th>
                      <th>Status</th>
                      <th>Receipt</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paymentHistory.map((payment, index) => (
                      <tr key={payment.id} className={index % 2 === 0 ? 'even-row' : 'odd-row'}>
                        <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{payment.id}</td>
                        <td>{payment.date}</td>
                        <td className="course-name">{payment.category}</td>
                        <td>{payment.method}</td>
                        <td style={{ fontWeight: 'bold', color: payment.tampered ? '#f44336' : 'inherit' }}>
                          ₹{payment.amount.toLocaleString()}
                          {payment.tampered && (
                            <span style={{ 
                              display: 'block', 
                              fontSize: '0.7rem', 
                              color: '#ff9800',
                              fontWeight: 'normal'
                            }}>
                              Tampered!
                            </span>
                          )}
                        </td>
                        <td>
                          <span style={{ 
                            background: payment.tampered ? '#fff3e0' : '#e8f5e9', 
                            color: payment.tampered ? '#e65100' : '#2e7d32', 
                            padding: '0.2rem 0.6rem', 
                            borderRadius: '12px', 
                            fontSize: '0.75rem', 
                            fontWeight: 'bold'
                          }}>
                            {payment.status}
                          </span>
                        </td>
                        <td>
                          <button className="ctop-table-btn edit" onClick={() => handleDownloadReceipt(payment)}>
                            View
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          {/* Receipt Modal */}
          {showReceipt && (
            <div className="ctop-card" style={{ marginBottom: '1.5rem', border: '2px solid #1976d2' }}>
              <div className="ctop-section-header" style={{ background: '#e3f2fd' }}>
                <h3>Payment Receipt — {showReceipt.receiptNo}</h3>
                <button className="ctop-action-btn secondary" onClick={() => setShowReceipt(null)}>Close</button>
              </div>
              <div className="ctop-card-body">
                <div style={{ textAlign: 'center', marginBottom: '1.5rem' }}>
                  <h2 style={{ color: '#1976d2', marginBottom: '0.25rem' }}>CTOP University</h2>
                  <p style={{ color: '#757575', fontSize: '0.85rem' }}>Cyscom Institute of Technology</p>
                </div>
                <div className="ctop-profile-info">
                  <div className="ctop-profile-row">
                    <span className="ctop-profile-label">Receipt No.</span>
                    <span className="ctop-profile-value">{showReceipt.receiptNo}</span>
                  </div>
                  <div className="ctop-profile-row">
                    <span className="ctop-profile-label">Transaction ID</span>
                    <span className="ctop-profile-value">{showReceipt.id}</span>
                  </div>
                  <div className="ctop-profile-row">
                    <span className="ctop-profile-label">Student Name</span>
                    <span className="ctop-profile-value">{user?.username || 'Student'}</span>
                  </div>
                  <div className="ctop-profile-row">
                    <span className="ctop-profile-label">Date</span>
                    <span className="ctop-profile-value">{showReceipt.date}</span>
                  </div>
                  <div className="ctop-profile-row">
                    <span className="ctop-profile-label">Category</span>
                    <span className="ctop-profile-value">{showReceipt.category}</span>
                  </div>
                  <div className="ctop-profile-row">
                    <span className="ctop-profile-label">Payment Method</span>
                    <span className="ctop-profile-value">{showReceipt.method}</span>
                  </div>
                  <div className="ctop-profile-row">
                    <span className="ctop-profile-label">Amount</span>
                    <span className="ctop-profile-value" style={{ fontWeight: 'bold', fontSize: '1.2rem', color: '#2e7d32' }}>₹{showReceipt.amount.toLocaleString()}</span>
                  </div>
                  <div className="ctop-profile-row">
                    <span className="ctop-profile-label">Status</span>
                    <span className="ctop-profile-value" style={{ color: '#2e7d32', fontWeight: 'bold' }}>{showReceipt.status}</span>
                  </div>
                </div>
                <div style={{ textAlign: 'center', marginTop: '1.5rem', paddingTop: '1rem', borderTop: '1px dashed #ccc' }}>
                  <p style={{ color: '#757575', fontSize: '0.8rem' }}>This is a computer-generated receipt and does not require a signature.</p>
                </div>
              </div>
            </div>
          )}

          {/* Fee Structure */}
          <div className="ctop-card">
            <div className="ctop-section-header">
              <h3>Complete Fee Structure</h3>
            </div>
            <div className="ctop-table-container">
              <table className="ctop-course-table">
                <thead>
                  <tr>
                    <th>Sl. No.</th>
                    <th>Category</th>
                    <th>Semester</th>
                    <th>Due Date</th>
                    <th>Amount</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {feeStructure.map((fee, index) => (
                    <tr key={fee.id} className={index % 2 === 0 ? 'even-row' : 'odd-row'}>
                      <td>{index + 1}</td>
                      <td className="course-name">{fee.category}</td>
                      <td>{fee.semester}</td>
                      <td>{fee.dueDate}</td>
                      <td style={{ fontWeight: 'bold' }}>₹{fee.amount.toLocaleString()}</td>
                      <td>
                        <span style={{
                          background: fee.status === 'paid' ? '#e8f5e9' : '#fff3e0',
                          color: fee.status === 'paid' ? '#2e7d32' : '#e65100',
                          padding: '0.2rem 0.6rem',
                          borderRadius: '12px',
                          fontSize: '0.75rem',
                          fontWeight: 'bold'
                        }}>
                          {fee.status === 'paid' ? 'Paid' : 'Pending'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default CtopFeePayment;
