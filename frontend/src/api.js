/**
 * TaskFlowr - API Client
 * INTENTIONALLY INSECURE: Multiple frontend security anti-patterns.
 */

// INTENTIONALLY INSECURE: API URL hardcoded and exposed in client JS
// TODO: Use environment variables, don't expose internal URLs
const API_BASE_URL = 'http://localhost:5000';

// INTENTIONALLY INSECURE: Internal API URLs exposed in frontend code
// TODO: Never expose internal service URLs in client-side code
const INTERNAL_URLS = {
  api: 'http://localhost:5000',
  admin: 'http://localhost:5000/api/admin',
  internal_health: 'http://localhost:5000/api/internal/health',
  debug: 'http://localhost:5000/api/auth/debug-token',
  secret_config: 'http://localhost:5000/api/admin/secret-config',
};

/**
 * Get the stored JWT token.
 * INTENTIONALLY INSECURE: Token stored in localStorage.
 * TODO: Use httpOnly cookies for token storage.
 */
function getToken() {
  // INTENTIONALLY INSECURE: localStorage is accessible to any JS on the page (XSS risk)
  // TODO: Use httpOnly, Secure, SameSite cookies
  return localStorage.getItem('taskflowr_token');
}

/**
 * Store the JWT token.
 * INTENTIONALLY INSECURE: Storing in localStorage.
 */
function setToken(token) {
  // INTENTIONALLY INSECURE: localStorage for auth tokens
  localStorage.setItem('taskflowr_token', token);
}

/**
 * Remove the stored token.
 * INTENTIONALLY INSECURE: Token may still be valid after removal.
 * TODO: Invalidate token server-side on logout.
 */
function removeToken() {
  localStorage.removeItem('taskflowr_token');
  // INTENTIONALLY INSECURE: Token is NOT invalidated server-side
  // Old token continues to work even after "logout"
}

/**
 * Get stored user data.
 * INTENTIONALLY INSECURE: User data including role stored client-side.
 */
/**
 * Decode JWT token (client-side)
 * INTENTIONALLY INSECURE: Client-side JWT decoding without signature verification
 * This enables JWT tampering attacks for educational purposes
 */
function decodeJWT(token) {
  try {
    // Split JWT into parts
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    // Decode the payload (second part)
    const payload = parts[1];
    const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(decoded);
  } catch (e) {
    console.error('Failed to decode JWT:', e);
    return null;
  }
}

function getUser() {
  // INTENTIONALLY INSECURE: Read user data from JWT token without verification
  // This allows JWT tampering attacks to work for educational purposes
  const token = getToken();
  
  if (token) {
    // Decode JWT and extract user data
    const payload = decodeJWT(token);
    if (payload) {
      console.log('[JWT DEBUG] Decoded token payload:', payload);
      // Return user data from JWT token
      return {
        id: payload.user_id || payload.id,
        user_id: payload.user_id || payload.id,
        username: payload.username || payload.sub,
        email: payload.email,
        full_name: payload.full_name,
        role: payload.role,
        is_admin: payload.role === 'admin' || payload.is_admin
      };
    }
  }
  
  // Fallback to localStorage if token doesn't exist or can't be decoded
  const userData = localStorage.getItem('taskflowr_user');
  return userData ? JSON.parse(userData) : null;
}

function setUser(user) {
  localStorage.setItem('taskflowr_user', JSON.stringify(user));
}

function removeUser() {
  localStorage.removeItem('taskflowr_user');
}

/**
 * Make an API request.
 * INTENTIONALLY INSECURE: No CSRF token, credentials included with wildcard CORS.
 */
async function apiRequest(endpoint, options = {}) {
  const token = getToken();

  const config = {
    headers: {
      'Content-Type': 'application/json',
      ...(token && { 'Authorization': `Bearer ${token}` }),
      ...options.headers,
    },
    // INTENTIONALLY INSECURE: Including credentials with wildcard CORS
    credentials: 'include',
    ...options,
  };

  if (options.body && typeof options.body === 'object') {
    config.body = JSON.stringify(options.body);
  }

  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, config);
    const data = await response.json();

    if (!response.ok) {
      throw { status: response.status, ...data };
    }

    return data;
  } catch (error) {
    // INTENTIONALLY INSECURE: Logging full error details to console
    // TODO: Don't log sensitive error details in production
    console.error('[API Error]', endpoint, error);
    throw error;
  }
}

// ============================================================
// Auth API
// ============================================================

export async function login(username, password) {
  const data = await apiRequest('/api/auth/login', {
    method: 'POST',
    body: { username, password },
  });
  // Backend returns access_token, not token
  if (data.access_token && data.user) {
    setToken(data.access_token);
    setUser(data.user);
    // INTENTIONALLY INSECURE: Set access_token as a cookie too (for CSRF vulnerability)
    document.cookie = `access_token=${data.access_token}; path=/;`;
  } else if (data.token) {
    // Fallback for old format
    setToken(data.token);
    setUser(data.user);
    document.cookie = `access_token=${data.token}; path=/;`;
  }
  return data;
}

export async function loginMySQL(username, password) {
  const data = await apiRequest('/api/auth/login/mysql', {
    method: 'POST',
    body: { username, password },
  });
  if (data.access_token && data.user) {
    setToken(data.access_token);
    setUser(data.user);
    // INTENTIONALLY INSECURE: Set access_token as a cookie too (for CSRF vulnerability)
    // httponly is false so JS can set/read it — this enables CSRF attacks
    // No SameSite restriction so it's sent with cross-origin requests from localhost
    document.cookie = `access_token=${data.access_token}; path=/;`;
  }
  return data;
}

export async function register(username, email, password, role = 'user') {
  // INTENTIONALLY INSECURE: Role sent from frontend
  // TODO: Never send role from client, always set server-side
  return apiRequest('/api/auth/register', {
    method: 'POST',
    body: { username, email, password, role },
  });
}

export async function logout() {
  try {
    await apiRequest('/api/auth/logout', { method: 'POST' });
  } catch (e) {
    // Ignore logout errors
  }
  removeToken();
  removeUser();
  // INTENTIONALLY INSECURE: Token still valid after logout
}

export async function getCurrentUser() {
  return apiRequest('/api/auth/me');
}

export async function forgotPassword(email) {
  return apiRequest('/api/auth/forgot-password', {
    method: 'POST',
    body: { email },
  });
}

export async function resetPassword(token, newPassword) {
  return apiRequest('/api/auth/reset-password', {
    method: 'POST',
    body: { token, new_password: newPassword },
  });
}

// ============================================================
// Tasks API
// ============================================================

export async function getTasks(search = '', status = '') {
  let query = '';
  if (search || status) {
    const params = new URLSearchParams();
    if (search) params.append('search', search);
    if (status) params.append('status', status);
    query = `?${params.toString()}`;
  }
  return apiRequest(`/api/tasks${query}`);
}

export async function getTask(id) {
  return apiRequest(`/api/tasks/${id}`);
}

export async function createTask(taskData) {
  return apiRequest('/api/tasks', {
    method: 'POST',
    body: taskData,
  });
}

export async function updateTask(id, taskData) {
  return apiRequest(`/api/tasks/${id}`, {
    method: 'PUT',
    body: taskData,
  });
}

export async function deleteTask(id) {
  return apiRequest(`/api/tasks/${id}`, { method: 'DELETE' });
}

// ============================================================
// Users API
// ============================================================

export async function getUsers() {
  return apiRequest('/api/users');
}

export async function getUser_api(id) {
  return apiRequest(`/api/users/${id}`);
}

export async function getMySQLProfile(id) {
  return apiRequest(`/api/users/profile/mysql/${id}`);
}

export async function updateMySQLProfile(id, userData) {
  return apiRequest(`/api/users/profile/mysql/${id}`, {
    method: 'PUT',
    body: userData,
  });
}

export async function updateUser(id, userData) {
  return apiRequest(`/api/users/${id}`, {
    method: 'PUT',
    body: userData,
  });
}

export async function changePassword(userId, newPassword) {
  return apiRequest(`/api/users/${userId}/change-password`, {
    method: 'POST',
    body: { new_password: newPassword },
  });
}

export async function searchUsers(query) {
  return apiRequest(`/api/users/search?q=${encodeURIComponent(query)}`);
}

// ============================================================
// Admin API
// ============================================================

export async function getAdminStats() {
  return apiRequest('/api/admin/stats');
}

export async function getAdminUsers() {
  return apiRequest('/api/admin/users');
}

export async function changeUserRole(userId, role) {
  return apiRequest(`/api/admin/users/${userId}/role`, {
    method: 'PUT',
    body: { role },
  });
}

export async function runDiagnostic(command) {
  return apiRequest('/api/admin/run-diagnostic', {
    method: 'POST',
    body: { command },
  });
}

export async function rawQuery(query) {
  return apiRequest('/api/admin/database/query', {
    method: 'POST',
    body: { query },
  });
}

// ============================================================
// Reports API
// ============================================================

export async function fetchReport(url) {
  return apiRequest('/api/fetch-report', {
    method: 'POST',
    body: { url },
  });
}

// ============================================================
// Reimbursements API
// ============================================================

export async function getReimbursements() {
  return apiRequest('/api/reimbursements');
}

export async function createReimbursement(amount, description) {
  return apiRequest('/api/reimbursements', {
    method: 'POST',
    body: { amount, description },
  });
}

export async function approveReimbursement(id) {
  return apiRequest(`/api/reimbursements/${id}/approve`, { method: 'POST' });
}

// ============================================================
// Messages API
// ============================================================

export async function getMessages(userId) {
  // INTENTIONALLY VULNERABLE: IDOR via user_id parameter
  return apiRequest(`/api/messages?user_id=${userId}`);
}

export async function getMessage(messageId) {
  // INTENTIONALLY VULNERABLE: IDOR via message_id
  return apiRequest(`/api/messages/${messageId}`);
}

// ============================================================
// Exports
// ============================================================

export {
  getToken,
  setToken,
  removeToken,
  getUser,
  setUser,
  removeUser,
  API_BASE_URL,
  INTERNAL_URLS,
};
