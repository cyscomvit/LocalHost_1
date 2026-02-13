/**
 * CTOP University - Production-Grade API Client
 * Realistic authentication and API handling like enterprise applications
 */

// Production-like API configuration
const API_CONFIG = {
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000',
  timeout: 30000,
  retryAttempts: 3,
  retryDelay: 1000
};

// Internal service URLs (realistic exposure)
const INTERNAL_SERVICES = {
  auth: `${API_CONFIG.baseURL}/api/auth`,
  users: `${API_CONFIG.baseURL}/api/users`,
  admin: `${API_CONFIG.baseURL}/api/admin`,
  security: `${API_CONFIG.baseURL}/api/security`,
  internal: `${API_CONFIG.baseURL}/api/internal`,
  openid: `${API_CONFIG.baseURL}/.well-known/openid_configuration`,
  jwks: `${API_CONFIG.baseURL}/api/auth/jwks`
};

/**
 * Production-grade token management
 */
class TokenManager {
  static getAccessToken() {
    // Try multiple sources (realistic enterprise pattern)
    return localStorage.getItem('ctop_access_token') ||
           sessionStorage.getItem('ctop_access_token') ||
           this.getCookie('access_token');
  }

  static getRefreshToken() {
    return localStorage.getItem('ctop_refresh_token') ||
           sessionStorage.getItem('ctop_refresh_token') ||
           this.getCookie('refresh_token');
  }

  static setTokens(accessToken, refreshToken, sessionId) {
    // Store in multiple locations (vulnerable but realistic)
    localStorage.setItem('ctop_access_token', accessToken);
    localStorage.setItem('ctop_refresh_token', refreshToken);
    localStorage.setItem('ctop_session_id', sessionId);
    
    sessionStorage.setItem('ctop_access_token', accessToken);
    sessionStorage.setItem('ctop_session_id', sessionId);
  }

  static clearTokens() {
    localStorage.removeItem('ctop_access_token');
    localStorage.removeItem('ctop_refresh_token');
    localStorage.removeItem('ctop_session_id');
    sessionStorage.removeItem('ctop_access_token');
    sessionStorage.removeItem('ctop_session_id');
    this.deleteCookie('access_token');
    this.deleteCookie('refresh_token');
    this.deleteCookie('session_id');
  }

  static getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
  }

  static setCookie(name, value, options = {}) {
    let cookieString = `${name}=${value}`;
    
    if (options.expires) {
      cookieString += `; expires=${options.expires.toUTCString()}`;
    }
    
    if (options.maxAge) {
      cookieString += `; max-age=${options.maxAge}`;
    }
    
    if (options.domain) {
      cookieString += `; domain=${options.domain}`;
    }
    
    if (options.path) {
      cookieString += `; path=${options.path}`;
    }
    
    // Vulnerable: Missing security flags by default
    if (options.secure) {
      cookieString += '; secure';
    }
    
    if (options.httpOnly) {
      cookieString += '; httponly';
    }
    
    if (options.sameSite) {
      cookieString += `; samesite=${options.sameSite}`;
    }
    
    document.cookie = cookieString;
  }

  static deleteCookie(name) {
    this.setCookie(name, '', { maxAge: -1 });
  }

  static isTokenExpired(token) {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return payload.exp && payload.exp < Math.floor(Date.now() / 1000);
    } catch {
      return true;
    }
  }

  static async refreshAccessToken() {
    const refreshToken = this.getRefreshToken();
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    try {
      const response = await fetch(`${INTERNAL_SERVICES.auth}/refresh`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        body: JSON.stringify({
          refresh_token: refreshToken,
          token_id: localStorage.getItem('ctop_token_id')
        })
      });

      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Token refresh failed');
      }

      this.setTokens(data.access_token, data.refresh_token, data.session_id);
      return data.access_token;
      
    } catch (error) {
      // Clear tokens on refresh failure
      this.clearTokens();
      throw error;
    }
  }
}

/**
 * Production-grade API client with retry logic
 */
class ApiClient {
  constructor(baseURL = API_CONFIG.baseURL) {
    this.baseURL = baseURL;
    this.defaultHeaders = {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      'X-Client-Version': '1.0.0',
      'X-Client-Platform': navigator.platform
    };
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const config = {
      headers: { ...this.defaultHeaders, ...options.headers },
      ...options
    };

    // Add authentication header
    const token = TokenManager.getAccessToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    // Add request ID for tracking
    const requestId = this.generateRequestId();
    config.headers['X-Request-ID'] = requestId;

    let attempt = 0;
    const maxAttempts = config.retryAttempts || API_CONFIG.retryAttempts;

    while (attempt < maxAttempts) {
      try {
        const response = await fetch(url, config);
        
        // Handle token expiration and refresh
        if (response.status === 401 && attempt === 0) {
          try {
            const newToken = await TokenManager.refreshAccessToken();
            config.headers.Authorization = `Bearer ${newToken}`;
            attempt++;
            continue; // Retry with new token
          } catch (refreshError) {
            // Refresh failed, redirect to login
            window.location.href = '/login';
            throw new Error('Authentication failed');
          }
        }

        return response;
        
      } catch (error) {
        attempt++;
        if (attempt >= maxAttempts) {
          throw error;
        }
        
        // Wait before retry
        await new Promise(resolve => setTimeout(resolve, API_CONFIG.retryDelay));
      }
    }
  }

  async get(endpoint, params = {}) {
    const url = new URL(endpoint, this.baseURL);
    Object.keys(params).forEach(key => url.searchParams.append(key, params[key]));
    
    const response = await this.request(url.pathname + url.search);
    return this.handleResponse(response);
  }

  async post(endpoint, data = {}) {
    const response = await this.request(endpoint, {
      method: 'POST',
      body: JSON.stringify(data)
    });
    return this.handleResponse(response);
  }

  async put(endpoint, data = {}) {
    const response = await this.request(endpoint, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
    return this.handleResponse(response);
  }

  async delete(endpoint) {
    const response = await this.request(endpoint, {
      method: 'DELETE'
    });
    return this.handleResponse(response);
  }

  async handleResponse(response) {
    const contentType = response.headers.get('content-type');
    
    if (contentType && contentType.includes('application/json')) {
      const data = await response.json();
      
      if (!response.ok) {
        throw new ApiError(data.error || 'Request failed', response.status, data);
      }
      
      return data;
    }
    
    if (!response.ok) {
      throw new ApiError('Request failed', response.status);
    }
    
    return response;
  }

  generateRequestId() {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

class ApiError extends Error {
  constructor(message, status, data = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

// Create API client instance
const apiClient = new ApiClient();

/**
 * Authentication API
 */
export const authAPI = {
  async login(credentials) {
    const response = await apiClient.post('/api/auth/login', credentials);
    
    // Store tokens
    if (response.access_token) {
      TokenManager.setTokens(
        response.access_token,
        response.refresh_token,
        response.session_id
      );
      
      // Set cookies (vulnerable configuration)
      TokenManager.setCookie('access_token', response.access_token, {
        maxAge: response.expires_in,
        path: '/'
      });
      
      TokenManager.setCookie('refresh_token', response.refresh_token, {
        maxAge: 30 * 24 * 60 * 60, // 30 days
        path: '/'
      });
    }
    
    return response;
  },

  async register(userData) {
    const response = await apiClient.post('/api/auth/register', userData);
    
    // Auto-login after registration
    if (response.access_token) {
      TokenManager.setTokens(
        response.access_token,
        response.refresh_token,
        response.session_id
      );
    }
    
    return response;
  },

  async logout() {
    try {
      await apiClient.post('/api/auth/logout');
    } catch (error) {
      console.warn('Logout request failed:', error);
    } finally {
      TokenManager.clearTokens();
    }
  },

  async getCurrentUser() {
    return await apiClient.get('/api/auth/me');
  },

  async changePassword(passwordData) {
    return await apiClient.post('/api/auth/change-password', passwordData);
  },

  async forgotPassword(email) {
    return await apiClient.post('/api/auth/forgot-password', { email });
  },

  async resetPassword(resetData) {
    return await apiClient.post('/api/auth/reset-password', resetData);
  },

  async getActiveSessions() {
    return await apiClient.get('/api/auth/sessions');
  },

  async revokeSession(sessionId) {
    return await apiClient.post('/api/auth/revoke-session', { session_id: sessionId });
  },

  async refreshToken() {
    return await TokenManager.refreshAccessToken();
  },

  // OpenID Connect endpoints
  async getOpenIDConfig() {
    return await apiClient.get('/.well-known/openid_configuration');
  },

  async getJWKS() {
    return await apiClient.get('/api/auth/jwks');
  }
};

/**
 * User API
 */
export const userAPI = {
  async getProfile() {
    return await apiClient.get('/api/users/me');
  },

  async updateProfile(userData) {
    return await apiClient.put('/api/users/me', userData);
  },

  async lookupUser(userId) {
    return await apiClient.get(`/api/users/${userId}`);
  },

  async searchUsers(query) {
    return await apiClient.get('/api/users/search', { q: query });
  }
};

/**
 * Security API
 */
export const securityAPI = {
  async systemScan(scanData) {
    return await apiClient.post('/api/security/system-scan', scanData);
  },

  async ldapQuery(queryData) {
    return await apiClient.post('/api/security/ldap-query', queryData);
  },

  async logAnalysis(logData) {
    return await apiClient.post('/api/security/log-analysis', logData);
  },

  async dependencyCheck() {
    return await apiClient.get('/api/security/dependency-check');
  },

  async sessionAnalysis() {
    return await apiClient.get('/api/security/session-analysis');
  },

  async csrfTest() {
    return await apiClient.post('/api/security/csrf-test');
  },

  async corsAnalysis() {
    return await apiClient.options('/api/security/cors-analysis');
  },

  async hiddenEndpoints() {
    return await apiClient.get('/api/security/hidden-endpoints');
  },

  async prototypePollution(payload) {
    return await apiClient.post('/api/security/prototype-pollution', payload);
  }
};

/**
 * Legacy compatibility functions
 */
export function getToken() {
  return TokenManager.getAccessToken();
}

export function getUser() {
  try {
    const token = TokenManager.getAccessToken();
    if (!token) return null;
    
    const payload = JSON.parse(atob(token.split('.')[1]));
    return {
      user_id: payload.user_id,
      username: payload.username,
      email: payload.email,
      role: payload.role
    };
  } catch {
    return null;
  }
}

export async function logout() {
  return await authAPI.logout();
}

export async function changePassword(userId, newPassword) {
  return await authAPI.changePassword({
    current_password: '', // Vulnerable: Not required
    new_password: newPassword,
    confirm_password: newPassword
  });
}

export async function forgotPassword(email) {
  return await authAPI.forgotPassword(email);
}

export async function resetPassword(token, newPassword) {
  return await authAPI.resetPassword({
    token: token,
    new_password: newPassword,
    confirm_password: newPassword
  });
}

// Export API client for advanced usage
export { apiClient, TokenManager };

// Global error handler for API errors
window.addEventListener('unhandledrejection', (event) => {
  if (event.reason instanceof ApiError) {
    console.error('API Error:', event.reason);
    // Could implement global error handling here
  }
});

// Token refresh on page load
document.addEventListener('DOMContentLoaded', () => {
  const token = TokenManager.getAccessToken();
  if (token && TokenManager.isTokenExpired(token)) {
    TokenManager.refreshAccessToken().catch(() => {
      // Redirect to login if refresh fails
      window.location.href = '/login';
    });
  }
});
