// zt-immune-system/dashboard/frontend/src/services/authService.js

const API_URL = 'http://localhost:8001'; // Backend API URL

/**
 * Logs in a user.
 * @param {string} username
 * @param {string} password
 * @returns {Promise<object>} - { success: boolean, token?: string, error?: string, user?: object }
 */
async function login(username, password) {
  try {
    const formData = new URLSearchParams();
    formData.append('username', username);
    formData.append('password', password);

    const response = await fetch(`${API_URL}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: formData.toString(),
    });

    if (response.ok) {
      const data = await response.json();
      if (data.access_token) {
        localStorage.setItem('accessToken', data.access_token);

        // Basic (unsafe) JWT decoding for client-side display purposes (e.g., username).
        // This is NOT for security decisions. Verification happens on the backend.
        let user = null;
        try {
          const payloadBase64 = data.access_token.split('.')[1];
          const decodedPayload = JSON.parse(atob(payloadBase64));
          user = {
            username: decodedPayload.sub, // 'sub' usually holds the username
            roles: decodedPayload.scopes || [] // 'scopes' usually holds the roles
          };
        } catch (e) {
          console.error("Error decoding token for display:", e);
          // Proceed without decoded user info if decoding fails
        }

        return { success: true, token: data.access_token, user };
      } else {
        return { success: false, error: 'Login failed: No access token received.' };
      }
    } else {
      // Try to parse error from backend if available
      let errorMessage = `Login failed with status: ${response.status}`;
      try {
        const errorData = await response.json();
        errorMessage = errorData.detail || errorMessage;
      } catch (e) {
        // Ignore if error response is not JSON
      }
      return { success: false, error: errorMessage };
    }
  } catch (error) {
    console.error('Login API call failed:', error);
    return { success: false, error: 'Login request failed. Check network or server.' };
  }
}

/**
 * Logs out the current user by removing the token from localStorage.
 */
function logout() {
  localStorage.removeItem('accessToken');
  // Potentially also clear any user-related state in a global store if not using AuthContext for everything.
}

/**
 * Retrieves the stored access token.
 * @returns {string|null} The access token or null if not found.
 */
function getToken() {
  return localStorage.getItem('accessToken');
}

/**
 * Constructs the Authorization header for API requests.
 * @returns {object|null} An object with the Authorization header or null if no token.
 */
function getAuthHeader() {
  const token = getToken();
  if (token) {
    return { 'Authorization': `Bearer ${token}` };
  }
  return null; // Or return {} if preferred for merging headers
}

export const authService = {
  login,
  logout,
  getToken,
  getAuthHeader,
};
