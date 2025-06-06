// zt-immune-system/dashboard/frontend/src/services/apiService.js
import { authService } from './authService'; // To use getToken or getAuthHeader

const API_BASE_URL = 'http://localhost:8001/api';

/**
 * Helper function to make authenticated API requests.
 * @param {string} url Full URL to fetch from.
 * @param {object} options Fetch options (method, headers, body, etc.).
 * @returns {Promise<any>} JSON response data.
 * @throws {Error} If the request fails or returns a non-2xx status.
 */
async function fetchWithAuth(url, options = {}) {
  const token = authService.getToken();
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers,
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(url, { ...options, headers });

  if (!response.ok) {
    let errorData;
    try {
      errorData = await response.json();
    } catch (e) {
      // Response was not JSON
      errorData = { detail: response.statusText || 'Unknown server error' };
    }
    const error = new Error(errorData.detail || `HTTP error! status: ${response.status}`);
    error.status = response.status;
    error.data = errorData; // Attach more detailed error info if available
    throw error;
  }

  // Handle cases where response might be empty (e.g., 204 No Content)
  const contentType = response.headers.get("content-type");
  if (contentType && contentType.indexOf("application/json") !== -1) {
    return response.json();
  } else {
    return null; // Or response.text() if text is expected
  }
}

/**
 * Fetches the system status.
 * @returns {Promise<object>} System status data.
 */
async function getStatus() {
  return fetchWithAuth(`${API_BASE_URL}/status`);
}

/**
 * Fetches recent alerts.
 * @param {number} limit Optional limit for number of alerts.
 * @returns {Promise<Array<object>>} List of alerts.
 */
async function getAlerts(limit = 20) {
  return fetchWithAuth(`${API_BASE_URL}/alerts?limit=${limit}`);
}

/**
 * Fetches registered agents.
 * @returns {Promise<Array<object>>} List of agents.
 */
async function getAgents() {
  return fetchWithAuth(`${API_BASE_URL}/agents`);
}

/**
 * Sends a command to the backend.
 * @param {string} commandString The command to execute.
 * @param {string|null} targetNode Optional target for the command.
 * @param {object} params Optional parameters for the command.
 * @returns {Promise<object>} Response from the command endpoint.
 */
async function sendCommand(commandString, targetNode = null, params = {}) {
  const payload = {
    command: commandString,
    target_node: targetNode,
    parameters: params,
  };
  return fetchWithAuth(`${API_BASE_URL}/commands`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

// Add other API functions as needed, e.g.:
// async function getAlertDetails(alertId) {
//   return fetchWithAuth(`${API_BASE_URL}/alerts/${alertId}`);
// }

export const apiService = {
  getStatus,
  getAlerts,
  getAgents,
  sendCommand, // Added sendCommand
  // getAlertDetails, // Uncomment when needed
};
