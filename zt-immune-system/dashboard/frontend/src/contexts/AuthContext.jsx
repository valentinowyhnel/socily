// zt-immune-system/dashboard/frontend/src/contexts/AuthContext.jsx
import React, { createContext, useContext, useState, useEffect } from 'react';
import { authService } from '../services/authService';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [token, setToken] = useState(null);
  const [user, setUser] = useState(null); // Stores basic user info like username, roles
  const [loading, setLoading] = useState(true); // To handle initial auth state check

  useEffect(() => {
    // Check for existing token on initial load
    const existingToken = authService.getToken();
    if (existingToken) {
      setToken(existingToken);
      setIsAuthenticated(true);
      // Decode token for user info (unsafe, for display only)
      try {
        const payloadBase64 = existingToken.split('.')[1];
        const decodedPayload = JSON.parse(atob(payloadBase64));
        setUser({
          username: decodedPayload.sub,
          roles: decodedPayload.scopes || []
        });
      } catch (e) {
        console.error("Error decoding token on initial load:", e);
        // Token might be invalid or malformed, log out
        authService.logout();
        setIsAuthenticated(false);
        setToken(null);
        setUser(null);
      }
    }
    setLoading(false);
  }, []);

  const login = async (username, password) => {
    setLoading(true);
    const response = await authService.login(username, password);
    if (response.success && response.token) {
      setToken(response.token);
      setIsAuthenticated(true);
      setUser(response.user); // User info (username, roles) from authService.login
      setLoading(false);
      return { success: true };
    } else {
      setIsAuthenticated(false);
      setToken(null);
      setUser(null);
      setLoading(false);
      return { success: false, error: response.error || 'Login failed in AuthContext' };
    }
  };

  const logout = () => {
    authService.logout();
    setIsAuthenticated(false);
    setToken(null);
    setUser(null);
  };

  // Do not render children until initial auth check is complete
  if (loading) {
    return <div>Loading authentication status...</div>; // Or a spinner component
  }

  return (
    <AuthContext.Provider value={{ isAuthenticated, token, user, login, logout, loadingAuth: loading }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined || context === null) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
