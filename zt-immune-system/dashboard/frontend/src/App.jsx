// zt-immune-system/dashboard/frontend/src/App.jsx
import React from 'react';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import LoginPage from './components/LoginPage';
import Dashboard from './components/Dashboard';
import './globals.css'; // Import global styles (Tailwind base, Shadcn theme)

const AppContent = () => {
  const { isAuthenticated, loadingAuth } = useAuth();

  if (loadingAuth) {
    // Display a loading indicator while checking auth status from localStorage
    return (
      <div className="flex items-center justify-center h-screen bg-background text-foreground">
        {/* Replace with a Shadcn Spinner or Progress component if available */}
        Loading application...
      </div>
    );
  }

  // LoginPage and Dashboard will now manage their own full-screen backgrounds if needed
  return isAuthenticated ? <Dashboard /> : <LoginPage />;
};

const App = () => {
  return (
    // Apply a base Tailwind class for potential dark theme, font, etc.
    // The actual dark/light mode switch would be more complex, often involving a theme provider.
    <div className="min-h-screen bg-background font-sans antialiased">
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </div>
  );
};

export default App;
