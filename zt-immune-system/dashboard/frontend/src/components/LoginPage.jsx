// zt-immune-system/dashboard/frontend/src/components/LoginPage.jsx
import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { Button } from "@/components/ui/button"; // Assuming Shadcn UI path
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"; // Assuming Shadcn UI path
import { Input } from "@/components/ui/input"; // Assuming Shadcn UI path
import { Label } from "@/components/ui/label"; // Assuming Shadcn UI path

const LoginPage = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const { login, loadingAuth } = useAuth(); // Added loadingAuth to disable form during login attempt
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);

    if (!username || !password) {
      setError('Username and password are required.');
      setIsSubmitting(false);
      return;
    }

    try {
      const result = await login(username, password);
      if (!result.success) {
        setError(result.error || 'Login failed. Please check your credentials.');
      }
      // On successful login, App.jsx handles redirection.
    } catch (err) {
      console.error("Login page error:", err);
      setError('An unexpected error occurred during login.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100 dark:bg-gray-900 px-4">
      <Card className="w-full max-w-sm">
        <CardHeader className="space-y-1">
          <CardTitle className="text-2xl font-bold text-center">ZT Immune System Login</CardTitle>
          <CardDescription className="text-center">
            Enter your credentials to access the dashboard.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <div className="p-3 bg-red-100 border border-red-400 text-red-700 rounded-md dark:bg-red-900/30 dark:border-red-700 dark:text-red-400">
                <p>{error}</p>
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                type="text"
                placeholder="admin"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled={isSubmitting || loadingAuth}
                autoComplete="username"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={isSubmitting || loadingAuth}
                autoComplete="current-password"
              />
            </div>
            <Button type="submit" className="w-full" disabled={isSubmitting || loadingAuth}>
              {isSubmitting || loadingAuth ? 'Logging in...' : 'Login'}
            </Button>
          </form>
        </CardContent>
        <CardFooter className="text-xs text-center text-gray-500 dark:text-gray-400">
          <p>Contact support if you have trouble logging in.</p>
        </CardFooter>
      </Card>
    </div>
  );
};

export default LoginPage;
