// zt-immune-system/dashboard/frontend/src/components/Dashboard.jsx
import React from 'react';
import { useAuth } from '../contexts/AuthContext';
import SystemStatusPanel from './SystemStatusPanel';
import AlertsPanel from './AlertsPanel';
import AgentsStatus from './AgentsStatus';
import ConsoleTerminal from './ConsoleTerminal';
import AICommandSuggestions from './AICommandSuggestions';
import { Button } from "@/components/ui/button"; // Assuming Shadcn UI path
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"; // Assuming Shadcn UI path
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"; // Assuming Shadcn UI path
import { LogOut } from 'lucide-react'; // Example icon

const Dashboard = () => {
  const { logout, user } = useAuth();

  const handleLogout = () => {
    logout();
  };

  return (
    <div className="min-h-screen flex flex-col bg-gray-100 dark:bg-gray-900 text-gray-900 dark:text-gray-100 p-4 md:p-6 lg:p-8">
      <header className="flex items-center justify-between pb-4 mb-4 border-b border-gray-300 dark:border-gray-700">
        <h1 className="text-2xl md:text-3xl font-bold">ZT Immune System Dashboard</h1>
        <div className="flex items-center space-x-3">
          {user && (
            <span className="text-sm text-gray-600 dark:text-gray-300">
              Welcome, <strong className="font-medium">{user.username || 'User'}</strong>
              {user.roles && user.roles.length > 0 && ` (${user.roles.join(', ')})`}
            </span>
          )}
          <Button variant="outline" size="sm" onClick={handleLogout}>
            <LogOut className="mr-2 h-4 w-4" />
            Logout
          </Button>
        </div>
      </header>

      <Tabs defaultValue="overview" className="flex-grow">
        <TabsList className="grid w-full grid-cols-2 sm:grid-cols-3 md:grid-cols-5 mb-4">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="alerts">Alerts</TabsTrigger>
          <TabsTrigger value="agents">Agents</TabsTrigger>
          <TabsTrigger value="console">Console</TabsTrigger>
          <TabsTrigger value="ai_commands">AI Suggestions</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>System Status</CardTitle>
              <CardDescription>Current operational status of the ZT Immune System components.</CardDescription>
            </CardHeader>
            <CardContent>
              <SystemStatusPanel />
            </CardContent>
          </Card>
          {/* Add more overview cards here if needed, e.g., a summary of critical alerts or agent health */}
          <Card>
            <CardHeader>
              <CardTitle>Quick Actions</CardTitle>
              <CardDescription>Common administrative actions.</CardDescription>
            </CardHeader>
            <CardContent className="flex space-x-2">
              <Button variant="outline">Scan All Endpoints</Button>
              <Button variant="outline">Check for Updates</Button>
              <Button variant="destructive">Initiate System Lockdown (Simulated)</Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="alerts">
          <Card>
            <CardHeader>
              <CardTitle>Real-time Alerts</CardTitle>
              <CardDescription>Live feed of security alerts from various sources.</CardDescription>
            </CardHeader>
            <CardContent>
              <AlertsPanel />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="agents">
          <Card>
            <CardHeader>
              <CardTitle>Agent Status & Management</CardTitle>
              <CardDescription>Overview of all deployed Mini-Agents.</CardDescription>
            </CardHeader>
            <CardContent>
              <AgentsStatus />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="console">
          <Card>
            <CardHeader>
              <CardTitle>Interactive System Console</CardTitle>
              <CardDescription>Direct command-line access to the system orchestrator or agents.</CardDescription>
            </CardHeader>
            <CardContent>
              <ConsoleTerminal />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="ai_commands">
          <Card>
            <CardHeader>
              <CardTitle>AI Command Suggestions</CardTitle>
              <CardDescription>Review and approve commands suggested by the AI based on detected threats.</CardDescription>
            </CardHeader>
            <CardContent>
              <AICommandSuggestions />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <footer className="mt-auto pt-4 text-center text-xs text-gray-500 dark:text-gray-400">
        ZT Immune System Dashboard &copy; {new Date().getFullYear()}
      </footer>
    </div>
  );
};

export default Dashboard;
