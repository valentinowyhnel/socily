// zt-immune-system/dashboard/frontend/src/components/AgentsStatus.jsx
import React, { useState, useEffect } from 'react';
import { apiService } from '../services/apiService';
import { ScrollArea } from "@/components/ui/scroll-area"; // Assuming Shadcn UI path
import { Badge } from "@/components/ui/badge"; // For status
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Wifi, WifiOff, AlertCircle, Loader2, Server } from 'lucide-react'; // Example icons

const getStatusVariant = (status = "unknown") => {
  switch (status.toLowerCase()) {
    case 'online':
      return 'default'; // Greenish in default Shadcn theme
    case 'offline':
      return 'destructive';
    case 'stale':
      return 'outline'; // Or a custom yellow/orange variant if defined
    default: // error, unknown
      return 'secondary';
  }
};

const getStatusIcon = (status = "unknown") => {
  switch (status.toLowerCase()) {
    case 'online':
      return <Wifi className="h-4 w-4 text-green-500" />;
    case 'offline':
      return <WifiOff className="h-4 w-4 text-red-500" />;
    case 'stale':
      return <AlertCircle className="h-4 w-4 text-yellow-500" />;
    default:
      return <AlertCircle className="h-4 w-4 text-gray-500" />;
  }
}

const AgentsStatus = () => {
  const [agents, setAgents] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchAgents = async () => {
      setIsLoading(true);
      setError('');
      try {
        const data = await apiService.getAgents();
        setAgents(data.sort((a,b) => a.agent_id.localeCompare(b.agent_id)));
      } catch (err) {
        console.error("Error fetching agents status:", err);
        setError(err.message || 'Failed to fetch agents status.');
      } finally {
        setIsLoading(false);
      }
    };

    fetchAgents();
    const intervalId = setInterval(fetchAgents, 30000); // Refresh every 30 seconds
    return () => clearInterval(intervalId);
  }, []);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-6 text-gray-500 dark:text-gray-400">
        <Loader2 className="mr-2 h-5 w-5 animate-spin" />
        <span>Loading agents status...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6 bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded-md text-red-700 dark:text-red-400 flex items-center">
        <AlertCircle className="mr-2 h-5 w-5" />
        <span>Error: {error}</span>
      </div>
    );
  }

  if (agents.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center p-6 text-gray-500 dark:text-gray-400">
        <Server className="mb-2 h-8 w-8" />
        <p>No agents registered or available.</p>
      </div>
    );
  }

  return (
    <ScrollArea className="h-[350px] rounded-md border dark:border-gray-700"> {/* Fixed height for scrollability */}
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[150px]">Agent ID</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Hostname</TableHead>
            <TableHead>IP Address</TableHead>
            <TableHead>Version</TableHead>
            <TableHead className="text-right">Last Seen</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {agents.map(agent => (
            <TableRow key={agent.agent_id} className="text-xs dark:hover:bg-gray-800">
              <TableCell className="font-medium">{agent.agent_id}</TableCell>
              <TableCell>
                <Badge variant={getStatusVariant(agent.status)} className="flex items-center w-fit">
                  {getStatusIcon(agent.status)}
                  <span className="ml-1.5">{agent.status?.toUpperCase() || 'UNKNOWN'}</span>
                </Badge>
              </TableCell>
              <TableCell>{agent.type || 'N/A'}</TableCell>
              <TableCell>{agent.hostname || 'N/A'}</TableCell>
              <TableCell>{agent.ip_address || 'N/A'}</TableCell>
              <TableCell>{agent.version || 'N/A'}</TableCell>
              <TableCell className="text-right">{new Date(agent.last_seen).toLocaleString()}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </ScrollArea>
  );
};

export default AgentsStatus;
