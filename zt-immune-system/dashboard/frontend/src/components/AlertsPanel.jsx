// zt-immune-system/dashboard/frontend/src/components/AlertsPanel.jsx
import React, { useState, useEffect, useRef } from 'react';
import { apiService } from '../services/apiService';
import { websocketService } from '../services/websocket';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"; // Assuming Shadcn UI path
import { ScrollArea } from "@/components/ui/scroll-area"; // Assuming Shadcn UI path
import { AlertTriangle, CheckCircle, Info, Loader2, XCircle } from 'lucide-react'; // Example icons

const MAX_ALERTS_DISPLAY = 50;

const getSeverityClasses = (severity) => {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return 'border-red-700 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300';
    case 'high':
      return 'border-orange-600 bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300';
    case 'medium':
      return 'border-yellow-500 bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400';
    case 'low':
      return 'border-blue-500 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400';
    default:
      return 'border-gray-300 bg-gray-50 dark:bg-gray-800/30 text-gray-600 dark:text-gray-400';
  }
};

const AlertItem = ({ alert }) => (
  <Card className={`mb-3 shadow-sm ${getSeverityClasses(alert.severity)}`}>
    <CardHeader className="pb-2 pt-3 px-4">
      <CardTitle className="text-sm font-semibold">{alert.description}</CardTitle>
      <CardDescription className="text-xs">
        ID: {alert.id} | Severity: {alert.severity || 'N/A'} | Status: {alert.status}
      </CardDescription>
    </CardHeader>
    <CardContent className="text-xs px-4 pb-3">
      <p>Time: {new Date(alert.timestamp).toLocaleString()}</p>
      {alert.source_ip && <p>Source IP: {alert.source_ip}</p>}
      {alert.source_host && <p>Source Host: {alert.source_host}</p>}
      {alert.details && (
        <details className="mt-1 text-xs">
          <summary className="cursor-pointer hover:underline">More Details</summary>
          <pre className="mt-1 p-2 bg-gray-100 dark:bg-gray-700/50 rounded text-xs whitespace-pre-wrap">
            {JSON.stringify(alert.details, null, 2)}
          </pre>
        </details>
      )}
    </CardContent>
  </Card>
);


const AlertsPanel = () => {
  const [alerts, setAlerts] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const socketRef = useRef(null);

  useEffect(() => {
    const fetchAlerts = async () => {
      setIsLoading(true);
      setError('');
      try {
        const initialAlerts = await apiService.getAlerts();
        setAlerts(initialAlerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)));
      } catch (err) {
        console.error("Error fetching initial alerts:", err);
        setError(err.message || 'Failed to fetch initial alerts.');
      } finally {
        setIsLoading(false);
      }
    };
    fetchAlerts();
  }, []);

  useEffect(() => {
    const wsUrl = 'ws://localhost:8001/api/agents/status';

    const handleWsOpen = () => console.log('AlertsPanel: WebSocket connection established.');

    const handleWsMessage = (message) => {
      console.log("AlertsPanel: WebSocket message received:", message.type);
      if (message.type === 'new_alert' && message.alert) {
        setAlerts(prevAlerts => {
          if (prevAlerts.find(a => a.id === message.alert.id)) return prevAlerts;
          const newAlerts = [message.alert, ...prevAlerts];
          return newAlerts.slice(0, MAX_ALERTS_DISPLAY);
        });
      } else if (message.type === 'alert_update' && message.alert) {
        setAlerts(prevAlerts =>
          prevAlerts.map(a => a.id === message.alert.id ? { ...a, ...message.alert } : a)
        );
      }
    };

    const handleWsError = (errEvent) => {
      console.error('AlertsPanel: WebSocket error event:', errEvent);
      setError('WebSocket error. Real-time updates may be unavailable.');
    };

    const handleWsClose = (event) => {
      console.log('AlertsPanel: WebSocket connection closed.', `Code: ${event.code}, Reason: ${event.reason}`);
      if (event.code !== 1000 && event.code !== 1005) {
        setError('WebSocket disconnected. Real-time updates stopped.');
      }
    };

    socketRef.current = websocketService.connectWebSocket({
      url: wsUrl,
      onOpen: handleWsOpen,
      onMessage: handleWsMessage,
      onError: handleWsError,
      onClose: handleWsClose,
    });

    return () => {
      if (socketRef.current) {
        websocketService.closeWebSocket(socketRef.current);
        socketRef.current = null;
      }
    };
  }, []);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-6 text-gray-500 dark:text-gray-400">
        <Loader2 className="mr-2 h-5 w-5 animate-spin" />
        <span>Loading initial alerts...</span>
      </div>
    );
  }

  // Display error related to initial fetch, WebSocket error is shown as a persistent message if it occurs
  if (error && alerts.length === 0) { // Show primary error if alerts couldn't be fetched initially
    return (
      <div className="p-6 bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded-md text-red-700 dark:text-red-400 flex items-center">
        <XCircle className="mr-2 h-5 w-5" />
        <span>Error: {error}</span>
      </div>
    );
  }

  return (
    <div className="h-[400px] flex flex-col"> {/* Set a fixed height for the panel or make it flexible */}
      {error && ( // Persistent WebSocket error message
         <div className="mb-2 p-2 bg-yellow-100 dark:bg-yellow-900/30 border border-yellow-300 dark:border-yellow-700 rounded-md text-yellow-700 dark:text-yellow-400 flex items-center text-sm">
           <AlertTriangle className="mr-2 h-4 w-4" />
           <span>{error}</span>
         </div>
      )}
      {alerts.length === 0 && !isLoading && !error && (
        <div className="flex-grow flex flex-col items-center justify-center text-gray-500 dark:text-gray-400">
          <Info className="mb-2 h-8 w-8" />
          <p>No alerts to display.</p>
        </div>
      )}
      {alerts.length > 0 && (
        <ScrollArea className="flex-grow pr-3"> {/* pr-3 for scrollbar padding */}
          {alerts.map(alert => (
            <AlertItem key={alert.id} alert={alert} />
          ))}
        </ScrollArea>
      )}
    </div>
  );
};

export default AlertsPanel;
