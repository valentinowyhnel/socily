// zt-immune-system/dashboard/frontend/src/components/SystemStatusPanel.jsx
import React, { useState, useEffect } from 'react';
import { apiService } from '../services/apiService';
import { AlertCircle, CheckCircle2, Loader2, ServerCrash } from 'lucide-react'; // Example icons

// Helper component for individual status items
const StatusItem = ({ label, value, icon }) => (
  <div className="flex items-center justify-between py-2 border-b border-gray-200 dark:border-gray-700 last:border-b-0">
    <div className="flex items-center">
      {icon && React.cloneElement(icon, { className: "mr-2 h-5 w-5 text-gray-500 dark:text-gray-400" })}
      <span className="text-sm font-medium text-gray-700 dark:text-gray-300">{label}:</span>
    </div>
    <span className="text-sm text-gray-900 dark:text-gray-100">{value}</span>
  </div>
);

const SystemStatusPanel = () => {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchStatus = async () => {
      setLoading(true);
      setError('');
      try {
        const data = await apiService.getStatus();
        setStatus(data);
      } catch (err) {
        console.error("Error fetching system status:", err);
        setError(err.message || 'Failed to fetch system status.');
        setStatus(null);
      } finally {
        setLoading(false);
      }
    };

    fetchStatus();
    const intervalId = setInterval(fetchStatus, 30000); // Refresh every 30 seconds
    return () => clearInterval(intervalId);
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center p-6 text-gray-500 dark:text-gray-400">
        <Loader2 className="mr-2 h-5 w-5 animate-spin" />
        <span>Loading system status...</span>
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

  if (!status) {
    return (
      <div className="p-6 text-center text-gray-500 dark:text-gray-400">
        <ServerCrash className="mx-auto mb-2 h-8 w-8" />
        No system status data available.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <StatusItem
        label="AI Status"
        value={status.ai_status?.toUpperCase()}
        icon={<CheckCircle2 className={status.ai_status === 'nominal' ? 'text-green-500' : 'text-yellow-500'} />}
      />
      <StatusItem
        label="Active Agents"
        value={status.active_agents?.toString()}
        icon={<CheckCircle2 className="text-green-500" />}
      />
      <StatusItem
        label="Kafka Status"
        value={status.kafka_status?.toUpperCase()}
        icon={<CheckCircle2 className={status.kafka_status === 'connected' ? 'text-green-500' : 'text-red-500'} />}
      />
      <StatusItem
        label="Last Processed Alert"
        value={status.last_processed_alert_ts ? new Date(status.last_processed_alert_ts).toLocaleString() : 'N/A'}
      />
      <StatusItem
        label="Alerts in Queue"
        value={status.alerts_in_queue?.toString()}
      />
    </div>
  );
};

export default SystemStatusPanel;
