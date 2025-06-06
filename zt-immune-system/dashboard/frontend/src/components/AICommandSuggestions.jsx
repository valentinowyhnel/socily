// zt-immune-system/dashboard/frontend/src/components/AICommandSuggestions.jsx
import React, { useState, useEffect, useRef } from 'react';
import { apiService } from '../services/apiService';
import { useAuth } from '../contexts/AuthContext';
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from "@/components/ui/card"; // Assuming Shadcn UI path
import { Button } from "@/components/ui/button"; // Assuming Shadcn UI path
import { Mic, AlertTriangle, CheckCircle, Loader2, Info } from 'lucide-react'; // Example icons

const mockSuggestions = [
  { id: 'ai_cmd_1', description: 'Isolate compromised host server-012', command_to_execute: 'isolate_host server-012 --reason="Suspicious C2 activity detected"', details: 'High probability of lateral movement based on network flow analysis (Alert #alert_init_1).' },
  { id: 'ai_cmd_2', description: 'Block malicious IP 192.0.2.77', command_to_execute: 'block_ip 192.0.2.77 --source="ThreatIntelFeedX"', details: 'IP associated with known C2 server targeting financial institutions.' },
  { id: 'ai_cmd_3', description: 'Scan endpoint "workstation-05" for malware', command_to_execute: 'scan_endpoint workstation-05 --profile=deep_scan', details: 'User "jane.doe" reported unusual sluggishness and pop-ups.' },
];

const AICommandSuggestions = () => {
  const [suggestedCommands, setSuggestedCommands] = useState([]);
  const [executionStatus, setExecutionStatus] = useState({}); // Keyed by command ID
  const { isAuthenticated } = useAuth();

  const [isListening, setIsListening] = useState(false);
  const [voiceTranscript, setVoiceTranscript] = useState('');
  const [voiceError, setVoiceError] = useState('');
  const [targetCommandForVoiceApproval, setTargetCommandForVoiceApproval] = useState(null);
  const speechRecognitionInstanceRef = useRef(null);
  const [speechSupported, setSpeechSupported] = useState(false);

  const approvalPhrases = ["approve", "confirm", "yes", "execute", "run command", "approve command", "proceed"];

  useEffect(() => {
    setSuggestedCommands(mockSuggestions);

    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (SpeechRecognition) {
      setSpeechSupported(true);
      const recognition = new SpeechRecognition();
      recognition.continuous = false;
      recognition.interimResults = false;
      recognition.lang = 'en-US';

      recognition.onstart = () => {
        setIsListening(true);
        setVoiceTranscript('');
        setVoiceError('');
      };

      recognition.onresult = (event) => {
        const transcript = event.results[0][0].transcript.trim().toLowerCase();
        setVoiceTranscript(transcript);
        if (targetCommandForVoiceApproval) {
          if (approvalPhrases.some(phrase => transcript.includes(phrase))) {
            handleApproveCommand(targetCommandForVoiceApproval);
            setTargetCommandForVoiceApproval(null);
          } else {
            setVoiceError(`Unrecognized phrase: "${transcript}". Try: ${approvalPhrases.join(', ')}.`);
            setTargetCommandForVoiceApproval(null);
          }
        } else {
          setVoiceError(`Heard "${transcript}", but no command was targeted.`);
        }
        setIsListening(false);
      };

      recognition.onerror = (event) => {
        setVoiceError(event.error || 'Unknown voice recognition error');
        setIsListening(false);
        setTargetCommandForVoiceApproval(null);
      };

      recognition.onend = () => {
        setIsListening(false);
      };
      speechRecognitionInstanceRef.current = recognition;
    } else {
      setSpeechSupported(false);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targetCommandForVoiceApproval]); // Dependency: handleApproveCommand might need to be wrapped in useCallback if included

  const handleApproveCommand = async (commandSuggestion) => {
    setTargetCommandForVoiceApproval(null);
    if (!isAuthenticated) {
      setExecutionStatus(prev => ({ ...prev, [commandSuggestion.id]: { status: 'error', message: 'Authentication required.' } }));
      return;
    }
    setExecutionStatus(prev => ({ ...prev, [commandSuggestion.id]: { status: 'executing', message: 'Executing...' } }));
    try {
      const commandParts = commandSuggestion.command_to_execute.split(' ');
      const mainCommand = commandParts[0];
      const targetNode = commandParts.length > 1 ? commandParts[1] : null;
      const params = {}; // Simplified parsing
      const response = await apiService.sendCommand(mainCommand, targetNode, params);
      setExecutionStatus(prev => ({ ...prev, [commandSuggestion.id]: { status: 'success', message: response.details || 'Command executed.', response } }));
    } catch (error) {
      if (targetCommandForVoiceApproval && targetCommandForVoiceApproval.id === commandSuggestion.id) {
        setTargetCommandForVoiceApproval(null);
      }
      setExecutionStatus(prev => ({ ...prev, [commandSuggestion.id]: { status: 'error', message: error.data?.detail || error.message || 'Failed.' } }));
    }
  };

  const handleVoiceApproveClick = (commandSuggestion) => {
    if (!speechRecognitionInstanceRef.current || !speechSupported) {
      setVoiceError('Voice recognition not available/supported.');
      return;
    }
    if (isListening) speechRecognitionInstanceRef.current.stop();
    setTargetCommandForVoiceApproval(commandSuggestion);
    setVoiceError('');
    setVoiceTranscript('');
    try {
      speechRecognitionInstanceRef.current.start();
    } catch (e) {
      setVoiceError("Could not start voice recognition.");
      setTargetCommandForVoiceApproval(null);
      setIsListening(false);
    }
  };

  if (!isAuthenticated) {
    return (
      <div className="p-4 bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-300 dark:border-yellow-700 rounded-md text-yellow-700 dark:text-yellow-400 flex items-center">
        <AlertTriangle className="mr-2 h-5 w-5" />
        Please log in to view and approve AI-suggested commands.
      </div>
    );
  }

  const currentVoiceTargetId = targetCommandForVoiceApproval?.id;

  return (
    <div className="space-y-4">
      {isListening && currentVoiceTargetId && (
        <div className="p-3 my-2 bg-blue-50 dark:bg-blue-900/30 border border-blue-300 dark:border-blue-700 rounded-md text-blue-700 dark:text-blue-400 flex items-center">
          <Mic className="mr-2 h-5 w-5 animate-pulse" />
          Listening for approval for: "<strong>{suggestedCommands.find(c=>c.id === currentVoiceTargetId)?.description}</strong>"... Say: "{approvalPhrases.slice(0,2).join('/')}/etc."
        </div>
      )}
      {voiceTranscript && !isListening && currentVoiceTargetId && (
          <div className="p-3 my-2 bg-gray-100 dark:bg-gray-700/50 rounded-md text-gray-700 dark:text-gray-300">Heard: "<em>{voiceTranscript}</em>"</div>
      )}
      {voiceError && (
        <div className="p-3 my-2 bg-red-50 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded-md text-red-700 dark:text-red-400 flex items-center">
          <AlertTriangle className="mr-2 h-5 w-5" /> {voiceError}
        </div>
      )}
      {!speechSupported && (
        <div className="p-3 my-2 bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-300 dark:border-yellow-700 rounded-md text-yellow-700 dark:text-yellow-400 flex items-center text-sm">
           <Mic className="mr-2 h-4 w-4" /> Voice recognition is not supported by your browser.
        </div>
      )}

      {suggestedCommands.length === 0 && !isListening && !currentVoiceTargetId && (
        <div className="flex flex-col items-center justify-center p-6 text-gray-500 dark:text-gray-400">
          <Info className="mb-2 h-8 w-8" />
          <p>No command suggestions available at the moment.</p>
        </div>
      )}

      {suggestedCommands.map(suggestion => {
        const statusInfo = executionStatus[suggestion.id];
        const isExecutingThis = statusInfo?.status === 'executing';
        const isThisVoiceTarget = currentVoiceTargetId === suggestion.id && isListening;

        return (
          <Card key={suggestion.id} className="shadow-md hover:shadow-lg transition-shadow dark:bg-gray-800">
            <CardHeader>
              <CardTitle className="text-base text-blue-700 dark:text-blue-400">{suggestion.description}</CardTitle>
              <CardDescription className="text-xs">AI Rationale: {suggestion.details || "No additional details."}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              <p className="text-sm"><strong>Command Preview:</strong></p>
              <code className="block p-2 bg-gray-100 dark:bg-gray-700 rounded text-xs text-gray-800 dark:text-gray-200 overflow-x-auto">
                {suggestion.command_to_execute}
              </code>
            </CardContent>
            <CardFooter className="flex justify-end space-x-2">
              <Button
                variant="default"
                size="sm"
                onClick={() => handleApproveCommand(suggestion)}
                disabled={isExecutingThis || isListening}
              >
                {isExecutingThis ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <CheckCircle className="mr-2 h-4 w-4" />}
                {isExecutingThis ? 'Executing...' : 'Approve & Run'}
              </Button>
              {speechSupported && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleVoiceApproveClick(suggestion)}
                  disabled={isListening || isExecutingThis}
                  title="Approve this command using voice"
                >
                  <Mic className={`mr-2 h-4 w-4 ${isThisVoiceTarget ? 'text-blue-500 animate-pulse' : ''}`} />
                  {isThisVoiceTarget ? 'Listening...' : 'Voice Approve'}
                </Button>
              )}
            </CardFooter>
            {statusInfo && (
              <div className={`px-6 py-2 text-xs border-t mt-2 ${
                statusInfo.status === 'success' ? 'bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-300 border-green-200 dark:border-green-700' :
                statusInfo.status === 'error' ? 'bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-300 border-red-200 dark:border-red-700' :
                'bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-700'}`}>
                Status: {statusInfo.message}
              </div>
            )}
          </Card>
        );
      })}
    </div>
  );
};

export default AICommandSuggestions;
