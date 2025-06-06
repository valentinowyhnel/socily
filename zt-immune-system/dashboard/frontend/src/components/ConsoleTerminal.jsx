// zt-immune-system/dashboard/frontend/src/components/ConsoleTerminal.jsx
import React, { useEffect, useRef, useCallback, useState } from 'react';
import { Terminal } from 'xterm';
import 'xterm/css/xterm.css'; // Import xterm.css
import { FitAddon } from 'xterm-addon-fit';
import { apiService } from '../services/apiService';
import { useAuth } from '../contexts/AuthContext';
import { AlertTriangle } from 'lucide-react';

const ConsoleTerminal = () => { // Removed title prop
  const terminalRef = useRef(null);
  const xtermInstanceRef = useRef(null);
  const fitAddonRef = useRef(null);
  const inputBufferRef = useRef('');
  const { isAuthenticated } = useAuth();
  const [isTermInitialized, setIsTermInitialized] = useState(false);

  const handleCommandSubmit = useCallback(async (command) => {
    if (!xtermInstanceRef.current) return;

    if (!isAuthenticated) {
      xtermInstanceRef.current.writeln('\r\n\x1b[31mError: Not authenticated. Please login to use the terminal.\x1b[0m');
      xtermInstanceRef.current.prompt();
      return;
    }

    xtermInstanceRef.current.writeln(`\r\n\x1b[32mExecuting: ${command}\x1b[0m`);
    try {
      const response = await apiService.sendCommand(command);
      const responseOutput = response.details || JSON.stringify(response, null, 2);
      xtermInstanceRef.current.writeln(`\r\nResponse: ${responseOutput}`);
    } catch (error) {
      const errorMessage = error.data?.detail || error.message || 'Failed to execute command';
      xtermInstanceRef.current.writeln(`\r\n\x1b[31mError: ${errorMessage}\x1b[0m`);
    }
    xtermInstanceRef.current.prompt();
  }, [isAuthenticated]);

  useEffect(() => {
    // Only initialize if authenticated and the DOM element is ready
    if (isAuthenticated && terminalRef.current && !xtermInstanceRef.current) {
      console.log("ConsoleTerminal: Initializing xterm.js");
      const term = new Terminal({
        cursorBlink: true,
        convertEol: true,
        rows: 20, // Increased rows
        theme: { // Consistent dark theme
          background: '#1f2937', // Tailwind gray-800
          foreground: '#d1d5db', // Tailwind gray-300
          cursor: '#f3f4f6',     // Tailwind gray-100
          selectionBackground: '#4b5563', // Tailwind gray-600 (selectionBackground for xterm v4+)
          black: '#111827', // Tailwind gray-900
          red: '#ef4444',     // Tailwind red-500
          green: '#22c55e',   // Tailwind green-500
          yellow: '#eab308',  // Tailwind yellow-500
          blue: '#3b82f6',    // Tailwind blue-500
          magenta: '#ec4899', // Tailwind pink-500
          cyan: '#06b6d4',    // Tailwind cyan-500
          white: '#f9fafb',   // Tailwind gray-50
          brightBlack: '#6b7280', // Tailwind gray-500
          brightRed: '#f87171',   // Tailwind red-400
          brightGreen: '#4ade80', // Tailwind green-400
          brightYellow: '#fde047',// Tailwind yellow-300
          brightBlue: '#60a5fa',  // Tailwind blue-400
          brightMagenta: '#f472b6',// Tailwind pink-400
          brightCyan: '#22d3ee',  // Tailwind cyan-400
          brightWhite: '#f9fafb', // Tailwind gray-50
        },
        fontSize: 13, // Slightly smaller for more content
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
        bellStyle: 'sound', // or 'visual' or 'none'
        allowProposedApi: true, // For some newer addons or features if needed
      });

      const fitAddon = new FitAddon();
      term.loadAddon(fitAddon);

      term.open(terminalRef.current);
      fitAddon.fit(); // Fit after open

      xtermInstanceRef.current = term;
      fitAddonRef.current = fitAddon;
      setIsTermInitialized(true); // Mark as initialized

      term.writeln('Welcome to ZT Immune System Interactive Terminal.');
      term.writeln('Type "help" for a list of commands (placeholder).');
      term.prompt = () => {
        term.write('\r\n\x1b[36m$\x1b[0m '); // Cyan prompt
      };
      term.prompt();

      term.onKey(({ key, domEvent }) => {
        const printable = !domEvent.altKey && !domEvent.ctrlKey && !domEvent.metaKey;

        if (domEvent.key === 'Enter') {
          if (inputBufferRef.current.trim() !== '') {
            handleCommandSubmit(inputBufferRef.current.trim());
          } else {
            term.writeln('');
            term.prompt();
          }
          inputBufferRef.current = '';
        } else if (domEvent.key === 'Backspace') {
          if (inputBufferRef.current.length > 0 && term.buffer.active.cursorX > 2) { // Prevent deleting prompt
            term.write('\b \b');
            inputBufferRef.current = inputBufferRef.current.slice(0, -1);
          }
        } else if (printable && key.length === 1) {
          term.write(key);
          inputBufferRef.current += key;
        }
      });
    } else if (!isAuthenticated && xtermInstanceRef.current) {
      // If user logs out while terminal is active
      xtermInstanceRef.current.dispose();
      xtermInstanceRef.current = null;
      setIsTermInitialized(false);
    }

    return () => { // Cleanup
      if (xtermInstanceRef.current && !isAuthenticated) { // Ensure disposal if unmounted while not authenticated
         xtermInstanceRef.current.dispose();
         xtermInstanceRef.current = null;
         setIsTermInitialized(false);
      }
    };
  }, [isAuthenticated, handleCommandSubmit]);


  useEffect(() => {
    const handleResize = () => {
      fitAddonRef.current?.fit();
    };
    if (isTermInitialized) {
      window.addEventListener('resize', handleResize);
      // Initial fit after terminal is shown and container is sized
      setTimeout(() => fitAddonRef.current?.fit(), 100); // Small delay for layout to settle
    }
    return () => {
      window.removeEventListener('resize', handleResize);
    };
  }, [isTermInitialized]);

  // Effect to handle re-focusing the terminal when it becomes visible/active
  // This is useful if it's in a Tab that gets hidden and re-shown
  useEffect(() => {
    if (isAuthenticated && isTermInitialized && xtermInstanceRef.current) {
        // Check if terminal is part of visible DOM (e.g. active tab)
        // This is a simplified check; IntersectionObserver could be more robust
        if (terminalRef.current && terminalRef.current.offsetParent !== null) {
            xtermInstanceRef.current.focus();
            // A small delay before fit can sometimes help if container size changes on tab switch
            setTimeout(() => fitAddonRef.current?.fit(), 50);
        }
    }
  }, [isAuthenticated, isTermInitialized]); // Re-run when auth or init state changes


  if (!isAuthenticated) {
    return (
      <div className="p-6 bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-300 dark:border-yellow-700 rounded-md text-yellow-700 dark:text-yellow-400 flex items-center justify-center h-[340px]"> {/* Match terminal height + padding */}
        <AlertTriangle className="mr-2 h-5 w-5" />
        Please login to use the interactive console.
      </div>
    );
  }

  return (
    // The parent Card in Dashboard.jsx provides the title and overall padding.
    // This div is the direct container for xterm.js.
    <div
      ref={terminalRef}
      className="w-full h-[340px] bg-gray-800 dark:bg-gray-900 p-2 rounded-b-md" // Dark bg for terminal, rounded bottom matching card
    />
  );
};

export default ConsoleTerminal;
