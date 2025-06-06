// zt-immune-system/dashboard/frontend/src/services/websocket.js

/**
 * Establishes and manages a WebSocket connection.
 * @param {object} params - Connection parameters.
 * @param {string} params.url - The WebSocket URL to connect to.
 * @param {function} params.onOpen - Callback for when the connection opens.
 * @param {function} params.onMessage - Callback for when a message is received.
 * @param {function} params.onError - Callback for when an error occurs.
 * @param {function} params.onClose - Callback for when the connection closes.
 * @returns {WebSocket | null} The WebSocket instance, or null if URL is not provided.
 */
function connectWebSocket({ url, onOpen, onMessage, onError, onClose }) {
  if (!url) {
    console.error("WebSocket URL must be provided.");
    if (onError) {
      onError(new Error("WebSocket URL must be provided."));
    }
    return null;
  }

  console.log(`Attempting to connect WebSocket to: ${url}`);
  const socket = new WebSocket(url);

  socket.onopen = (event) => {
    console.log(`WebSocket connected to ${url}`, event);
    if (onOpen) {
      onOpen(event);
    }
  };

  socket.onmessage = (event) => {
    try {
      const message = JSON.parse(event.data);
      // console.log(`WebSocket message received from ${url}:`, message); // Can be very noisy
      if (onMessage) {
        onMessage(message);
      }
    } catch (e) {
      console.error(`Error parsing WebSocket message from ${url}:`, e, "\nRaw data:", event.data);
      // Optionally call onError or a specific onParseError callback if defined
      if (onError) {
         // Pass a custom error object or the original error
        onError(new Error(`Failed to parse message from ${url}. Original error: ${e.message}. Data: ${event.data.substring(0,100)}...`));
      }
    }
  };

  socket.onerror = (errorEvent) => {
    // The 'error' event object itself is often not very informative for WebSocket errors.
    // The actual error details are usually logged by the browser console before this handler is called.
    console.error(`WebSocket error on ${url}. Type: ${errorEvent.type}. Check browser console for more details.`, errorEvent);
    if (onError) {
      onError(new Error(`WebSocket connection error to ${url}. See browser console.`));
    }
  };

  socket.onclose = (event) => {
    console.log(`WebSocket disconnected from ${url}. Code: ${event.code}, Reason: '${event.reason || "No reason provided"}', Cleanly closed: ${event.wasClean}`, event);
    if (onClose) {
      onClose(event);
    }
  };

  return socket;
}

/**
 * Closes an active WebSocket connection.
 * @param {WebSocket} socket - The WebSocket instance to close.
 */
function closeWebSocket(socket) {
  if (socket && socket.readyState === WebSocket.OPEN) {
    console.log("Closing WebSocket connection.", socket.url);
    socket.close(1000, "Client requested disconnect"); // 1000 indicates a normal closure
  } else if (socket) {
    console.log("WebSocket already closed or not in OPEN state. Current state:", socket.readyState, socket.url);
  } else {
    // This case should ideally not happen if socket instance is managed correctly
    console.warn("closeWebSocket called with no WebSocket instance.");
  }
}

export const websocketService = {
  connectWebSocket,
  closeWebSocket,
};
