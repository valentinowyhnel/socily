# zt-immune-system/ia_principale/communication/websocket_server.py
"""
Manages WebSocket communications for the IA Principale module.

This includes:
- Defining the WebSocket endpoint (`/ws_comm/ws`).
- Handling client connections, disconnections, and message exchanges.
- Authenticating clients using JWT passed as a query parameter.
- Parsing incoming JSON messages and routing them based on their 'type'.
- Sending user commands received via WebSocket to a Kafka topic.
- Consuming alerts from a Kafka topic and broadcasting them to connected clients.
- A `ConnectionManager` class to manage active WebSocket connections.
"""

import json
import os
import threading # For stop_event type hint in consumer function
import asyncio   # For scheduling coroutines from threads
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
import logging
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timezone

from pydantic import BaseModel, ValidationError

from ..auth import get_current_user_ws # JWT authentication dependency
from ..communication.kafka_client import KafkaConsumerWrapper # For frontend alerts consumer

# Configure logger for this module
logger = logging.getLogger(__name__)
if not logger.hasHandlers() and not logging.getLogger().hasHandlers(): # Avoid double config
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s'
    )

# Kafka Topic for User Commands (sent from WebSocket to Kafka)
USER_COMMANDS_TOPIC = os.environ.get("KAFKA_USER_COMMANDS_TOPIC", "user_commands")
logger.info(f"User commands from WebSockets will be sent to Kafka topic: '{USER_COMMANDS_TOPIC}'")

websocket_server_router = APIRouter()

# --- Pydantic Model for Incoming WebSocket Messages ---
class WebSocketMessage(BaseModel):
    """
    Pydantic model for validating the structure of incoming JSON messages from WebSocket clients.

    Attributes:
        type: A string indicating the type of the message (e.g., "echo", "user_command").
        data: A dictionary containing the payload specific to the message type.
        timestamp: An optional datetime object. If provided by the client as an ISO
                   datetime string, FastAPI/Pydantic will attempt to parse it.
    """
    type: str
    data: Dict[str, Any]
    timestamp: Optional[datetime] = None


class ConnectionManager:
    """
    Manages active WebSocket connections.

    This class provides methods to connect, disconnect, and broadcast messages
    to connected clients. It stores active connections along with the user ID
    obtained from JWT authentication.
    """
    def __init__(self):
        """Initializes the ConnectionManager with an empty list of active connections."""
        # Stores tuples of (WebSocket, user_id)
        self.active_connections: List[Tuple[WebSocket, str]] = []
        logger.info("ConnectionManager initialized.")

    async def connect(self, websocket: WebSocket, user_id: str):
        """
        Registers a new WebSocket connection.

        The WebSocket connection should already be accepted by the caller.

        Args:
            websocket: The WebSocket instance for the new connection.
            user_id: The authenticated user ID associated with this connection.
        """
        self.active_connections.append((websocket, user_id))
        logger.info(
            f"User '{user_id}' connected via WebSocket from {websocket.client}. "
            f"Total active connections: {len(self.active_connections)}"
        )

    def disconnect(self, websocket: WebSocket):
        """
        Removes a WebSocket connection from the list of active connections.

        Args:
            websocket: The WebSocket instance to disconnect.
        """
        user_id_disconnected = "unknown_user"
        connection_to_remove: Optional[Tuple[WebSocket, str]] = None
        for conn_tuple in self.active_connections:
            if conn_tuple[0] == websocket:
                connection_to_remove = conn_tuple
                user_id_disconnected = conn_tuple[1]
                break

        if connection_to_remove:
            self.active_connections.remove(connection_to_remove)
            logger.info(
                f"User '{user_id_disconnected}' disconnected WebSocket {websocket.client}. "
                f"Total active connections: {len(self.active_connections)}"
            )
        else:
            # This might happen if disconnect is called multiple times or on a connection not properly registered.
            logger.warning(
                f"Attempted to disconnect WebSocket {websocket.client} which was not found in active connections."
            )

    async def send_personal_json(self, data: dict, websocket: WebSocket, user_id: str):
        """
        Sends a JSON message to a specific WebSocket client.

        Args:
            data: The dictionary (JSON payload) to send.
            websocket: The WebSocket instance of the recipient.
            user_id: The user ID of the recipient (for logging purposes).
        """
        try:
            await websocket.send_json(data)
            logger.debug(f"Sent personal JSON to user '{user_id}' ({websocket.client}): {data.get('type', 'N/A')}")
        except WebSocketDisconnect: # Handle cases where client might have disconnected just before send
             logger.warning(f"Attempted to send personal JSON to user '{user_id}' but WebSocket was disconnected: {websocket.client}")
             self.disconnect(websocket) # Ensure cleanup if not already handled
        except Exception:
            logger.exception(f"Error sending personal JSON to user '{user_id}' ({websocket.client}).")
            # Optionally, consider disconnecting the client if sends consistently fail.
            # self.disconnect(websocket)

    async def broadcast_json(self, data: dict):
        """
        Broadcasts a JSON message to all active WebSocket connections.

        Iterates over a copy of the active connections list to allow for safe
        disconnection of clients if sending a message fails.

        Args:
            data: The dictionary (JSON payload) to broadcast.
        """
        num_connections = len(self.active_connections)
        message_type = data.get('type', 'N/A')
        logger.debug(f"Attempting to broadcast JSON message of type '{message_type}' to {num_connections} client(s).")

        # Iterate over a copy of the list in case of disconnections during broadcast
        for connection_tuple in list(self.active_connections):
            websocket, user_id = connection_tuple
            try:
                await websocket.send_json(data)
                logger.debug(f"Broadcast JSON (type: '{message_type}') sent to user '{user_id}' ({websocket.client})")
            except WebSocketDisconnect: # Client disconnected during broadcast attempt
                logger.info(f"Client '{user_id}' ({websocket.client}) disconnected during broadcast. Removing from active list.")
                self.disconnect(websocket)
            except Exception:
                logger.exception(f"Error broadcasting JSON (type: '{message_type}') to user '{user_id}' ({websocket.client}). Removing client.")
                self.disconnect(websocket) # Disconnect if any other send error occurs

# ConnectionManager instance is now created in main.py (app.state.connection_manager)
# This allows it to be shared with other components like the Kafka consumer for frontend alerts.

@websocket_server_router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    current_user: Dict[str, Any] = Depends(get_current_user_ws) # JWT Authentication dependency
):
    """
    Main WebSocket endpoint for real-time bidirectional communication.

    Handles:
    - Client authentication via JWT (passed as 'token' query parameter).
    - Connection management using the global `ConnectionManager` instance.
    - Receiving, validating, and processing JSON messages from clients.
    - Routing client messages (e.g., "user_command") to appropriate handlers (e.g., Kafka).
    - Sending acknowledgments and error messages back to the client.

    Expected client message format (JSON):
    {
        "type": "message_type_string",
        "data": { ... payload specific to type ... },
        "timestamp": "optional_iso_datetime_string"
    }
    """
    user_id = current_user.get("sub", "unknown_user") # 'sub' claim from JWT is user identifier
    manager = websocket.app.state.connection_manager # Access shared ConnectionManager

    if not manager:
        logger.critical("ConnectionManager not found in app.state. WebSocket endpoint cannot function.")
        # Attempt to close with an error, though without a manager, it's a bit limited.
        await websocket.accept() # Accept to send error, then close.
        await websocket.send_json({"type": "error", "message": "Server configuration error, cannot establish connection."})
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
        return

    await websocket.accept() # Accept the WebSocket connection
    await manager.connect(websocket, user_id) # Register with ConnectionManager

    kafka_producer = getattr(websocket.app.state, 'kafka_producer', None)
    if not kafka_producer or not kafka_producer.producer:
        logger.error(f"Kafka producer not available for user '{user_id}'. User commands will not be sent to Kafka.")
        # This is a server-side issue, client will be informed if they try to send a command.

    try:
        # Send connection acknowledgment to the client
        await manager.send_personal_json(
            {"type": "connection_ack", "status": "Authentication successful", "user_id": user_id},
            websocket, user_id
        )

        # Main message loop for this connection
        while True:
            try:
                received_data = await websocket.receive_json()
                logger.debug(f"Raw JSON received from user '{user_id}': {received_data}")

                # Validate incoming message structure using Pydantic model
                try:
                    message = WebSocketMessage(**received_data)
                    logger.info(f"Validated message of type '{message.type}' from user '{user_id}'. Data: {message.data}")

                    # --- Message Type Routing ---
                    if message.type == "echo":
                        # Echo the received data back to the client
                        await manager.send_personal_json({
                            "type": "echo_response",
                            "original_data": message.data,
                            "original_timestamp": message.timestamp.isoformat() if message.timestamp else None
                        }, websocket, user_id)

                    elif message.type == "user_command":
                        # Process user commands, e.g., by sending them to Kafka
                        command_name = message.data.get('command_name', 'N/A')
                        logger.info(f"Processing 'user_command' type: '{command_name}' from user '{user_id}'. Data: {message.data}")

                        if kafka_producer and kafka_producer.producer:
                            # Construct payload for Kafka
                            kafka_payload = {
                                "user_id": user_id,
                                "command_details": message.data, # Contains command_name and other params
                                "received_timestamp_utc": datetime.now(timezone.utc).isoformat(),
                                "client_timestamp_utc": message.timestamp.astimezone(timezone.utc).isoformat() if message.timestamp else None
                            }
                            logger.debug(f"Preparing to send to Kafka topic '{USER_COMMANDS_TOPIC}': {kafka_payload}")

                            # Send to Kafka
                            success = kafka_producer.send_message(USER_COMMANDS_TOPIC, kafka_payload)

                            if success:
                                logger.info(f"User command '{command_name}' from '{user_id}' successfully sent to Kafka topic '{USER_COMMANDS_TOPIC}'.")
                                await manager.send_personal_json({
                                    "type": "command_ack", "command_name": command_name,
                                    "status": "Command submitted to Kafka successfully.", "details": message.data
                                }, websocket, user_id)
                            else:
                                logger.error(f"Failed to send user command '{command_name}' from '{user_id}' to Kafka topic '{USER_COMMANDS_TOPIC}'.")
                                await manager.send_personal_json({
                                    "type": "command_error", "command_name": command_name,
                                    "status": "Failed to submit command to Kafka backend.", "details": message.data
                                }, websocket, user_id)
                        else:
                            # Kafka producer is not available
                            logger.error(f"Kafka producer unavailable. Cannot send command '{command_name}' from user '{user_id}'.")
                            await manager.send_personal_json({
                                "type": "command_error", "command_name": command_name,
                                "status": "Command processing system is currently unavailable.", "details": message.data
                            }, websocket, user_id)
                    else:
                        # Handle unsupported message types
                        logger.warning(f"Unsupported message type '{message.type}' received from user '{user_id}'.")
                        await manager.send_personal_json({
                            "type": "error", "message": f"Message type '{message.type}' is not supported."
                        }, websocket, user_id)

                except ValidationError as e:
                    # Pydantic model validation failed
                    logger.error(f"Pydantic validation error for message from user '{user_id}': {e.errors()}", exc_info=False) # exc_info=False as e.errors() is detailed
                    await manager.send_personal_json({
                        "type": "error", "message": "Invalid message structure.", "details": e.errors()
                    }, websocket, user_id)
                except Exception: # Catch other errors during specific message processing
                    logger.exception(f"Error processing message from user '{user_id}'. Raw data: {received_data}")
                    await manager.send_personal_json({
                        "type": "error", "message": "An error occurred while processing your message."
                    }, websocket, user_id)

            except json.JSONDecodeError:
                # Malformed JSON received (websocket.receive_json() failed)
                logger.warning(f"Invalid JSON format received from user '{user_id}'.", exc_info=True) # Log with stack trace for context
                # Explicitly send text here as send_json might fail if client expects JSON but this indicates a protocol error by client
                await websocket.send_text(json.dumps({"type": "error", "message": "Invalid JSON format received."}))
            except TypeError:
                 # receive_json() can raise TypeError if it receives non-text/bytes (e.g. client sends binary frame)
                 logger.warning(f"Received non-JSON message type (e.g., binary) from user '{user_id}'.", exc_info=True)
                 await websocket.send_text(json.dumps({"type": "error", "message": "Expected JSON text message, received other data type."}))

    except WebSocketDisconnect:
        logger.info(f"WebSocket connection closed by user '{user_id}' (client: {websocket.client})")
    except Exception: # Catch unexpected errors in the main WebSocket handling loop or connection setup
        logger.exception(f"An unexpected error occurred in WebSocket handling for user '{user_id}' (client: {websocket.client}).")
    finally:
        # Ensure client is disconnected from the manager upon any exit from the loop
        manager.disconnect(websocket)

# --- Kafka Consumer for Frontend Alerts ---
def start_frontend_alerts_kafka_consumer(
    kafka_broker: str,
    topic: str,
    group_id: str,
    manager_instance: ConnectionManager,
    stop_event: threading.Event
):
    """
    Starts a Kafka consumer in a separate thread to listen for frontend alerts.

    Messages consumed from the specified Kafka topic are formatted and broadcasted
    to all connected WebSocket clients via the provided `ConnectionManager`.

    Args:
        kafka_broker: Address of the Kafka broker.
        topic: Kafka topic to consume messages from.
        group_id: Consumer group ID for Kafka.
        manager_instance: The shared `ConnectionManager` instance to broadcast messages.
        stop_event: A `threading.Event` to signal graceful shutdown of the consumer.
    """
    logger.info(f"Initializing Kafka consumer for frontend alerts: Broker='{kafka_broker}', Topic='{topic}', GroupID='{group_id}'")
    consumer_wrapper = None
    try:
        consumer_wrapper = KafkaConsumerWrapper(
            topic,
            bootstrap_servers=kafka_broker,
            group_id=group_id,
            auto_offset_reset='latest' # Consume only new messages for real-time alerts
        )
        if not consumer_wrapper.consumer:
            logger.error(f"Failed to initialize KafkaConsumerWrapper for frontend alerts. Topic: '{topic}'. Consumer thread will exit.")
            return

        logger.info(f"Kafka consumer for frontend alerts started successfully. Listening on topic '{topic}'.")
        main_event_loop = asyncio.get_event_loop() # Get the main event loop (FastAPI's loop)

        while not stop_event.is_set():
            try:
                messages_dict = consumer_wrapper.consumer.poll(timeout_ms=1000, max_records=5)
                if not messages_dict: # No messages in this poll interval
                    if stop_event.is_set(): # Check stop event again after poll returns
                        logger.debug("Frontend alerts consumer: stop_event set after poll timeout.")
                        break
                    continue # Continue to next poll iteration

                for tp, messages in messages_dict.items():
                    logger.debug(f"Received {len(messages)} messages from Kafka topic '{tp.topic}' partition {tp.partition} for frontend broadcast.")
                    for kafka_msg in messages:
                        if stop_event.is_set():
                            logger.debug("Frontend alerts consumer: stop_event set during message processing.")
                            break
                        try:
                            alert_data = kafka_msg.value # Already deserialized by KafkaConsumerWrapper
                            logger.info(f"Received alert for frontend broadcast: {alert_data}")

                            frontend_payload = {
                                "type": "alert", # Standardized message type for frontend clients
                                "data": alert_data,
                                "timestamp_utc": datetime.now(timezone.utc).isoformat() # Add server-side timestamp
                            }

                            # Schedule the async broadcast_json on the main event loop
                            # This is crucial as this consumer runs in a separate thread.
                            if main_event_loop.is_running():
                                asyncio.run_coroutine_threadsafe(
                                    manager_instance.broadcast_json(frontend_payload),
                                    main_event_loop
                                )
                                logger.debug(f"Scheduled broadcast of alert: {frontend_payload.get('data', {}).get('alert_id', 'N/A')}")
                            else:
                                logger.warning("Main event loop not running. Cannot schedule alert broadcast to WebSockets.")

                        except Exception:
                            logger.exception(f"Error processing individual Kafka message for frontend alert. Message: {kafka_msg}")
                    if stop_event.is_set(): break # Break from outer loop if stop_event was set

            except Exception: # Catch errors from consumer.poll() or within the processing loop
                logger.exception("Error in frontend alerts Kafka consumer poll loop.")
                if stop_event.is_set(): break # Exit if stop is signaled
                # Optional: Add a short sleep to prevent rapid error logging in case of persistent issues
                # This wait also respects the stop_event.
                stop_event.wait(timeout=5) # Sleep for 5s or until stop_event is set

    except Exception: # Catches errors during consumer_wrapper initialization
        logger.exception(f"Fatal error in frontend_alerts_kafka_consumer setup for topic '{topic}'. Consumer thread will exit.")
    finally:
        if consumer_wrapper:
            logger.info(f"Closing Kafka consumer for frontend alerts. Topic: '{topic}'")
            consumer_wrapper.close()
        logger.info(f"Frontend alerts Kafka consumer thread for topic '{topic}' has stopped.")


# --- Global Helper Functions for Broadcasting (callable from other modules if app context is available) ---
# These are placeholders; direct use from other modules would require passing the app instance
# or using a more sophisticated dependency injection for the manager.
# For now, broadcasting is primarily initiated by the frontend_alerts_kafka_consumer.

async def broadcast_message_to_clients(message: str, app_instance: Optional[Any] = None):
    """Helper to broadcast a text message if manager is accessible (e.g., via app_instance.state)."""
    # This function is not currently used for text broadcasts as we focus on JSON.
    # Kept for potential future use or as an example.
    if app_instance and hasattr(app_instance.state, 'connection_manager'):
        manager = app_instance.state.connection_manager
        # ConnectionManager currently doesn't have a broadcast_text method, only broadcast_json
        # For simplicity, we'll log a warning or adapt if text broadcast is needed.
        logger.warning(f"Text broadcast requested: '{message}'. Consider using JSON broadcast or extending ConnectionManager.")
        # await manager.broadcast(message) # If ConnectionManager had a broadcast_text method
    else:
        logger.error("broadcast_message_to_clients: ConnectionManager not available via app_instance.state.")

async def broadcast_json_to_clients(data: dict, app_instance: Optional[Any] = None):
    """Helper to broadcast a JSON message if manager is accessible (e.g., via app_instance.state)."""
    if app_instance and hasattr(app_instance.state, 'connection_manager'):
        manager = app_instance.state.connection_manager
        await manager.broadcast_json(data)
    else:
        logger.error("broadcast_json_to_clients: ConnectionManager not available via app_instance.state.")


if __name__ == "__main__":
    # This block is for informational purposes; this module is not typically run directly.
    # The FastAPI application (main.py) manages the lifecycle of these components.
    logger.info(
        "WebSocket server module (websocket_server.py). "
        "This module defines WebSocket routes and connection management. "
        "It is run as part of the main FastAPI application (main.py)."
    )
