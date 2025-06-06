# ZT Immune System - IA Principale (Main AI)


![Gemini_Generated_Image_63xkd663xkd663xk](https://github.com/user-attachments/assets/6dfc739b-469a-431e-981f-c46dd8622eb6)




## Overview

The IA Principale (Main AI) is the central intelligence and orchestration hub of the ZT Immune System. It acts as the "brain" of the platform, responsible for:

-   Receiving and ingesting security alerts and events from various Mini-Agents via Kafka.
-   Analyzing and correlating these events to identify and evaluate potential threats.
-   Making decisions based on threat levels, system policies, and learned behaviors.
-   Orchestrating responses by dispatching tasks to appropriate Mini-Agents (e.g., for deeper analysis, containment, remediation, or further data collection for learning).
-   Providing a real-time communication interface via WebSockets for dashboards or other clients to receive alerts and send commands.
-   Continuously learning and adapting from new data and the outcomes of its decisions (future capability).

Key sub-modules within the IA Principale include:
-   **`Orchestrator`**: The core component that processes events, evaluates threats, and decides on actions.
-   **`DataIngestion`**: Includes Kafka consumer logic for the `alerts_raw` topic, feeding data into the Orchestrator.
-   **`Communication`**:
    -   `kafka_client.py`: Wrappers for Kafka producer and consumer functionalities.
    -   `websocket_server.py`: Manages WebSocket connections, authentication, and real-time message exchange.
-   **`Auth`**: Handles JWT-based authentication for secure API and WebSocket access.

## Technologies Used

-   **Python 3.9+**: The primary programming language.
-   **FastAPI**: For building the REST API and WebSocket endpoints.
-   **Uvicorn**: ASGI server to run the FastAPI application.
-   **`kafka-python`**: Python client for Apache Kafka.
-   **`python-jose[cryptography]`**: For JWT creation and validation.
-   **Pydantic**: For data validation and settings management (used by FastAPI).
-   **Various data processing and AI/ML libraries**: (Future) `pandas`, `numpy`, `scikit-learn`, `TensorFlow`/`PyTorch`.

## Prerequisites

-   **Python**: Version 3.9 or newer.
-   **`pip`**: The Python package installer.
-   **Virtual Environment (Recommended)**.
-   **Running Kafka Broker**: Essential for message bus operations.

## Project Setup and Installation

1.  **Navigate to the project root directory**:
    ```bash
    cd zt-immune-system
    ```

2.  **Create and activate a Python virtual environment**:
    ```bash
    python -m venv venv
    ```
    Activate:
    -   Linux/macOS: `source venv/bin/activate`
    -   Windows: `venv\Scripts\activate`

3.  **Install dependencies**:
    From the project root (`zt-immune-system`), install all dependencies listed in the main `requirements.txt`:
    ```bash
    pip install -r requirements.txt
    ```
    This file should include FastAPI, Uvicorn, kafka-python, python-jose, etc.

## Configuration

Configuration is primarily managed through environment variables. Key variables include:

-   **`KAFKA_BROKER_ADDRESS`**: Address(es) of Kafka brokers.
    -   Default: `"localhost:9092"`
-   **`JWT_SECRET_KEY`**: Secret key for encoding/decoding JWTs. **Must be changed for production.**
    -   Default: `"your-default-super-secret-key-for-dev"` (Highly insecure)
-   **`JWT_ALGORITHM`**: JWT signing algorithm.
    -   Default: `"HS256"`
-   **`JWT_ACCESS_TOKEN_EXPIRE_MINUTES`**: Expiry time for access tokens.
    -   Default: `30`
-   **`KAFKA_ALERTS_RAW_TOPIC`**: Topic for raw alerts consumed by the orchestrator.
    -   Default: `"alerts_raw"`
-   **`KAFKA_ALERTS_RAW_GROUP_ID`**: Consumer group ID for raw alerts.
    -   Default: `"orchestrator_alerts_group_1"`
-   **`KAFKA_USER_COMMANDS_TOPIC`**: Topic for user commands sent from WebSockets.
    -   Default: `"user_commands"`
-   **`KAFKA_FRONTEND_ALERTS_TOPIC`**: Topic for alerts to be broadcast to WebSocket clients.
    -   Default: `"frontend_alerts"`
-   **`KAFKA_FRONTEND_ALERTS_GROUP_ID`**: Consumer group ID for frontend alerts.
    -   Default: `"frontend_alerts_websocket_group"`

## Running the Main AI Server

1.  **Ensure Kafka is Running**.
2.  **Set Environment Variables** (as listed above, especially `KAFKA_BROKER_ADDRESS` and a secure `JWT_SECRET_KEY`).
    Example for Linux/macOS:
    ```bash
    export KAFKA_BROKER_ADDRESS="localhost:9092"
    export JWT_SECRET_KEY="a_very_strong_and_unique_secret_key_!@#$"
    # Add other variables as needed
    ```
3.  **Activate Virtual Environment** (if not already active).
4.  **Run the FastAPI Application using Uvicorn**:
    From the `zt-immune-system` project root:
    ```bash
    uvicorn zt_immune_system.ia_principale.main:app --reload --port 8000
    ```
    -   `--reload`: Enables auto-reloading for development. Uvicorn watches for code changes.
    -   `--port 8000`: Specifies the port to run on.

## Key Modules & Logic Flow

-   **`main.py`**:
    -   FastAPI application entry point.
    -   Manages lifecycle of background tasks (Kafka consumers, Orchestrator) using lifespan events.
    -   Initializes and shares `KafkaProducerWrapper` (for WebSocket commands) and `ConnectionManager` (for WebSockets) via `app.state`.
-   **`orchestrator.py`**:
    -   Core decision-making engine. Processes events from `alerts_raw` topic.
    -   Dispatches tasks to Mini-Agents via Kafka.
-   **`data_ingestion.py`**:
    -   `start_alerts_raw_consumer()`: Consumes from `alerts_raw` topic, feeds to `Orchestrator`.
-   **`communication/kafka_client.py`**:
    -   `KafkaProducerWrapper` and `KafkaConsumerWrapper` classes for Kafka interactions.
-   **`communication/websocket_server.py`**:
    -   Defines WebSocket endpoint (`/ws_comm/ws`).
    -   `ConnectionManager`: Manages active WebSocket connections and broadcasts.
    -   `start_frontend_alerts_kafka_consumer()`: Consumes from `frontend_alerts` topic and broadcasts to connected clients.
-   **`auth.py`**:
    -   Handles JWT creation and verification.
    -   Provides `get_current_user_ws` dependency for authenticating WebSocket connections.

---

## Real-time Communication API (WebSockets)

The IA Principale provides a WebSocket endpoint for real-time, bidirectional communication, primarily intended for dashboards or other monitoring/command clients.

### Running the Server
The WebSocket server is part of the main FastAPI application. Run the application as described in the "Running the Main AI Server" section:
```bash
uvicorn zt_immune_system.ia_principale.main:app --reload --port 8000
```

### Endpoint URL
The WebSocket endpoint is available at:
`ws://<host>:<port>/ws_comm/ws`
Example: `ws://localhost:8000/ws_comm/ws`

### Authentication
-   **Method:** JSON Web Token (JWT)
-   **Transmission:** The JWT must be provided as a query parameter named `token`.
    Example: `ws://localhost:8000/ws_comm/ws?token=YOUR_VALID_JWT_HERE`
-   **Token Acquisition:** Clients are expected to obtain a JWT through a separate authentication mechanism (e.g., a REST API login endpoint, which is not part of this specific `ia_principale` module but would be part of a complete ZT Immune System deployment). For development or testing, tokens can be generated using the `create_access_token` function in `auth.py` or other JWT tools.

### Message Format (Client-to-Server)
Clients should send messages to the server in JSON format. Each message must adhere to the following structure:

```json
{
  "type": "message_type_string",
  "data": {
    // Payload specific to the message 'type'
  },
  "timestamp": "optional_iso_datetime_string_utc"
  // Example: "2023-10-27T10:00:00Z" or "2023-10-27T10:00:00+00:00"
}
```
-   `type` (str): Defines the purpose or category of the message.
-   `data` (dict): A dictionary containing the actual payload for the message. The structure of `data` depends on the `type`.
-   `timestamp` (str, optional): An ISO 8601 formatted datetime string indicating when the message was created by the client (preferably in UTC).

### Key Client-to-Server Message Types

1.  **`user_command`**
    *   **Purpose:** Allows authenticated clients to send commands to the backend system (which are then relayed via Kafka).
    *   **`data` Structure Example:**
        ```json
        {
          "command_name": "block_ip", // Or "isolate_host", "run_scan", etc.
          "target_node_id": "host_xyz123", // Optional, depending on command
          "parameters": {
            "ip_address": "192.168.1.100", // Example parameter
            "duration_minutes": 60
          }
        }
        ```
    *   The server will acknowledge receipt and submission to Kafka (see Server-to-Client messages).

2.  **`echo`**
    *   **Purpose:** A simple message type for testing connectivity and message round-trip. The server will echo back the `data` and `timestamp` it receives.
    *   **`data` Structure Example:**
        ```json
        {
          "message": "Hello from client!",
          "any_other_data": "can be included"
        }
        ```

### Key Server-to-Client Message Types

The server will send JSON messages to connected clients.

1.  **`connection_ack`**
    *   **Purpose:** Sent by the server immediately after a successful WebSocket connection and authentication.
    *   **Payload Example:**
        ```json
        {
          "type": "connection_ack",
          "status": "Authentication successful",
          "user_id": "user_subject_from_jwt"
        }
        ```

2.  **`alert`**
    *   **Purpose:** Broadcasts real-time security alerts (consumed from the `frontend_alerts` Kafka topic) to all connected clients.
    *   **Payload Example (`data` field contains the actual alert from Kafka):**
        ```json
        {
          "type": "alert",
          "data": {
            // Structure of the alert consumed from Kafka
            "alert_id": "alert_uuid_12345",
            "severity": "high",
            "description": "Suspicious login attempt detected.",
            "source_ip": "10.0.0.5",
            "details": { /* ... more alert specific data ... */ }
          },
          "timestamp_utc": "server_iso_datetime_string_utc"
        }
        ```

3.  **`command_ack`**
    *   **Purpose:** Sent in response to a client's `user_command` message if the command was successfully submitted to the Kafka backend.
    *   **Payload Example:**
        ```json
        {
          "type": "command_ack",
          "command_name": "block_ip", // From the original command
          "status": "Command submitted to Kafka successfully.",
          "details": { /* Original data from client's command */ }
        }
        ```

4.  **`command_error`**
    *   **Purpose:** Sent if a `user_command` could not be processed or relayed to Kafka.
    *   **Payload Example:**
        ```json
        {
          "type": "command_error",
          "command_name": "block_ip",
          "status": "Failed to submit command to Kafka backend.",
          // Or "Command processing system unavailable."
          "details": { /* Original data from client's command */ }
        }
        ```

5.  **`echo_response`**
    *   **Purpose:** Sent in response to a client's `echo` message.
    *   **Payload Example:**
        ```json
        {
          "type": "echo_response",
          "original_data": { /* data from client's echo message */ },
          "original_timestamp": "client_iso_datetime_string_or_null"
        }
        ```

6.  **`error`** (General errors)
    *   **Purpose:** Sent for other types of errors, such as invalid message structure from the client, unsupported message types, etc.
    *   **Payload Example (Invalid Structure):**
        ```json
        {
          "type": "error",
          "message": "Invalid message structure.",
          "details": [ /* Pydantic validation error details */ ]
        }
        ```
    *   **Payload Example (Unsupported Type):**
        ```json
        {
          "type": "error",
          "message": "Message type 'some_unknown_type' is not supported."
        }
        ```

### Dependencies
Key Python libraries used for the WebSocket server include:
-   FastAPI (for WebSocket handling)
-   Uvicorn (ASGI server)
-   kafka-python (for Kafka communication)
-   python-jose[cryptography] (for JWT authentication)
-   Pydantic (for message validation)

Refer to the main `requirements.txt` in the project root for a complete list of dependencies.

---
*This README provides an overview specific to the IA Principale. For information about the entire ZT Immune System project, refer to the main README.md in the project root.*
