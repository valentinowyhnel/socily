import pytest
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, List

from fastapi import WebSocketException, status
from pydantic import ValidationError

# Adjust imports based on your project structure
from zt_immune_system.ia_principale.communication.websocket_server import (
    WebSocketMessage,
    ConnectionManager,
    # websocket_server_router # Router needed if testing it directly, but TestClient uses app
)
from zt_immune_system.ia_principale.main import app # For TestClient
from zt_immune_system.ia_principale.auth import create_access_token # For generating test tokens

# Mock WebSocket class for unit testing ConnectionManager
class MockWebSocket:
    def __init__(self, client_host="testclient", client_port=12345, app_state=None):
        self.client = (client_host, client_port)
        self.accepted = False
        self.closed = False
        self.close_code = None
        self.close_reason = None
        self.sent_jsons: List[Dict[str, Any]] = []
        self.app = type('AppState', (object,), {"state": app_state or {}})() # Mock app with state


    async def accept(self):
        self.accepted = True

    async def send_json(self, data: dict):
        if self.closed:
            raise Exception("Cannot send on a closed WebSocket")
        self.sent_jsons.append(data)

    async def send_text(self, data: str): # Required by some error paths in endpoint
        if self.closed:
            raise Exception("Cannot send on a closed WebSocket")
        # For simplicity, we'll just store text messages as JSON if needed for inspection
        self.sent_jsons.append({"type": "text_message", "content": data})


    async def receive_json(self) -> Dict[str, Any]:
        # This needs to be provided by the test if messages are expected to be received
        # For now, ConnectionManager tests don't require receiving.
        # The endpoint integration tests will handle actual message sending/receiving.
        pass

    async def close(self, code: int = status.WS_1000_NORMAL_CLOSURE, reason: str = None):
        self.closed = True
        self.close_code = code
        self.close_reason = reason
        # print(f"MockWebSocket closed with code {code}, reason: {reason}")


# --- Pydantic Model Tests ---
def test_websocket_message_valid():
    data = {"type": "test_type", "data": {"key": "value"}, "timestamp": datetime.now().isoformat()}
    msg = WebSocketMessage(**data)
    assert msg.type == "test_type"
    assert msg.data["key"] == "value"
    assert isinstance(msg.timestamp, datetime)

def test_websocket_message_missing_required_field():
    with pytest.raises(ValidationError):
        WebSocketMessage(data={"key": "value"}) # Missing 'type'

def test_websocket_message_invalid_data_type():
    with pytest.raises(ValidationError):
        WebSocketMessage(type="test", data="not a dict")

def test_websocket_message_timestamp_optional():
    data = {"type": "test_type", "data": {"key": "value"}}
    msg = WebSocketMessage(**data)
    assert msg.timestamp is None


# --- ConnectionManager Unit Tests ---
@pytest.mark.asyncio
async def test_connection_manager_connect_disconnect():
    manager = ConnectionManager()
    mock_ws1 = MockWebSocket()
    mock_ws2 = MockWebSocket()

    assert len(manager.active_connections) == 0
    # await mock_ws1.accept() # accept is called by manager.connect now in the refactored manager
    await manager.connect(mock_ws1, "user1")
    assert len(manager.active_connections) == 1
    assert (mock_ws1, "user1") in manager.active_connections

    # await mock_ws2.accept()
    await manager.connect(mock_ws2, "user2")
    assert len(manager.active_connections) == 2
    assert (mock_ws2, "user2") in manager.active_connections

    manager.disconnect(mock_ws1)
    assert len(manager.active_connections) == 1
    assert (mock_ws1, "user1") not in manager.active_connections
    assert (mock_ws2, "user2") in manager.active_connections

    manager.disconnect(mock_ws2)
    assert len(manager.active_connections) == 0

def test_connection_manager_disconnect_non_existent():
    manager = ConnectionManager()
    mock_ws = MockWebSocket()
    # No error should be raised, just a warning logged (tested implicitly by not raising)
    manager.disconnect(mock_ws)
    assert len(manager.active_connections) == 0


@pytest.mark.asyncio
async def test_connection_manager_send_personal_json():
    manager = ConnectionManager()
    mock_ws = MockWebSocket()
    # await mock_ws.accept() # Not needed as manager.connect does it
    # await manager.connect(mock_ws, "user1") # Not strictly needed for send_personal_json if called directly

    test_payload = {"message": "hello"}
    await manager.send_personal_json(test_payload, mock_ws, "user1")
    assert len(mock_ws.sent_jsons) == 1
    assert mock_ws.sent_jsons[0] == test_payload

@pytest.mark.asyncio
async def test_connection_manager_broadcast_json():
    manager = ConnectionManager()
    mock_ws1 = MockWebSocket()
    mock_ws2 = MockWebSocket()

    # await mock_ws1.accept()
    await manager.connect(mock_ws1, "user1")
    # await mock_ws2.accept()
    await manager.connect(mock_ws2, "user2")

    broadcast_payload = {"type": "broadcast", "content": "test broadcast"}
    await manager.broadcast_json(broadcast_payload)

    assert len(mock_ws1.sent_jsons) == 1
    assert mock_ws1.sent_jsons[0] == broadcast_payload
    assert len(mock_ws2.sent_jsons) == 1
    assert mock_ws2.sent_jsons[0] == broadcast_payload

@pytest.mark.asyncio
async def test_connection_manager_broadcast_json_handles_send_errors():
    manager = ConnectionManager()
    mock_ws_ok = MockWebSocket(client_host="ok_client")
    mock_ws_fail = MockWebSocket(client_host="fail_client")

    # await mock_ws_ok.accept()
    await manager.connect(mock_ws_ok, "user_ok")
    # await mock_ws_fail.accept()
    await manager.connect(mock_ws_fail, "user_fail")

    # Make one of the WebSockets fail on send_json
    async def mock_send_json_fail(data: dict):
        raise Exception("Simulated send failure")
    mock_ws_fail.send_json = mock_send_json_fail

    broadcast_payload = {"type": "critical_update", "content": "important info"}
    await manager.broadcast_json(broadcast_payload)

    # Check that the message was sent to the OK client
    assert len(mock_ws_ok.sent_jsons) == 1
    assert mock_ws_ok.sent_jsons[0] == broadcast_payload

    # Check that the failing client was disconnected
    assert (mock_ws_fail, "user_fail") not in manager.active_connections
    assert len(manager.active_connections) == 1 # Only mock_ws_ok should remain


# --- WebSocket Endpoint Integration Tests (using TestClient) ---

# Fixtures for tokens are in conftest.py (valid_jwt_token_for_test_user, expired_jwt_token_for_test_user)

def test_websocket_connect_valid_token(test_client_instance, valid_jwt_token_for_test_user):
    """Test successful WebSocket connection with a valid JWT."""
    with test_client_instance.websocket_connect(f"/ws_comm/ws?token={valid_jwt_token_for_test_user}") as websocket:
        response = websocket.receive_json() # First message should be connection_ack
        assert response["type"] == "connection_ack"
        assert response["status"] == "Authentication successful"
        assert response["user_id"] == "testuser@example.com" # From the 'sub' claim in valid_jwt_token
        # Can send a test message if desired
        # websocket.send_json({"type": "echo", "data": {"test": "hello"}})
        # echo_response = websocket.receive_json()
        # assert echo_response["type"] == "echo_response"

def test_websocket_connect_missing_token(test_client_instance):
    """Test WebSocket connection rejection if token is missing."""
    with pytest.raises(WebSocketException) as exc_info: # TestClient raises WebSocketException on protocol errors
        with test_client_instance.websocket_connect("/ws_comm/ws"):
            pass # Should not connect
    # FastAPI's TestClient behavior for failed WebSocket connections might not always
    # let us inspect the close code directly in the same way a live client would.
    # The fact that it raises WebSocketException on failed handshake is the primary check.
    # For specific close codes, you might need to inspect logs or use a real WebSocket client for tests.
    # However, we can try to assert the type of exception if TestClient wraps it.
    # Based on FastAPI/Starlette, a 403 might be raised before WS upgrade for auth failures.
    # Or WebSocketException with specific close codes if the connection is established then closed.
    # Let's assume it will be a WebSocketException related to the auth process.
    # The auth dependency calls `websocket.close(code=status.WS_1008_POLICY_VIOLATION)`
    # Starlette's TestClient websocket_connect context manager will raise WebSocketDisconnect
    # if the server closes the connection during the handshake or immediately after.
    # The actual exception might be starlette.websockets.WebSocketDisconnect.
    # For now, checking for a general WebSocket related exception from FastAPI/Starlette is a start.
    assert exc_info.type is WebSocketException # Or potentially starlette.websockets.WebSocketDisconnect

def test_websocket_connect_invalid_token(test_client_instance):
    """Test WebSocket connection rejection with an invalid JWT."""
    invalid_token = "this.is.a.very.invalid.token"
    with pytest.raises(WebSocketException):
        with test_client_instance.websocket_connect(f"/ws_comm/ws?token={invalid_token}"):
            pass

def test_websocket_connect_expired_token(test_client_instance, expired_jwt_token_for_test_user):
    """Test WebSocket connection rejection with an expired JWT."""
    with pytest.raises(WebSocketException):
        with test_client_instance.websocket_connect(f"/ws_comm/ws?token={expired_jwt_token_for_test_user}"):
            pass

@pytest.mark.asyncio # For TestClient's websocket operations if used with async parts
async def test_websocket_echo_message(test_client_instance, valid_jwt_token_for_test_user):
    """Test sending an 'echo' type message and receiving the echo response."""
    # Note: TestClient's websocket_connect is synchronous in its context manager use,
    # but send/receive operations on the 'websocket' object can be async if the server is.
    # Pytest-asyncio handles this if the test function is marked async.

    # Using the synchronous context manager for setup
    with test_client_instance.websocket_connect(f"/ws_comm/ws?token={valid_jwt_token_for_test_user}") as websocket:
        ack = websocket.receive_json() # Consume the ack
        assert ack["type"] == "connection_ack"

        timestamp_original = datetime.now(timezone.utc)
        test_echo_data = {"type": "echo", "data": {"message": "Hello WebSocket"}, "timestamp": timestamp_original.isoformat()}
        websocket.send_json(test_echo_data)

        response = websocket.receive_json()
        assert response["type"] == "echo_response"
        assert response["original_data"] == test_echo_data["data"]
        assert response["original_timestamp"] == timestamp_original.isoformat()

# Conceptual test for broadcasting - would require more setup (e.g., mocking Kafka consumer to trigger broadcast)
# @pytest.mark.asyncio
# async def test_websocket_receives_broadcast(test_client_instance, valid_jwt_token_for_test_user):
#     async with test_client_instance.websocket_connect(f"/ws_comm/ws?token={valid_jwt_token_for_test_user}") as websocket1:
#         async with test_client_instance.websocket_connect(f"/ws_comm/ws?token={valid_jwt_token_for_test_user}") as websocket2: # Needs a different token or user for distinctness if manager keys by user
#             ack1 = await websocket1.receive_json()
#             ack2 = await websocket2.receive_json()
#
#             # This part needs to trigger a broadcast from the server side.
#             # e.g., by mocking the Kafka consumer that feeds into ConnectionManager.broadcast_json
#             # For example, if there was an HTTP endpoint to trigger a test broadcast:
#             # test_client_instance.post("/trigger_broadcast", json={"message": "hello all"})
#             # Or, more directly, if we can access the manager from the test_client_instance.app.state:
#             # await test_client_instance.app.state.connection_manager.broadcast_json({"type": "test_bcast", "data": "content"})
#
#             # Then check if both clients received it
#             # broadcast_msg1 = await websocket1.receive_json(timeout=1) # Add timeout
#             # broadcast_msg2 = await websocket2.receive_json(timeout=1)
#             # assert broadcast_msg1["type"] == "test_bcast"
#             # assert broadcast_msg2["type"] == "test_bcast"
#     pass

# Note: The TestClient runs the app in the same process, so app.state can be accessed if needed,
# but direct manipulation of state during tests should be done carefully.
# Mocking dependencies (like Kafka clients) at the boundary is often cleaner for unit/integration tests.
# E.g., using `app.dependency_overrides` for FastAPI dependencies, or `unittest.mock.patch` for others.
```
