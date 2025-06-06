# /dashboard/backend/app.py

from fastapi import FastAPI, WebSocket, HTTPException, Depends, WebSocketDisconnect # Query, status
from fastapi.middleware.cors import CORSMiddleware # If frontend is on a different origin
from typing import List, Dict, Any
import asyncio # For WebSocket simulation
import random # For generating dummy data
import time # For timestamps

# Import the new API router
from .api_routes import router as ai_api_router

# Authentication imports
from fastapi.security import OAuth2PasswordRequestForm
from . import auth # This will import all names from auth.py
from datetime import timedelta


# The old get_current_active_user_placeholder is no longer needed
# as auth.py provides the actual get_current_active_user.
# async def get_current_active_user_placeholder(token: str = Depends(lambda x: x.headers.get("Authorization"))):
#     print(f"Simulated auth: Verifying token {token}")
#     if token == "Bearer valid_dashboard_user_token":
#         return {"username": "dashboard_user", "roles": ["analyst"]}
#     return {"username": "dashboard_user_placeholder", "roles": ["analyst_placeholder"]}


app = FastAPI(
    title="ZT Immune System Dashboard Backend",
    description="Provides APIs and WebSocket endpoints for the Zero Trust Immune System dashboard.",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

print("Initialisation du logger pour Dashboard Backend (app.py) (placeholder)")


simulated_alerts_db: List[Dict[str, Any]] = [
    {"id": "alert_1", "timestamp": time.time() - 300, "severity": "high", "description": "Critical RCE attempt detected on server X.", "source_ip": "1.2.3.4", "status": "new"},
    {"id": "alert_2", "timestamp": time.time() - 600, "severity": "medium", "description": "Suspicious login pattern for user 'bob'.", "source_ip": "10.0.0.5", "status": "acknowledged"},
]
active_websockets: List[WebSocket] = []


@app.get("/api/alerts", response_model=List[Dict[str, Any]])
async def get_alerts(
    skip: int = 0,
    limit: int = 10,
    # current_user: Dict = Depends(get_current_active_user_placeholder) # Authentication disabled for now
):
    print(f"API CALL: /api/alerts (user: placeholder_user)")
    sorted_alerts = sorted(simulated_alerts_db, key=lambda x: x["timestamp"], reverse=True)
    return sorted_alerts[skip : skip + limit]

@app.post("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    # current_user: Dict = Depends(get_current_active_user_placeholder) # Authentication disabled for now
):
    user_performing_action = "placeholder_user" # current_user.get("username")
    print(f"API CALL: /api/alerts/{alert_id}/acknowledge (user: {user_performing_action})")
    for alert in simulated_alerts_db:
        if alert["id"] == alert_id:
            alert["status"] = "acknowledged"
            alert["acknowledged_by"] = user_performing_action
            alert["acknowledged_at"] = time.time()
            await broadcast_message_to_websockets({"type": "alert_update", "alert": alert})
            return {"message": "Alert acknowledged", "alert": alert}
    raise HTTPException(status_code=404, detail="Alert not found")


@app.websocket("/api/agents/status")
async def websocket_agent_status(websocket: WebSocket):
    await websocket.accept()
    active_websockets.append(websocket)
    client_ip = websocket.client.host if websocket.client else "unknown_client"
    print(f"WebSocket client connected: {client_ip}")

    try:
        await websocket.send_json({"type": "connection_ack", "message": "Connected to agent status feed."})
        await websocket.send_json({"type": "initial_alerts", "alerts": simulated_alerts_db})

        while True:
            # This simple server primarily pushes; client messages could be handled here if needed.
            # Example: data = await websocket.receive_text()
            # print(f"Message from WebSocket client {client_ip}: {data}")
            await asyncio.sleep(1)

    except WebSocketDisconnect:
        print(f"WebSocket client disconnected: {client_ip}")
    except Exception as e:
        print(f"Error in WebSocket connection for {client_ip}: {type(e).__name__} - {e}")
    finally: # Ensure removal from active list on any exit
        if websocket in active_websockets:
            active_websockets.remove(websocket)


async def broadcast_message_to_websockets(message: Dict[str, Any]):
    print(f"Broadcasting to {len(active_websockets)} clients: {message.get('type')}")
    disconnected_clients: List[WebSocket] = []
    for connection in active_websockets:
        try:
            await connection.send_json(message)
        except Exception as e:
            print(f"Failed to send to a WebSocket client ({type(e).__name__}), marking for removal.")
            disconnected_clients.append(connection)

    for client_to_remove in disconnected_clients:
        if client_to_remove in active_websockets: # Check again in case it was removed by another task
            active_websockets.remove(client_to_remove)


async def simulate_events():
    print("Background event simulator started.")
    counter = 3
    while True:
        await asyncio.sleep(random.uniform(5, 15))

        new_alert_id = f"alert_{counter}"
        new_alert = {
            "id": new_alert_id,
            "timestamp": time.time(),
            "severity": random.choice(["low", "medium", "high", "critical"]),
            "description": f"Simulated event {counter} - {random.choice(['Firewall block', 'Malware detected', 'Policy violation', 'System anomaly'])}",
            "source_ip": f"10.0.1.{random.randint(1,254)}",
            "status": "new"
        }
        simulated_alerts_db.append(new_alert)
        print(f"SIMULATED NEW ALERT: {new_alert_id}")
        await broadcast_message_to_websockets({"type": "new_alert", "alert": new_alert})
        counter += 1


@app.on_event("startup")
async def startup_event():
    print("FastAPI app startup: Initializing background tasks...")
    asyncio.create_task(simulate_events())

# Token endpoint for authentication
@app.post("/token", response_model=auth.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = auth.authenticate_user(auth.fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401, # Corrected from status.HTTP_401_UNAUTHORIZED to an int
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.username, "scopes": user.roles}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Include the AI System Interaction API router
app.include_router(ai_api_router)

if __name__ == "__main__":
    import uvicorn
    print("Starting Uvicorn server for Dashboard Backend (app.py)...")
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")
