from fastapi import APIRouter, HTTPException, Depends
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from datetime import datetime, timedelta

from .auth import (
    # get_current_active_user, # Base dependency, not directly used if role-specific ones are used
    get_current_admin_user,
    get_current_analyst_user,
    # get_current_agent_user, # Uncomment if an endpoint needs this specific role
    # UserRoles, # Can be used for more complex role logic if needed
    User # For type hinting the injected current_user
)

# --- Pydantic Models ---

class AlertModel(BaseModel):
    id: str
    timestamp: datetime
    severity: str # e.g., "Low", "Medium", "High", "Critical"
    description: str
    source_ip: Optional[str] = None
    source_host: Optional[str] = None
    status: str # e.g., "new", "acknowledged", "in_progress", "resolved", "false_positive"
    details: Optional[Dict[str, Any]] = None

class AgentModel(BaseModel):
    agent_id: str
    status: str # e.g., "online", "offline", "error", "stale"
    last_seen: datetime
    type: str # e.g., "detection", "analysis", "response", "learning"
    version: Optional[str] = "1.0.0"
    ip_address: Optional[str] = None
    hostname: Optional[str] = None

class DecisionModel(BaseModel):
    decision_id: str
    timestamp: datetime
    target: str # e.g., IP address, user ID, process name, FQDN
    action: str # e.g., "block_ip", "isolate_host", "terminate_process", "quarantine_file", "log_and_monitor"
    reason: str # Brief explanation or link to alert/policy
    status: str # e.g., "pending", "executed", "failed", "rolled_back"
    triggered_by: str # e.g., "alert_001", "policy_xyz", "manual_command"

class IOCModel(BaseModel):
    ioc_id: str
    type: str # e.g., "ip_address", "domain_name", "file_hash_md5", "file_hash_sha256", "url"
    value: str
    first_seen: datetime
    last_seen: datetime
    source: Optional[str] = "internal_detection" # e.g., "misp_feed", "virustotal", "agent_det_001"
    confidence: Optional[float] = 0.5 # 0.0 to 1.0
    tags: Optional[List[str]] = []

class CommandModel(BaseModel):
    command: str # e.g., "scan_host", "get_agent_config", "update_rules", "block_ioc"
    target_node: Optional[str] = None # Could be an agent_id, a hostname, or a group tag
    parameters: Optional[Dict[str, Any]] = None

class CommandResponseModel(BaseModel):
    status: str # e.g., "received", "queued", "executing", "completed", "failed", "timeout"
    details: str
    command_id: Optional[str] = None
    results: Optional[Dict[str, Any]] = None # For commands that return data

class MISPFeedEventModel(BaseModel): # More specific model for MISP event structure (simplified)
    uuid: str
    info: str
    Attribute: List[Dict[str, Any]] # List of MISP attributes
    Tag: Optional[List[Dict[str, Any]]] = []

class MISPFeedModel(BaseModel):
    event_data: List[MISPFeedEventModel]

class StatusResponseModel(BaseModel):
    ai_status: str # e.g., "nominal", "degraded", "training", "error"
    active_agents: int
    kafka_status: str # e.g., "connected", "degraded", "disconnected"
    last_processed_alert_ts: Optional[datetime] = None
    alerts_in_queue: int = 0

# --- APIRouter ---
router = APIRouter(prefix="/api", tags=["AI System Interaction"])

# --- Placeholder Data & Helper Functions ---
# This data would typically come from a database or live system state
def generate_id(prefix: str = "item"):
    return f"{prefix}_{int(datetime.now().timestamp() * 1000)}_{int(datetime.now().microsecond / 1000)}"

_alerts_db: Dict[str, AlertModel] = {
    "alert_init_1": AlertModel(id="alert_init_1", timestamp=datetime.now() - timedelta(minutes=30), severity="High", description="Potential malware C2 communication detected from internal host.", source_ip="192.168.1.100", source_host="workstation-012", status="new", details={"protocol": "TCP", "destination_port": 4444, "matched_signature": "EvilTrafficRule_v1"}),
    "alert_init_2": AlertModel(id="alert_init_2", timestamp=datetime.now() - timedelta(hours=1), severity="Medium", description="Multiple failed login attempts for user 'admin' on 'auth-server-prod'.", source_ip="10.0.0.5", source_host="auth-server-prod", status="acknowledged", details={"target_user": "admin", "attempt_count": 15}),
    "alert_init_3": AlertModel(id="alert_init_3", timestamp=datetime.now() - timedelta(days=1), severity="Low", description="Outdated OpenSSL version detected on host 'srv-web-01'.", source_host="srv-web-01", status="in_progress", details={"current_version": "1.1.1g", "recommended_version": "1.1.1k"}),
}

_agents_db: Dict[str, AgentModel] = {
    "agent_det_001": AgentModel(agent_id="agent_det_001", status="online", last_seen=datetime.now() - timedelta(seconds=30), type="detection", version="1.1.0", ip_address="192.168.0.10", hostname="detector-primary"),
    "agent_ana_001": AgentModel(agent_id="agent_ana_001", status="online", last_seen=datetime.now() - timedelta(minutes=1), type="analysis", version="1.0.2", ip_address="192.168.0.11", hostname="analyzer-main"),
    "agent_res_001": AgentModel(agent_id="agent_res_001", status="offline", last_seen=datetime.now() - timedelta(hours=3), type="response", version="1.0.0", ip_address="192.168.0.12", hostname="responder-01"),
}

_decisions_db: Dict[str, DecisionModel] = {
    "dec_init_1": DecisionModel(decision_id="dec_init_1", timestamp=datetime.now() - timedelta(minutes=25), target="192.168.1.100", action="block_ip", reason="Associated with alert_init_1: High severity C2 communication.", status="executed", triggered_by="alert_init_1"),
    "dec_init_2": DecisionModel(decision_id="dec_init_2", timestamp=datetime.now() - timedelta(minutes=50), target="user:admin@auth-server-prod", action="force_mfa_reauth", reason="Associated with alert_init_2: Multiple failed logins.", status="pending", triggered_by="alert_init_2"),
}

_iocs_db: Dict[str, IOCModel] = {
    "ioc_init_1": IOCModel(ioc_id="ioc_init_1", type="ip_address", value="192.168.1.100", first_seen=datetime.now() - timedelta(days=1), last_seen=datetime.now() - timedelta(minutes=30), source="agent_det_001", confidence=0.8, tags=["c2_traffic", "internal_compromise"]),
    "ioc_init_2": IOCModel(ioc_id="ioc_init_2", type="domain_name", value="evil-domain-placeholder.com", first_seen=datetime.now() - timedelta(hours=5), last_seen=datetime.now() - timedelta(hours=1), source="misp_feed_xyz", confidence=0.6, tags=["phishing", "malware_distribution"]),
}

# --- GET Endpoints ---

@router.get("/status", response_model=StatusResponseModel)
async def get_system_status(current_user: User = Depends(get_current_analyst_user)):
    """Retrieves the current operational status of the AI system. Requires Analyst role."""
    print(f"User '{current_user.username}' (roles: {current_user.roles}) accessed /status.")
    online_agents = len([agent for agent in _agents_db.values() if agent.status == "online"])
    return StatusResponseModel(
        ai_status="nominal",
        active_agents=online_agents,
        kafka_status="connected", # This would be dynamically checked
        last_processed_alert_ts=max(alert.timestamp for alert in _alerts_db.values()) if _alerts_db else None,
        alerts_in_queue=0 # This would come from Kafka/Orchestrator
    )

@router.get("/alerts", response_model=List[AlertModel])
async def get_recent_alerts(limit: int = 10, status: Optional[str] = None, current_user: User = Depends(get_current_analyst_user)):
    """Retrieves a list of recent alerts. Requires Analyst role."""
    print(f"User '{current_user.username}' (roles: {current_user.roles}) accessed /alerts.")
    alerts = sorted(_alerts_db.values(), key=lambda a: a.timestamp, reverse=True)
    if status:
        alerts = [alert for alert in alerts if alert.status == status]
    return alerts[:limit]

@router.get("/alerts/{alert_id}", response_model=AlertModel)
async def get_alert_details(alert_id: str, current_user: User = Depends(get_current_analyst_user)):
    """Retrieves details for a specific alert by its ID. Requires Analyst role."""
    print(f"User '{current_user.username}' (roles: {current_user.roles}) accessed /alerts/{alert_id}.")
    alert = _alerts_db.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert with ID '{alert_id}' not found.")
    return alert

@router.get("/agents", response_model=List[AgentModel])
async def list_registered_agents(status_filter: Optional[str] = None, current_user: User = Depends(get_current_analyst_user)):
    """Lists all registered Mini-Agents and their status. Requires Analyst role."""
    print(f"User '{current_user.username}' (roles: {current_user.roles}) accessed /agents.")
    agents = list(_agents_db.values())
    if status_filter:
        agents = [agent for agent in agents if agent.status == status_filter]
    return agents

@router.get("/agents/{agent_id}/logs", response_model=List[str])
async def get_agent_logs(agent_id: str, limit: int = 50, current_user: User = Depends(get_current_analyst_user)):
    """Retrieves recent logs for a specific agent (placeholder). Requires Analyst role."""
    print(f"User '{current_user.username}' (roles: {current_user.roles}) accessed /agents/{agent_id}/logs.")
    if agent_id not in _agents_db:
        raise HTTPException(status_code=404, detail=f"Agent with ID '{agent_id}' not found.")
    # Placeholder logs - in reality, this would fetch from a logging system or the agent itself
    return [
        f"{datetime.now() - timedelta(seconds=s*10)}: Log entry {5-s} for agent {agent_id}" for s in range(min(5, limit))
    ][:limit]

@router.get("/decisions", response_model=List[DecisionModel])
async def list_ai_decisions(limit: int = 10, target: Optional[str] = None, current_user: User = Depends(get_current_analyst_user)):
    """Lists recent automated decisions made by the AI. Requires Analyst role."""
    print(f"User '{current_user.username}' (roles: {current_user.roles}) accessed /decisions.")
    decisions = sorted(_decisions_db.values(), key=lambda d: d.timestamp, reverse=True)
    if target:
        decisions = [d for d in decisions if target in d.target]
    return decisions[:limit]

@router.get("/intel/iocs", response_model=List[IOCModel])
async def get_iocs(limit: int = 20, ioc_type: Optional[str] = None, source: Optional[str] = None, current_user: User = Depends(get_current_analyst_user)):
    """Retrieves observed or ingested Indicators of Compromise (IOCs). Requires Analyst role."""
    print(f"User '{current_user.username}' (roles: {current_user.roles}) accessed /intel/iocs.")
    iocs = sorted(_iocs_db.values(), key=lambda i: i.last_seen, reverse=True)
    if ioc_type:
        iocs = [i for i in iocs if i.type == ioc_type]
    if source:
        iocs = [i for i in iocs if i.source == source]
    return iocs[:limit]

# --- POST Endpoints ---

@router.post("/commands", response_model=CommandResponseModel)
async def execute_ai_command(cmd: CommandModel, current_user: User = Depends(get_current_admin_user)):
    """
    Sends a command to the AI system (e.g., to an agent or the orchestrator).
    Requires Admin role.
    """
    print(f"API: User '{current_user.username}' (roles: {current_user.roles}) executing command: {cmd.command} for target {cmd.target_node} with params {cmd.parameters}.")
    # In a real system, this would likely send a message via Kafka to the orchestrator or directly to an agent.
    command_id = generate_id("cmd")
    # Simulate command processing
    _decisions_db[command_id] = DecisionModel(
        decision_id=command_id,
        timestamp=datetime.now(),
        target=cmd.target_node or "system",
        action=cmd.command,
        reason=f"Manual command via API: {cmd.parameters.get('reason', 'N/A') if cmd.parameters else 'N/A'}",
        status="queued", # Or "executing" if direct
        triggered_by="api_user"
    )
    return CommandResponseModel(
        status="queued",
        details=f"Command '{cmd.command}' for target '{cmd.target_node or 'orchestrator'}' received and queued.",
        command_id=command_id
    )

@router.post("/intel/misp_feed", response_model=Dict[str, Any])
async def ingest_misp_feed(feed: MISPFeedModel):
    """Allows ingestion of a MISP (or similar threat intel) feed."""
    print(f"API: Received MISP feed with {len(feed.event_data)} events.")
    items_ingested_count = 0
    for event in feed.event_data:
        # Simulate processing each event and extracting attributes as IOCs
        for attribute in event.Attribute:
            if attribute.get("value") and attribute.get("type"):
                ioc_id = generate_id("ioc_misp")
                _iocs_db[ioc_id] = IOCModel(
                    ioc_id=ioc_id,
                    type=attribute["type"],
                    value=attribute["value"],
                    first_seen=datetime.fromisoformat(attribute.get("firstseen")) if attribute.get("firstseen") else datetime.now(), # MISP uses 'firstseen'
                    last_seen=datetime.fromisoformat(attribute.get("lastseen")) if attribute.get("lastseen") else datetime.now(), # MISP uses 'lastseen'
                    source=f"misp_event_{event.uuid}",
                    confidence=float(attribute.get("confidence", 0.5)), # MISP might have confidence
                    tags=[tag.get("name") for tag in event.Tag if tag.get("name")] + [attribute.get("category")]
                )
                items_ingested_count +=1
    return {"status": "received", "events_processed": len(feed.event_data), "iocs_extracted": items_ingested_count}

# Example of how to run this router with Uvicorn for testing:
# if __name__ == "__main__":
#     import uvicorn
#     from fastapi import FastAPI
#
#     app = FastAPI(title="ZT-Immune System Dashboard API")
#     app.include_router(router)
#     # uvicorn.run(app, host="0.0.0.0", port=8001) # Port for API, dashboard might be on 8000 or 3000
#     # To run: uvicorn zt-immune-system.dashboard.backend.api_routes:app --reload --port 8001
#     # Ensure this file is runnable in that context or adjust path.
#     # Typically, app instance is in app.py and uvicorn runs that.
#     pass # main block is usually in app.py
