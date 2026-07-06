import asyncio
import json
import logging
from typing import Dict, Any, List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.repl.profiles import get_profile_manager
from src.sdk.agent_graph import get_agent_graph, DiscoveryType, Discovery

logger = logging.getLogger("api")

app = FastAPI(title="Cyber-CoPilot API")

# Allow Next.js frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── WebSocket Managers ───────────────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Error broadcasting message: {e}")

logs_manager = ConnectionManager()
graph_manager = ConnectionManager()

# Background task to poll AgentGraph/DiscoveryBus or just use callbacks
async def broadcast_discoveries():
    """Background task to broadcast discoveries if not using callbacks."""
    pass # We will use callbacks from DiscoveryBus

@app.on_event("startup")
async def startup_event():
    # Setup DiscoveryBus subscriber to push to WebSockets
    bus = get_agent_graph().discovery_bus
    
    def on_discovery(discovery: Discovery):
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
            
        data = {
            "event": "new_discovery",
            "data": discovery.to_dict()
        }
        asyncio.run_coroutine_threadsafe(graph_manager.broadcast(json.dumps(data)), loop)
        
        log_data = {
            "type": "finding",
            "message": f"[{discovery.type.value.upper()}] {discovery.source_agent} found {discovery.data.get('name', 'something')} on {discovery.target}"
        }
        asyncio.run_coroutine_threadsafe(logs_manager.broadcast(json.dumps(log_data)), loop)

    for dtype in DiscoveryType:
        bus.subscribe(dtype, on_discovery)
        
    # Hook into Runner callbacks for real-time thinking and tool logs
    from src.sdk.runner import Runner
    
    def push_log(log_type: str, message: str, agent: str = "System"):
        try:
            loop = asyncio.get_running_loop()
            data = {"type": log_type, "message": message, "agent": agent}
            asyncio.run_coroutine_threadsafe(logs_manager.broadcast(json.dumps(data)), loop)
        except RuntimeError:
            pass
            
    Runner.on_thinking = lambda agent, thinking: push_log("thinking", thinking, agent)
    Runner.on_command = lambda agent, tool, cmd: push_log("command", f"Running: {cmd}", agent)
    Runner.on_tool_end = lambda agent, tool, success, result: push_log(
        "success" if success else "error", 
        f"[{tool}] {'Success' if success else 'Failed'}", 
        agent
    )
    Runner.on_finding = lambda finding: push_log("finding", f"New Finding: {finding}", "System")


# ─── REST Endpoints ───────────────────────────────────────────────────────────

@app.get("/api/targets")
async def get_targets():
    """Return all target profiles."""
    pm = get_profile_manager()
    targets = []
    for t_name, profile in pm.profiles.items():
        from dataclasses import asdict
        targets.append(asdict(profile))
    return {"targets": targets}

class ScanRequest(BaseModel):
    target: str
    intent: str
    agents: List[str] = []

@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    """Start an async scan on the target."""
    graph = get_agent_graph()
    
    # Run the graph in the background
    asyncio.create_task(graph.run_graph_async(task=req.intent, target=req.target, agents=req.agents if req.agents else None))
    
    return {"status": "started", "target": req.target, "intent": req.intent}


# ─── WebSocket Endpoints ──────────────────────────────────────────────────────

@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    await logs_manager.connect(websocket)
    try:
        while True:
            # Keep alive and handle client messages if any
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        logs_manager.disconnect(websocket)

@app.websocket("/ws/graph")
async def websocket_graph(websocket: WebSocket):
    await graph_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        graph_manager.disconnect(websocket)


# ─── UI Compatibility Bridge Endpoints ────────────────────────────────────────

@app.get("/api/dashboard/stats")
async def get_dashboard_stats():
    return {
        "total_scans": 1, "active_scans": 1, "completed_scans": 0, "failed_scans": 0,
        "total_vulnerabilities": 0, "critical_vulnerabilities": 0, "high_vulnerabilities": 0,
        "medium_vulnerabilities": 0, "low_vulnerabilities": 0, "info_vulnerabilities": 0,
        "total_endpoints": 0, "active_agents": 1
    }

@app.get("/api/dashboard/recent")
async def get_dashboard_recent(limit: int = 5):
    return {"scans": []}

@app.get("/api/dashboard/activity-feed")
async def get_dashboard_activity(limit: int = 20):
    return {"activities": [], "total": 0}

@app.get("/api/agent/active")
async def get_agent_active():
    return {"agents": []}

@app.get("/api/agent/tasks")
async def get_agent_tasks():
    return {"tasks": []}

@app.post("/api/targets/validate/bulk")
async def validate_targets_bulk(targets: List[str]):
    return [{"valid": True, "normalized_url": t} for t in targets]

@app.post("/api/agent/run")
async def agent_run(req: Dict[str, Any]):
    target = req.get("target", "")
    intent = req.get("mode", "full_auto")
    prompt = req.get("prompt", "")
    if prompt:
        intent = prompt
        
    graph = get_agent_graph()
    # Deploy actual engine
    asyncio.create_task(graph.run_graph_async(task=intent, target=target))
    
    return {"agent_id": "local_framework_01", "status": "started", "message": "Agent dispatched"}

@app.get("/api/agent/{agent_id}")
async def get_agent_status(agent_id: str):
    return {
        "agent_id": agent_id, 
        "status": "running", 
        "findings": [], 
        "tool_executions": [],
        "phase": "Auditing"
    }

@app.get("/api/v1/settings")
async def get_settings():
    return {}

@app.get("/api/v1/settings/stats")
async def get_settings_stats():
    return {}

@app.get("/api/v1/knowledge/documents")
async def get_knowledge_documents():
    return {"documents": []}

@app.get("/api/v1/knowledge/stats")
async def get_knowledge_stats():
    return {}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
