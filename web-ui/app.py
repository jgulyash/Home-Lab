"""
Web UI for AI-Powered Cybersecurity Lab

FastAPI-based web interface for monitoring agents and security operations.
"""

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime
import os
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="SecLab Control Panel", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models
class AgentStatus(BaseModel):
    name: str
    status: str
    last_run: str
    tasks_completed: int
    success_rate: float


class ThreatAlert(BaseModel):
    alert_id: str
    timestamp: str
    severity: str
    threat_type: str
    description: str
    status: str


class Incident(BaseModel):
    incident_id: str
    title: str
    severity: str
    status: str
    created_at: str


# Mock data (in production, query from database)
def get_dashboard_stats() -> Dict[str, Any]:
    return {
        'active_threats': 3,
        'incidents_today': 5,
        'critical_alerts': 1,
        'detection_rate': 87,
        'agents_running': 6,
        'iocs_collected': 247,
        'hunts_completed': 12,
        'vulnerabilities_found': 8
    }


def get_agent_statuses() -> List[AgentStatus]:
    return [
        AgentStatus(
            name="Threat Detection",
            status="running",
            last_run="2 minutes ago",
            tasks_completed=156,
            success_rate=98.5
        ),
        AgentStatus(
            name="Incident Response",
            status="running",
            last_run="5 minutes ago",
            tasks_completed=23,
            success_rate=100.0
        ),
        AgentStatus(
            name="Threat Intelligence",
            status="running",
            last_run="15 minutes ago",
            tasks_completed=48,
            success_rate=95.8
        ),
        AgentStatus(
            name="Threat Hunting",
            status="idle",
            last_run="1 hour ago",
            tasks_completed=12,
            success_rate=91.7
        ),
        AgentStatus(
            name="Red Team",
            status="idle",
            last_run="Never",
            tasks_completed=0,
            success_rate=0.0
        ),
        AgentStatus(
            name="Malware Analysis",
            status="running",
            last_run="30 minutes ago",
            tasks_completed=7,
            success_rate=100.0
        )
    ]


def get_recent_alerts() -> List[ThreatAlert]:
    return [
        ThreatAlert(
            alert_id="THREAT-20240501120000",
            timestamp=datetime.now().isoformat(),
            severity="high",
            threat_type="Brute Force",
            description="Multiple failed login attempts from 10.0.0.50",
            status="investigating"
        ),
        ThreatAlert(
            alert_id="THREAT-20240501115500",
            timestamp=datetime.now().isoformat(),
            severity="critical",
            threat_type="Malware",
            description="Ransomware detected on endpoint workstation-05",
            status="contained"
        ),
        ThreatAlert(
            alert_id="THREAT-20240501114500",
            timestamp=datetime.now().isoformat(),
            severity="medium",
            threat_type="Suspicious Activity",
            description="Unusual PowerShell execution pattern",
            status="resolved"
        )
    ]


def get_recent_incidents() -> List[Incident]:
    return [
        Incident(
            incident_id="INC-001",
            title="Brute force attack on web server",
            severity="high",
            status="investigating",
            created_at=datetime.now().isoformat()
        ),
        Incident(
            incident_id="INC-002",
            title="Suspicious PowerShell execution",
            severity="medium",
            status="contained",
            created_at=datetime.now().isoformat()
        ),
        Incident(
            incident_id="INC-003",
            title="Malware detected on endpoint",
            severity="critical",
            status="resolved",
            created_at=datetime.now().isoformat()
        )
    ]


# API Endpoints
@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve main dashboard"""
    html_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")

    if os.path.exists(html_path):
        with open(html_path, 'r') as f:
            return f.read()
    else:
        return """
        <html>
            <head><title>SecLab Control Panel</title></head>
            <body>
                <h1>SecLab Control Panel</h1>
                <p>Web UI is starting...</p>
                <p>API is available at <a href="/docs">/docs</a></p>
            </body>
        </html>
        """


@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.get("/api/dashboard/stats")
async def dashboard_stats():
    """Get dashboard statistics"""
    return get_dashboard_stats()


@app.get("/api/agents/status")
async def agents_status():
    """Get status of all agents"""
    return get_agent_statuses()


@app.get("/api/threats/recent")
async def recent_threats():
    """Get recent threat alerts"""
    return get_recent_alerts()


@app.get("/api/incidents/recent")
async def recent_incidents():
    """Get recent incidents"""
    return get_recent_incidents()


@app.post("/api/agents/{agent_name}/trigger")
async def trigger_agent(agent_name: str):
    """Trigger an agent to run"""
    logger.info(f"Triggering agent: {agent_name}")

    # In production, trigger via Celery
    return {
        "status": "triggered",
        "agent": agent_name,
        "task_id": f"task-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    }


@app.post("/api/hunt/start")
async def start_hunt(hypothesis: str = "General threat hunting"):
    """Start a threat hunt"""
    logger.info(f"Starting hunt: {hypothesis}")

    # In production, trigger hunt agent
    return {
        "status": "started",
        "hunt_id": f"HUNT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "hypothesis": hypothesis
    }


@app.post("/api/firewall/block-ip")
async def block_ip(ip: str):
    """Block an IP address"""
    logger.info(f"Blocking IP: {ip}")

    # In production, call firewall API
    return {
        "status": "blocked",
        "ip": ip,
        "rule_id": f"FW-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    }


@app.get("/api/reports/latest")
async def latest_reports():
    """Get latest reports"""
    reports_dir = "/app/data/reports"

    reports = []

    if os.path.exists(reports_dir):
        for root, dirs, files in os.walk(reports_dir):
            for file in files[:10]:  # Latest 10
                file_path = os.path.join(root, file)
                reports.append({
                    'filename': file,
                    'path': file_path,
                    'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                })

    return reports


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
