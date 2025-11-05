"""
Incident Response Agent

This agent automates incident investigation, containment, and response
using LLM-powered analysis and decision-making.
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
from openai import OpenAI
import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IncidentSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentStatus(Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"


@dataclass
class IncidentTimeline:
    """Represents an event in the incident timeline"""
    timestamp: datetime
    event_type: str
    description: str
    actor: str  # system, agent, analyst

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'description': self.description,
            'actor': self.actor
        }


@dataclass
class Incident:
    """Represents a security incident"""
    incident_id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus
    created_at: datetime
    updated_at: datetime
    affected_assets: List[str]
    indicators: List[str]
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    timeline: List[IncidentTimeline]
    containment_actions: List[str]
    eradication_actions: List[str]
    root_cause: Optional[str]
    recommendations: List[str]
    assigned_to: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['severity'] = self.severity.value
        data['status'] = self.status.value
        data['created_at'] = self.created_at.isoformat()
        data['updated_at'] = self.updated_at.isoformat()
        data['timeline'] = [t.to_dict() for t in self.timeline]
        return data


class IncidentResponseAgent:
    """
    AI-powered incident response agent that automates investigation,
    containment, and remediation
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

        # Wazuh API configuration
        self.wazuh_url = os.getenv('WAZUH_API_URL')
        self.wazuh_token = None

        logger.info("Incident Response Agent initialized")

    def create_incident_from_alert(self, alert: Dict[str, Any]) -> Incident:
        """Create incident from threat alert"""
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}"

        # Determine severity
        severity_map = {
            'critical': IncidentSeverity.CRITICAL,
            'high': IncidentSeverity.HIGH,
            'medium': IncidentSeverity.MEDIUM,
            'low': IncidentSeverity.LOW
        }
        severity = severity_map.get(alert.get('severity', 'medium'), IncidentSeverity.MEDIUM)

        incident = Incident(
            incident_id=incident_id,
            title=alert.get('description', 'Security Incident'),
            description=alert.get('description', ''),
            severity=severity,
            status=IncidentStatus.NEW,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            affected_assets=[],
            indicators=alert.get('indicators', []),
            mitre_tactics=alert.get('mitre_tactics', []),
            mitre_techniques=alert.get('mitre_techniques', []),
            timeline=[
                IncidentTimeline(
                    timestamp=datetime.now(),
                    event_type='incident_created',
                    description='Incident created from threat detection',
                    actor='system'
                )
            ],
            containment_actions=[],
            eradication_actions=[],
            root_cause=None,
            recommendations=[],
            assigned_to='ai-agent'
        )

        logger.info(f"Created incident: {incident_id}")
        return incident

    def investigate_incident(self, incident: Incident) -> Dict[str, Any]:
        """
        Perform automated investigation using LLM
        """
        logger.info(f"Investigating incident: {incident.incident_id}")

        # Update status
        incident.status = IncidentStatus.INVESTIGATING
        incident.timeline.append(
            IncidentTimeline(
                timestamp=datetime.now(),
                event_type='investigation_started',
                description='Automated investigation initiated',
                actor='ai-agent'
            )
        )

        # Gather additional context
        context = self._gather_investigation_context(incident)

        # LLM-powered investigation
        investigation_results = self._llm_investigate(incident, context)

        # Update incident with findings
        incident.affected_assets = investigation_results.get('affected_assets', [])
        incident.root_cause = investigation_results.get('root_cause', '')

        incident.timeline.append(
            IncidentTimeline(
                timestamp=datetime.now(),
                event_type='investigation_completed',
                description=f"Investigation completed. Root cause: {incident.root_cause}",
                actor='ai-agent'
            )
        )

        logger.info(f"Investigation completed for {incident.incident_id}")
        return investigation_results

    def _gather_investigation_context(self, incident: Incident) -> Dict[str, Any]:
        """Gather additional context for investigation"""
        context = {
            'incident_details': incident.to_dict(),
            'recent_alerts': self._fetch_related_alerts(incident),
            'asset_information': self._fetch_asset_information(incident),
            'threat_intelligence': self._fetch_threat_intelligence(incident)
        }
        return context

    def _fetch_related_alerts(self, incident: Incident) -> List[Dict[str, Any]]:
        """Fetch related alerts from Wazuh"""
        # Mock implementation
        return [
            {
                'timestamp': datetime.now().isoformat(),
                'description': 'Related suspicious activity detected',
                'source': 'endpoint-security'
            }
        ]

    def _fetch_asset_information(self, incident: Incident) -> List[Dict[str, Any]]:
        """Fetch information about affected assets"""
        # Mock implementation
        return [
            {
                'hostname': 'webserver-01',
                'ip': '192.168.1.100',
                'os': 'Ubuntu 22.04',
                'criticality': 'high',
                'services': ['nginx', 'ssh']
            }
        ]

    def _fetch_threat_intelligence(self, incident: Incident) -> Dict[str, Any]:
        """Fetch relevant threat intelligence"""
        # Mock implementation
        return {
            'known_campaigns': [],
            'ioc_matches': len(incident.indicators),
            'threat_actors': []
        }

    def _llm_investigate(
        self,
        incident: Incident,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Use LLM to perform deep investigation"""

        prompt = f"""You are an expert incident responder. Analyze this security incident and provide:

1. Root cause analysis
2. Attack timeline reconstruction
3. Affected assets and systems
4. Blast radius assessment
5. Recommended containment actions (specific and actionable)
6. Recommended eradication steps
7. Recovery recommendations

Incident Details:
{json.dumps(context['incident_details'], indent=2)}

Additional Context:
- Recent Alerts: {len(context['recent_alerts'])} related alerts
- Asset Information: {json.dumps(context['asset_information'], indent=2)}
- Threat Intelligence: {json.dumps(context['threat_intelligence'], indent=2)}

Provide your analysis in JSON format with keys:
- root_cause: string
- attack_timeline: list of events
- affected_assets: list of hostnames
- blast_radius: string (contained/limited/widespread)
- containment_actions: list of specific actions
- eradication_actions: list of specific actions
- recovery_actions: list of specific actions
- confidence: float (0-1)
"""

        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are an expert cybersecurity incident responder with 20 years of experience."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                response_format={"type": "json_object"}
            )

            analysis = json.loads(response.choices[0].message.content)
            logger.info("LLM investigation completed")
            return analysis

        except Exception as e:
            logger.error(f"LLM investigation failed: {e}")
            return {
                'root_cause': 'Investigation failed',
                'attack_timeline': [],
                'affected_assets': [],
                'blast_radius': 'unknown',
                'containment_actions': ['Manual investigation required'],
                'eradication_actions': [],
                'recovery_actions': [],
                'confidence': 0.0
            }

    def contain_incident(self, incident: Incident, investigation: Dict[str, Any]) -> bool:
        """
        Execute automated containment actions
        """
        logger.info(f"Containing incident: {incident.incident_id}")

        containment_actions = investigation.get('containment_actions', [])

        incident.status = IncidentStatus.CONTAINED
        incident.timeline.append(
            IncidentTimeline(
                timestamp=datetime.now(),
                event_type='containment_started',
                description='Automated containment initiated',
                actor='ai-agent'
            )
        )

        # Execute containment actions
        for action in containment_actions:
            success = self._execute_containment_action(action, incident)
            incident.containment_actions.append(action)

            incident.timeline.append(
                IncidentTimeline(
                    timestamp=datetime.now(),
                    event_type='containment_action',
                    description=f"Executed: {action}",
                    actor='ai-agent'
                )
            )

        incident.timeline.append(
            IncidentTimeline(
                timestamp=datetime.now(),
                event_type='containment_completed',
                description=f"Executed {len(containment_actions)} containment actions",
                actor='ai-agent'
            )
        )

        logger.info(f"Containment completed for {incident.incident_id}")
        return True

    def _execute_containment_action(self, action: str, incident: Incident) -> bool:
        """Execute a specific containment action"""
        logger.info(f"Executing containment action: {action}")

        # Parse action and execute
        if "isolate" in action.lower() or "quarantine" in action.lower():
            return self._isolate_host(incident)
        elif "block ip" in action.lower():
            return self._block_ip_address(incident)
        elif "disable account" in action.lower():
            return self._disable_user_account(incident)
        else:
            logger.warning(f"Unknown containment action: {action}")
            return False

    def _isolate_host(self, incident: Incident) -> bool:
        """Isolate affected host from network"""
        # In production, integrate with Wazuh active response
        logger.info(f"Isolating hosts: {incident.affected_assets}")
        return True

    def _block_ip_address(self, incident: Incident) -> bool:
        """Block malicious IP addresses on firewall"""
        # In production, integrate with OPNsense API
        for indicator in incident.indicators:
            if "IP:" in indicator:
                ip = indicator.split("IP:")[1].strip()
                logger.info(f"Blocking IP: {ip}")
        return True

    def _disable_user_account(self, incident: Incident) -> bool:
        """Disable compromised user accounts"""
        # In production, integrate with AD/LDAP
        logger.info("Disabling compromised accounts")
        return True

    def generate_incident_report(self, incident: Incident) -> str:
        """Generate comprehensive incident report using LLM"""

        prompt = f"""Generate a professional incident response report for the following incident:

{json.dumps(incident.to_dict(), indent=2)}

Include:
1. Executive Summary
2. Incident Details
3. Timeline of Events
4. Technical Analysis
5. Actions Taken
6. Recommendations
7. Lessons Learned

Format as Markdown."""

        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are an expert technical writer specializing in security incident reports."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )

            report = response.choices[0].message.content
            return report

        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return "# Incident Report\n\nReport generation failed."

    def handle_incident(self, alert: Dict[str, Any]) -> Incident:
        """
        Main incident handling workflow:
        1. Create incident
        2. Investigate
        3. Contain
        4. Generate report
        """
        logger.info("Starting incident response workflow")

        # Create incident
        incident = self.create_incident_from_alert(alert)

        # Investigate
        investigation = self.investigate_incident(incident)

        # Auto-contain if severity is high or critical
        if incident.severity in [IncidentSeverity.CRITICAL, IncidentSeverity.HIGH]:
            self.contain_incident(incident, investigation)

        # Update recommendations
        incident.recommendations = investigation.get('recovery_actions', [])
        incident.updated_at = datetime.now()

        # Generate report
        report = self.generate_incident_report(incident)

        # Save report
        self._save_incident_report(incident, report)

        logger.info(f"Incident handling completed: {incident.incident_id}")
        return incident

    def _save_incident_report(self, incident: Incident, report: str) -> None:
        """Save incident report to disk"""
        try:
            report_dir = "/app/data/reports"
            os.makedirs(report_dir, exist_ok=True)

            filename = f"{report_dir}/{incident.incident_id}.md"
            with open(filename, 'w') as f:
                f.write(report)

            logger.info(f"Incident report saved: {filename}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")


def main():
    """Main execution"""
    agent = IncidentResponseAgent()

    # Mock alert for testing
    mock_alert = {
        'severity': 'high',
        'description': 'Multiple failed login attempts followed by successful login',
        'indicators': ['IP: 10.0.0.50', 'User: admin'],
        'mitre_tactics': ['Initial Access', 'Credential Access'],
        'mitre_techniques': ['T1110 - Brute Force', 'T1078 - Valid Accounts']
    }

    # Handle incident
    incident = agent.handle_incident(mock_alert)

    print("\n" + "="*80)
    print(f"INCIDENT RESPONSE COMPLETED")
    print(f"Incident ID: {incident.incident_id}")
    print(f"Status: {incident.status.value}")
    print(f"Severity: {incident.severity.value}")
    print(f"Root Cause: {incident.root_cause}")
    print(f"Containment Actions: {len(incident.containment_actions)}")
    print(f"Recommendations: {len(incident.recommendations)}")
    print("="*80)


if __name__ == "__main__":
    main()
