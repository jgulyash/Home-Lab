"""
Celery Tasks for Automated Security Workflows

These tasks implement automated security operations including
threat detection, incident response, intelligence gathering, etc.
"""

import os
import sys
import logging
from datetime import datetime
from typing import Dict, Any, List

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from workflows.celery_app import app
from agents.threat_detection.agent import ThreatDetectionAgent
from agents.incident_response.agent import IncidentResponseAgent
from agents.threat_intelligence.agent import ThreatIntelligenceAgent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@app.task(name='workflows.tasks.run_threat_detection')
def run_threat_detection() -> Dict[str, Any]:
    """
    Periodic threat detection workflow
    """
    logger.info("Starting automated threat detection")

    try:
        agent = ThreatDetectionAgent()
        threats = agent.run_detection()

        # If threats detected, trigger incident response
        for threat in threats:
            if threat.severity in ['critical', 'high']:
                logger.warning(f"High-severity threat detected: {threat.alert_id}")
                # Trigger incident response asynchronously
                handle_incident.delay(threat.to_dict())

        return {
            'status': 'success',
            'threats_detected': len(threats),
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Threat detection failed: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }


@app.task(name='workflows.tasks.handle_incident')
def handle_incident(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Automated incident response workflow
    """
    logger.info(f"Starting incident response for alert: {alert.get('alert_id')}")

    try:
        agent = IncidentResponseAgent()
        incident = agent.handle_incident(alert)

        return {
            'status': 'success',
            'incident_id': incident.incident_id,
            'severity': incident.severity.value,
            'actions_taken': len(incident.containment_actions),
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Incident response failed: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }


@app.task(name='workflows.tasks.run_threat_intelligence')
def run_threat_intelligence() -> Dict[str, Any]:
    """
    Periodic threat intelligence gathering workflow
    """
    logger.info("Starting threat intelligence cycle")

    try:
        agent = ThreatIntelligenceAgent()
        results = agent.run_intelligence_cycle()

        return {
            'status': 'success',
            'iocs_collected': results['iocs_collected'],
            'campaigns_identified': results['campaigns'],
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Threat intelligence cycle failed: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }


@app.task(name='workflows.tasks.run_vulnerability_scan')
def run_vulnerability_scan() -> Dict[str, Any]:
    """
    Automated vulnerability scanning workflow
    """
    logger.info("Starting vulnerability scan")

    try:
        # Import vulnerability agent
        from agents.vulnerability_management.agent import VulnerabilityAgent

        agent = VulnerabilityAgent()
        results = agent.run_scan()

        # If critical vulnerabilities found, create alerts
        if results.get('critical_vulns', 0) > 0:
            logger.warning(f"Critical vulnerabilities found: {results['critical_vulns']}")

        return {
            'status': 'success',
            'total_vulns': results.get('total_vulns', 0),
            'critical_vulns': results.get('critical_vulns', 0),
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Vulnerability scan failed: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }


@app.task(name='workflows.tasks.analyze_logs')
def analyze_logs(log_source: str, timeframe: str = '1h') -> Dict[str, Any]:
    """
    Automated log analysis using ML
    """
    logger.info(f"Analyzing logs from {log_source}")

    try:
        # This would integrate with your log analysis agent
        # For now, return mock results

        return {
            'status': 'success',
            'log_source': log_source,
            'events_analyzed': 1500,
            'anomalies_detected': 3,
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Log analysis failed: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }


@app.task(name='workflows.tasks.generate_daily_report')
def generate_daily_report() -> Dict[str, Any]:
    """
    Generate daily SOC operations report
    """
    logger.info("Generating daily SOC report")

    try:
        from workflows.reporting import generate_soc_report

        report = generate_soc_report()

        return {
            'status': 'success',
            'report_generated': True,
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }


@app.task(name='workflows.tasks.update_firewall_rules')
def update_firewall_rules(iocs: List[str]) -> Dict[str, Any]:
    """
    Automatically update firewall rules with new IOCs
    """
    logger.info(f"Updating firewall with {len(iocs)} IOCs")

    try:
        # This would integrate with OPNsense API
        # For now, return mock results

        blocked = []
        for ioc in iocs:
            # Parse IOC type and value
            if 'IP:' in ioc:
                ip = ioc.split('IP:')[1].strip()
                blocked.append(ip)
                logger.info(f"Blocked IP: {ip}")

        return {
            'status': 'success',
            'rules_added': len(blocked),
            'blocked_ips': blocked,
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Firewall update failed: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }


@app.task(name='workflows.tasks.health_check')
def health_check() -> Dict[str, Any]:
    """
    Health check for all agents and systems
    """
    logger.info("Running health check")

    health_status = {
        'timestamp': datetime.now().isoformat(),
        'services': {}
    }

    # Check agent health
    try:
        agent = ThreatDetectionAgent()
        health_status['services']['threat_detection'] = 'healthy'
    except Exception as e:
        health_status['services']['threat_detection'] = f'unhealthy: {str(e)}'

    try:
        agent = IncidentResponseAgent()
        health_status['services']['incident_response'] = 'healthy'
    except Exception as e:
        health_status['services']['incident_response'] = f'unhealthy: {str(e)}'

    try:
        agent = ThreatIntelligenceAgent()
        health_status['services']['threat_intelligence'] = 'healthy'
    except Exception as e:
        health_status['services']['threat_intelligence'] = f'unhealthy: {str(e)}'

    # Check if any service is unhealthy
    unhealthy = [k for k, v in health_status['services'].items() if v != 'healthy']

    if unhealthy:
        logger.warning(f"Unhealthy services: {unhealthy}")
        health_status['status'] = 'degraded'
    else:
        health_status['status'] = 'healthy'

    return health_status


@app.task(name='workflows.tasks.continuous_threat_hunting')
def continuous_threat_hunting(hypothesis: str) -> Dict[str, Any]:
    """
    Execute threat hunting hypothesis
    """
    logger.info(f"Executing threat hunt: {hypothesis}")

    try:
        from agents.threat_detection.agent import ThreatDetectionAgent

        agent = ThreatDetectionAgent()

        # Fetch recent logs
        alerts = agent.fetch_recent_alerts(hours=24)

        # Use LLM to hunt based on hypothesis
        results = agent.analyze_with_llm(alerts)

        return {
            'status': 'success',
            'hypothesis': hypothesis,
            'findings': results,
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Threat hunting failed: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }


# Workflow chains for complex operations
@app.task(name='workflows.tasks.full_security_assessment')
def full_security_assessment() -> Dict[str, Any]:
    """
    Run complete security assessment pipeline
    """
    logger.info("Starting full security assessment")

    results = {
        'assessment_id': f"ASSESS-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        'timestamp': datetime.now().isoformat(),
        'components': {}
    }

    try:
        # Run all assessment components
        threat_detection_result = run_threat_detection()
        results['components']['threat_detection'] = threat_detection_result

        threat_intel_result = run_threat_intelligence()
        results['components']['threat_intelligence'] = threat_intel_result

        vuln_scan_result = run_vulnerability_scan()
        results['components']['vulnerability_scan'] = vuln_scan_result

        results['status'] = 'completed'

    except Exception as e:
        logger.error(f"Full security assessment failed: {e}")
        results['status'] = 'failed'
        results['error'] = str(e)

    return results
