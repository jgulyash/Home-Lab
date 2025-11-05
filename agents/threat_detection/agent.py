"""
Threat Detection Agent

This agent uses ML and LLM to detect threats in security logs and events.
It performs anomaly detection, pattern recognition, and behavioral analysis.
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from openai import OpenAI
import requests
from dataclasses import dataclass, asdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ThreatAlert:
    """Represents a detected threat"""
    alert_id: str
    timestamp: datetime
    severity: str  # critical, high, medium, low
    threat_type: str
    description: str
    indicators: List[str]
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    confidence: float
    raw_events: List[Dict[str, Any]]
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data


class ThreatDetectionAgent:
    """
    AI-powered threat detection agent that combines ML and LLM
    for comprehensive security event analysis
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

        # ML Model for anomaly detection
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.scaler = StandardScaler()
        self.is_trained = False

        # Wazuh API configuration
        self.wazuh_url = os.getenv('WAZUH_API_URL')
        self.wazuh_user = os.getenv('WAZUH_API_USER')
        self.wazuh_password = os.getenv('WAZUH_API_PASSWORD')
        self.wazuh_token = None

        logger.info("Threat Detection Agent initialized")

    def authenticate_wazuh(self) -> None:
        """Authenticate with Wazuh API"""
        if not self.wazuh_url:
            logger.warning("Wazuh URL not configured")
            return

        try:
            response = requests.post(
                f"{self.wazuh_url}/security/user/authenticate",
                auth=(self.wazuh_user, self.wazuh_password),
                verify=False
            )
            response.raise_for_status()
            self.wazuh_token = response.json()['data']['token']
            logger.info("Successfully authenticated with Wazuh")
        except Exception as e:
            logger.error(f"Failed to authenticate with Wazuh: {e}")

    def fetch_recent_alerts(self, hours: int = 1) -> List[Dict[str, Any]]:
        """Fetch recent alerts from Wazuh"""
        if not self.wazuh_token:
            self.authenticate_wazuh()

        if not self.wazuh_token:
            # Return mock data for testing
            return self._generate_mock_alerts()

        try:
            headers = {'Authorization': f'Bearer {self.wazuh_token}'}
            params = {
                'limit': 1000,
                'sort': '-timestamp'
            }

            response = requests.get(
                f"{self.wazuh_url}/alerts",
                headers=headers,
                params=params,
                verify=False
            )
            response.raise_for_status()
            return response.json()['data']['affected_items']
        except Exception as e:
            logger.error(f"Failed to fetch alerts: {e}")
            return []

    def _generate_mock_alerts(self) -> List[Dict[str, Any]]:
        """Generate mock alerts for testing"""
        return [
            {
                'id': '1',
                'timestamp': datetime.now().isoformat(),
                'rule': {'description': 'Multiple authentication failures', 'level': 10},
                'agent': {'name': 'webserver-01', 'ip': '192.168.1.100'},
                'data': {'srcip': '10.0.0.50', 'srcuser': 'admin'}
            },
            {
                'id': '2',
                'timestamp': datetime.now().isoformat(),
                'rule': {'description': 'Suspicious process execution', 'level': 12},
                'agent': {'name': 'workstation-05', 'ip': '192.168.1.105'},
                'data': {'process': 'powershell.exe', 'command': 'Invoke-WebRequest'}
            }
        ]

    def extract_features(self, alerts: List[Dict[str, Any]]) -> pd.DataFrame:
        """Extract numerical features from alerts for ML analysis"""
        features = []

        for alert in alerts:
            rule = alert.get('rule', {})
            data = alert.get('data', {})

            feature = {
                'rule_level': rule.get('level', 0),
                'hour_of_day': pd.to_datetime(alert.get('timestamp')).hour,
                'has_srcip': 1 if data.get('srcip') else 0,
                'has_dstip': 1 if data.get('dstip') else 0,
                'has_srcuser': 1 if data.get('srcuser') else 0,
            }
            features.append(feature)

        return pd.DataFrame(features)

    def detect_anomalies(self, alerts: List[Dict[str, Any]]) -> List[int]:
        """
        Use ML to detect anomalous alerts
        Returns list of indices of anomalous alerts
        """
        if len(alerts) < 10:
            logger.warning("Not enough alerts for anomaly detection")
            return []

        # Extract features
        features_df = self.extract_features(alerts)

        # Train model if not trained (in production, load pre-trained model)
        if not self.is_trained:
            features_scaled = self.scaler.fit_transform(features_df)
            self.anomaly_detector.fit(features_scaled)
            self.is_trained = True
        else:
            features_scaled = self.scaler.transform(features_df)

        # Predict anomalies (-1 for anomalies, 1 for normal)
        predictions = self.anomaly_detector.predict(features_scaled)
        anomaly_indices = [i for i, pred in enumerate(predictions) if pred == -1]

        logger.info(f"Detected {len(anomaly_indices)} anomalous alerts")
        return anomaly_indices

    def analyze_with_llm(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Use LLM to perform deep behavioral analysis on alerts
        """
        # Prepare context for LLM
        context = self._prepare_llm_context(alerts)

        prompt = f"""You are a cybersecurity threat analyst. Analyze the following security alerts and provide:
1. Threat assessment (severity: critical/high/medium/low)
2. Attack pattern identification
3. MITRE ATT&CK tactics and techniques
4. Indicators of Compromise (IOCs)
5. Recommended actions

Security Alerts:
{json.dumps(context, indent=2)}

Provide your analysis in JSON format with keys: severity, threat_type, description, mitre_tactics, mitre_techniques, iocs, recommendations"""

        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are an expert cybersecurity threat analyst with deep knowledge of MITRE ATT&CK framework."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                response_format={"type": "json_object"}
            )

            analysis = json.loads(response.choices[0].message.content)
            logger.info("LLM analysis completed")
            return analysis

        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return {
                'severity': 'medium',
                'threat_type': 'unknown',
                'description': 'Automated analysis failed',
                'mitre_tactics': [],
                'mitre_techniques': [],
                'iocs': [],
                'recommendations': 'Manual investigation required'
            }

    def _prepare_llm_context(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prepare alerts context for LLM analysis"""
        context = []
        for alert in alerts[:10]:  # Limit to avoid token limits
            context.append({
                'id': alert.get('id'),
                'timestamp': alert.get('timestamp'),
                'rule': alert.get('rule', {}).get('description'),
                'level': alert.get('rule', {}).get('level'),
                'agent': alert.get('agent', {}).get('name'),
                'data': alert.get('data', {})
            })
        return context

    def generate_threat_alert(
        self,
        alerts: List[Dict[str, Any]],
        llm_analysis: Dict[str, Any]
    ) -> ThreatAlert:
        """Generate structured threat alert from analysis"""

        # Extract IOCs
        iocs = []
        for alert in alerts:
            data = alert.get('data', {})
            if 'srcip' in data:
                iocs.append(f"IP: {data['srcip']}")
            if 'md5' in data:
                iocs.append(f"MD5: {data['md5']}")

        threat_alert = ThreatAlert(
            alert_id=f"THREAT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            timestamp=datetime.now(),
            severity=llm_analysis.get('severity', 'medium'),
            threat_type=llm_analysis.get('threat_type', 'unknown'),
            description=llm_analysis.get('description', ''),
            indicators=list(set(iocs)),
            mitre_tactics=llm_analysis.get('mitre_tactics', []),
            mitre_techniques=llm_analysis.get('mitre_techniques', []),
            confidence=0.85,
            raw_events=[a.get('id') for a in alerts],
            recommendation=llm_analysis.get('recommendations', '')
        )

        return threat_alert

    def run_detection(self) -> List[ThreatAlert]:
        """
        Main detection workflow:
        1. Fetch recent alerts
        2. Detect anomalies with ML
        3. Analyze with LLM
        4. Generate threat alerts
        """
        logger.info("Starting threat detection cycle")

        # Fetch alerts
        alerts = self.fetch_recent_alerts(hours=1)
        if not alerts:
            logger.info("No alerts to analyze")
            return []

        logger.info(f"Fetched {len(alerts)} alerts")

        # Detect anomalies
        anomaly_indices = self.detect_anomalies(alerts)

        # Group alerts for analysis
        alert_groups = self._group_related_alerts(alerts)

        threat_alerts = []
        for group in alert_groups:
            # Analyze with LLM
            llm_analysis = self.analyze_with_llm(group)

            # Generate threat alert
            threat_alert = self.generate_threat_alert(group, llm_analysis)
            threat_alerts.append(threat_alert)

            logger.info(f"Generated threat alert: {threat_alert.alert_id}")

        return threat_alerts

    def _group_related_alerts(
        self,
        alerts: List[Dict[str, Any]]
    ) -> List[List[Dict[str, Any]]]:
        """Group related alerts for correlated analysis"""
        # Simple grouping by source IP and time window
        # In production, use more sophisticated correlation
        groups = []
        current_group = []

        for alert in sorted(alerts, key=lambda x: x.get('timestamp', '')):
            if not current_group:
                current_group.append(alert)
            elif len(current_group) < 5:
                current_group.append(alert)
            else:
                groups.append(current_group)
                current_group = [alert]

        if current_group:
            groups.append(current_group)

        return groups


def main():
    """Main execution"""
    agent = ThreatDetectionAgent()

    # Run detection
    threats = agent.run_detection()

    # Output results
    for threat in threats:
        print("\n" + "="*80)
        print(f"THREAT ALERT: {threat.alert_id}")
        print(f"Severity: {threat.severity}")
        print(f"Type: {threat.threat_type}")
        print(f"Description: {threat.description}")
        print(f"MITRE Tactics: {', '.join(threat.mitre_tactics)}")
        print(f"MITRE Techniques: {', '.join(threat.mitre_techniques)}")
        print(f"Indicators: {', '.join(threat.indicators)}")
        print(f"Recommendation: {threat.recommendation}")
        print("="*80)


if __name__ == "__main__":
    main()
