"""
Threat Intelligence Agent

This agent gathers, correlates, and analyzes threat intelligence
from multiple sources including OSINT, commercial feeds, and dark web.
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import requests
from openai import OpenAI
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class IOC:
    """Indicator of Compromise"""
    ioc_type: str  # ip, domain, url, hash, email
    value: str
    first_seen: datetime
    last_seen: datetime
    confidence: float
    threat_types: List[str]
    sources: List[str]
    tags: List[str]
    context: str

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['first_seen'] = self.first_seen.isoformat()
        data['last_seen'] = self.last_seen.isoformat()
        return data


@dataclass
class ThreatActor:
    """Threat Actor Profile"""
    actor_id: str
    name: str
    aliases: List[str]
    motivation: str
    sophistication: str
    target_industries: List[str]
    target_countries: List[str]
    ttps: List[str]  # MITRE techniques
    campaigns: List[str]
    first_observed: datetime
    last_activity: datetime
    description: str

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['first_observed'] = self.first_observed.isoformat()
        data['last_activity'] = self.last_activity.isoformat()
        return data


class ThreatIntelligenceAgent:
    """
    AI-powered threat intelligence agent that gathers, analyzes,
    and correlates threat data from multiple sources
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

        # API Keys
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.alienvault_api_key = os.getenv('ALIENVAULT_API_KEY')
        self.abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY')

        # Storage
        self.ioc_database = {}
        self.threat_actors = {}

        logger.info("Threat Intelligence Agent initialized")

    def fetch_alienvault_otx(self) -> List[IOC]:
        """Fetch IOCs from AlienVault OTX"""
        logger.info("Fetching IOCs from AlienVault OTX")

        if not self.alienvault_api_key:
            logger.warning("AlienVault API key not configured")
            return self._generate_mock_iocs()

        try:
            headers = {'X-OTX-API-KEY': self.alienvault_api_key}
            url = "https://otx.alienvault.com/api/v1/pulses/subscribed"

            response = requests.get(url, headers=headers, params={'limit': 50})
            response.raise_for_status()

            pulses = response.json().get('results', [])
            iocs = []

            for pulse in pulses:
                for indicator in pulse.get('indicators', [])[:10]:
                    ioc = IOC(
                        ioc_type=indicator.get('type', 'unknown'),
                        value=indicator.get('indicator', ''),
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        confidence=0.8,
                        threat_types=pulse.get('tags', []),
                        sources=['AlienVault OTX'],
                        tags=pulse.get('tags', []),
                        context=pulse.get('description', '')
                    )
                    iocs.append(ioc)

            logger.info(f"Fetched {len(iocs)} IOCs from AlienVault")
            return iocs

        except Exception as e:
            logger.error(f"Failed to fetch from AlienVault: {e}")
            return []

    def _generate_mock_iocs(self) -> List[IOC]:
        """Generate mock IOCs for testing"""
        return [
            IOC(
                ioc_type='ip',
                value='192.0.2.1',
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                confidence=0.9,
                threat_types=['malware', 'botnet'],
                sources=['threat_feed'],
                tags=['mirai', 'iot'],
                context='Known Mirai botnet C2 server'
            ),
            IOC(
                ioc_type='domain',
                value='malicious-domain.com',
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                confidence=0.85,
                threat_types=['phishing'],
                sources=['threat_feed'],
                tags=['credential_theft'],
                context='Phishing domain targeting financial sector'
            ),
            IOC(
                ioc_type='hash',
                value='d41d8cd98f00b204e9800998ecf8427e',
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                confidence=0.95,
                threat_types=['ransomware'],
                sources=['malware_bazaar'],
                tags=['lockbit'],
                context='LockBit ransomware sample'
            )
        ]

    def enrich_ioc(self, ioc: IOC) -> IOC:
        """Enrich IOC with additional intelligence from multiple sources"""
        logger.info(f"Enriching IOC: {ioc.value}")

        # VirusTotal enrichment
        if self.virustotal_api_key and ioc.ioc_type in ['hash', 'domain', 'ip', 'url']:
            vt_data = self._query_virustotal(ioc)
            if vt_data:
                ioc.confidence = min(ioc.confidence + 0.1, 1.0)
                ioc.sources.append('VirusTotal')

        # AbuseIPDB enrichment (for IPs)
        if self.abuseipdb_api_key and ioc.ioc_type == 'ip':
            abuse_data = self._query_abuseipdb(ioc.value)
            if abuse_data:
                ioc.confidence = min(ioc.confidence + 0.1, 1.0)
                ioc.sources.append('AbuseIPDB')

        # LLM enrichment
        llm_context = self._llm_enrich_ioc(ioc)
        if llm_context:
            ioc.context = llm_context

        return ioc

    def _query_virustotal(self, ioc: IOC) -> Optional[Dict[str, Any]]:
        """Query VirusTotal for IOC information"""
        try:
            headers = {'x-apikey': self.virustotal_api_key}

            if ioc.ioc_type == 'ip':
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc.value}"
            elif ioc.ioc_type == 'domain':
                url = f"https://www.virustotal.com/api/v3/domains/{ioc.value}"
            elif ioc.ioc_type == 'hash':
                url = f"https://www.virustotal.com/api/v3/files/{ioc.value}"
            else:
                return None

            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()

        except Exception as e:
            logger.error(f"VirusTotal query failed: {e}")
            return None

    def _query_abuseipdb(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query AbuseIPDB for IP reputation"""
        try:
            headers = {'Key': self.abuseipdb_api_key}
            params = {'ipAddress': ip, 'maxAgeInDays': 90}

            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params=params
            )
            response.raise_for_status()
            return response.json()

        except Exception as e:
            logger.error(f"AbuseIPDB query failed: {e}")
            return None

    def _llm_enrich_ioc(self, ioc: IOC) -> str:
        """Use LLM to provide context about the IOC"""

        prompt = f"""Analyze this Indicator of Compromise and provide contextual intelligence:

IOC Type: {ioc.ioc_type}
Value: {ioc.value}
Threat Types: {', '.join(ioc.threat_types)}
Tags: {', '.join(ioc.tags)}
Current Context: {ioc.context}

Provide:
1. Threat assessment
2. Common attack patterns using this IOC
3. Recommended defensive actions
4. Related threat campaigns if known

Keep response concise (2-3 sentences)."""

        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a threat intelligence analyst."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=200
            )

            return response.choices[0].message.content

        except Exception as e:
            logger.error(f"LLM enrichment failed: {e}")
            return ioc.context

    def correlate_iocs(self, iocs: List[IOC]) -> List[Dict[str, Any]]:
        """Correlate IOCs to identify campaigns and patterns"""
        logger.info(f"Correlating {len(iocs)} IOCs")

        # Group by tags and threat types
        correlations = []

        # Simple correlation by common tags
        tag_groups = {}
        for ioc in iocs:
            for tag in ioc.tags:
                if tag not in tag_groups:
                    tag_groups[tag] = []
                tag_groups[tag].append(ioc)

        # Identify significant correlations
        for tag, related_iocs in tag_groups.items():
            if len(related_iocs) >= 2:
                correlations.append({
                    'correlation_type': 'tag',
                    'identifier': tag,
                    'ioc_count': len(related_iocs),
                    'iocs': [ioc.value for ioc in related_iocs],
                    'confidence': 0.7
                })

        logger.info(f"Found {len(correlations)} correlations")
        return correlations

    def identify_threat_campaigns(self, correlations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Use LLM to identify potential threat campaigns from correlated IOCs"""

        if not correlations:
            return []

        prompt = f"""Analyze these correlated IOCs and identify potential threat campaigns:

{json.dumps(correlations, indent=2)}

For each potential campaign, provide:
1. Campaign name/identifier
2. Threat actor (if identifiable)
3. Target profile
4. Attack methodology
5. Confidence level (0-1)

Respond in JSON format with array of campaigns."""

        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a threat intelligence analyst specializing in campaign identification."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                response_format={"type": "json_object"}
            )

            result = json.loads(response.choices[0].message.content)
            campaigns = result.get('campaigns', [])
            logger.info(f"Identified {len(campaigns)} campaigns")
            return campaigns

        except Exception as e:
            logger.error(f"Campaign identification failed: {e}")
            return []

    def check_ioc_in_logs(self, ioc: IOC, log_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check if IOC appears in internal logs"""
        matches = []

        for log_entry in log_data:
            log_str = json.dumps(log_entry).lower()
            if ioc.value.lower() in log_str:
                matches.append(log_entry)

        if matches:
            logger.warning(f"IOC {ioc.value} found in {len(matches)} log entries!")

        return matches

    def generate_threat_report(self, iocs: List[IOC], campaigns: List[Dict[str, Any]]) -> str:
        """Generate comprehensive threat intelligence report"""

        prompt = f"""Generate a professional threat intelligence report:

IOCs Analyzed: {len(iocs)}
Top IOC Types: {self._get_ioc_type_distribution(iocs)}
Identified Campaigns: {len(campaigns)}

Campaign Details:
{json.dumps(campaigns, indent=2)}

Sample IOCs:
{json.dumps([ioc.to_dict() for ioc in iocs[:5]], indent=2)}

Include:
1. Executive Summary
2. Key Findings
3. Threat Landscape Overview
4. Identified Campaigns
5. Recommended Actions
6. IOC Summary Table

Format as Markdown."""

        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are an expert threat intelligence analyst."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )

            return response.choices[0].message.content

        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return "# Threat Intelligence Report\n\nReport generation failed."

    def _get_ioc_type_distribution(self, iocs: List[IOC]) -> Dict[str, int]:
        """Get distribution of IOC types"""
        distribution = {}
        for ioc in iocs:
            distribution[ioc.ioc_type] = distribution.get(ioc.ioc_type, 0) + 1
        return distribution

    def run_intelligence_cycle(self) -> Dict[str, Any]:
        """
        Run complete intelligence cycle:
        1. Collection
        2. Processing & Enrichment
        3. Analysis & Correlation
        4. Dissemination
        """
        logger.info("Starting threat intelligence cycle")

        # Collection
        iocs = []
        iocs.extend(self.fetch_alienvault_otx())

        logger.info(f"Collected {len(iocs)} IOCs")

        # Enrichment
        enriched_iocs = []
        for ioc in iocs[:10]:  # Limit for API rate limits
            enriched_ioc = self.enrich_ioc(ioc)
            enriched_iocs.append(enriched_ioc)

        # Correlation
        correlations = self.correlate_iocs(enriched_iocs)

        # Campaign identification
        campaigns = self.identify_threat_campaigns(correlations)

        # Generate report
        report = self.generate_threat_report(enriched_iocs, campaigns)

        # Save report
        self._save_report(report)

        # Save IOCs to database (for future matching)
        self._save_iocs(enriched_iocs)

        return {
            'iocs_collected': len(iocs),
            'iocs_enriched': len(enriched_iocs),
            'correlations': len(correlations),
            'campaigns': len(campaigns),
            'report': report
        }

    def _save_report(self, report: str) -> None:
        """Save threat intelligence report"""
        try:
            report_dir = "/app/data/reports"
            os.makedirs(report_dir, exist_ok=True)

            filename = f"{report_dir}/threat_intel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            with open(filename, 'w') as f:
                f.write(report)

            logger.info(f"Threat intel report saved: {filename}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")

    def _save_iocs(self, iocs: List[IOC]) -> None:
        """Save IOCs to database"""
        try:
            ioc_dir = "/app/data/iocs"
            os.makedirs(ioc_dir, exist_ok=True)

            filename = f"{ioc_dir}/iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump([ioc.to_dict() for ioc in iocs], f, indent=2)

            logger.info(f"IOCs saved: {filename}")
        except Exception as e:
            logger.error(f"Failed to save IOCs: {e}")


def main():
    """Main execution"""
    agent = ThreatIntelligenceAgent()

    # Run intelligence cycle
    results = agent.run_intelligence_cycle()

    print("\n" + "="*80)
    print("THREAT INTELLIGENCE CYCLE COMPLETED")
    print(f"IOCs Collected: {results['iocs_collected']}")
    print(f"IOCs Enriched: {results['iocs_enriched']}")
    print(f"Correlations Found: {results['correlations']}")
    print(f"Campaigns Identified: {results['campaigns']}")
    print("="*80)


if __name__ == "__main__":
    main()
