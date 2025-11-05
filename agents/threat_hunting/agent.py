"""
Threat Hunting Agent

Hypothesis-driven threat hunting using LLM-powered analysis.
Proactively searches for threats that evade traditional detection.
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.ollama_provider import HybridLLMProvider

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class HuntingHypothesis:
    """Represents a threat hunting hypothesis"""
    hypothesis_id: str
    title: str
    description: str
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    data_sources: List[str]
    queries: List[Dict[str, str]]  # platform: query
    expected_findings: str
    created_at: datetime
    status: str  # active, validated, invalidated

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        return data


@dataclass
class HuntResult:
    """Results from a hunting operation"""
    hunt_id: str
    hypothesis_id: str
    executed_at: datetime
    findings_count: int
    findings: List[Dict[str, Any]]
    analysis: str
    true_positives: int
    false_positives: int
    recommendations: List[str]
    follow_up_hunts: List[str]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['executed_at'] = self.executed_at.isoformat()
        return data


class ThreatHuntingAgent:
    """
    AI-powered threat hunting agent that generates hypotheses
    and hunts for threats proactively
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.llm = HybridLLMProvider()

        # Wazuh API configuration
        self.wazuh_url = os.getenv('WAZUH_API_URL')
        self.wazuh_token = None

        logger.info("Threat Hunting Agent initialized")

    def generate_hypotheses(
        self,
        threat_landscape: Optional[str] = None,
        recent_incidents: Optional[List[Dict[str, Any]]] = None
    ) -> List[HuntingHypothesis]:
        """
        Generate threat hunting hypotheses using LLM

        Args:
            threat_landscape: Current threat intel context
            recent_incidents: Recent security incidents for context

        Returns:
            List of hunting hypotheses
        """
        logger.info("Generating threat hunting hypotheses")

        prompt = self._build_hypothesis_prompt(threat_landscape, recent_incidents)

        messages = [
            {
                "role": "system",
                "content": "You are an expert threat hunter with deep knowledge of adversary TTPs and MITRE ATT&CK. Generate actionable hunting hypotheses."
            },
            {
                "role": "user",
                "content": prompt
            }
        ]

        try:
            response = self.llm.chat_completion(
                messages=messages,
                temperature=0.4,
                response_format="json"
            )

            hypotheses_data = json.loads(response)
            hypotheses = []

            for h in hypotheses_data.get('hypotheses', []):
                hypothesis = HuntingHypothesis(
                    hypothesis_id=f"HUNT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    title=h.get('title', ''),
                    description=h.get('description', ''),
                    mitre_tactics=h.get('mitre_tactics', []),
                    mitre_techniques=h.get('mitre_techniques', []),
                    data_sources=h.get('data_sources', []),
                    queries=h.get('queries', []),
                    expected_findings=h.get('expected_findings', ''),
                    created_at=datetime.now(),
                    status='active'
                )
                hypotheses.append(hypothesis)

            logger.info(f"Generated {len(hypotheses)} hunting hypotheses")
            return hypotheses

        except Exception as e:
            logger.error(f"Failed to generate hypotheses: {e}")
            return []

    def _build_hypothesis_prompt(
        self,
        threat_landscape: Optional[str],
        recent_incidents: Optional[List[Dict[str, Any]]]
    ) -> str:
        """Build prompt for hypothesis generation"""

        prompt = """Generate 3-5 threat hunting hypotheses based on current threat landscape and recent activity.

For each hypothesis provide:
1. Title (concise, actionable)
2. Description (what you're looking for and why)
3. MITRE tactics and techniques
4. Required data sources (logs, network, endpoint)
5. Hunting queries (Wazuh, KQL, or generic format)
6. Expected findings if hypothesis is true

"""

        if threat_landscape:
            prompt += f"\nCurrent Threat Landscape:\n{threat_landscape}\n"

        if recent_incidents:
            prompt += f"\nRecent Incidents:\n{json.dumps(recent_incidents, indent=2)}\n"
        else:
            prompt += """
Focus on common attack patterns:
- Living-off-the-land techniques
- Credential access and lateral movement
- Data exfiltration
- Persistence mechanisms
- Evasion techniques
"""

        prompt += """
Return JSON format:
{
  "hypotheses": [
    {
      "title": "Hypothesis title",
      "description": "Detailed description",
      "mitre_tactics": ["Credential Access"],
      "mitre_techniques": ["T1003"],
      "data_sources": ["Windows Event Logs", "Sysmon"],
      "queries": [
        {"platform": "wazuh", "query": "rule.id:4625 AND data.win.system.eventID:4625"},
        {"platform": "kql", "query": "SecurityEvent | where EventID == 4625"}
      ],
      "expected_findings": "Failed login attempts from service accounts"
    }
  ]
}
"""

        return prompt

    def execute_hunt(self, hypothesis: HuntingHypothesis) -> HuntResult:
        """
        Execute a hunting hypothesis

        Args:
            hypothesis: The hypothesis to test

        Returns:
            Hunt results
        """
        logger.info(f"Executing hunt: {hypothesis.title}")

        # Execute queries against data sources
        findings = self._execute_queries(hypothesis.queries)

        # Analyze findings with LLM
        analysis = self._analyze_findings(hypothesis, findings)

        # Parse analysis
        analysis_data = json.loads(analysis)

        result = HuntResult(
            hunt_id=f"HUNTRES-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            hypothesis_id=hypothesis.hypothesis_id,
            executed_at=datetime.now(),
            findings_count=len(findings),
            findings=findings,
            analysis=analysis_data.get('analysis', ''),
            true_positives=analysis_data.get('true_positives', 0),
            false_positives=analysis_data.get('false_positives', 0),
            recommendations=analysis_data.get('recommendations', []),
            follow_up_hunts=analysis_data.get('follow_up_hunts', [])
        )

        logger.info(f"Hunt completed: {result.findings_count} findings")
        return result

    def _execute_queries(self, queries: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """
        Execute hunting queries

        In production, this would query real data sources.
        For now, return mock data.
        """
        # Mock findings
        findings = [
            {
                'timestamp': datetime.now().isoformat(),
                'source': 'endpoint',
                'event': 'Suspicious PowerShell execution',
                'details': {
                    'process': 'powershell.exe',
                    'command_line': 'powershell -enc <base64>',
                    'parent_process': 'winword.exe'
                }
            },
            {
                'timestamp': datetime.now().isoformat(),
                'source': 'network',
                'event': 'Unusual outbound connection',
                'details': {
                    'dest_ip': '192.0.2.100',
                    'dest_port': 443,
                    'bytes_out': 50000
                }
            }
        ]

        return findings

    def _analyze_findings(
        self,
        hypothesis: HuntingHypothesis,
        findings: List[Dict[str, Any]]
    ) -> str:
        """Analyze hunting findings with LLM"""

        prompt = f"""Analyze these threat hunting findings and determine if they validate the hypothesis.

Hypothesis:
{hypothesis.title}
{hypothesis.description}

Expected: {hypothesis.expected_findings}

Findings:
{json.dumps(findings, indent=2)}

Provide analysis in JSON format:
{{
  "analysis": "Detailed analysis of findings",
  "hypothesis_validated": true/false,
  "true_positives": <count>,
  "false_positives": <count>,
  "severity": "critical/high/medium/low",
  "recommendations": ["list of actionable recommendations"],
  "follow_up_hunts": ["suggested follow-up hunting activities"]
}}
"""

        messages = [
            {
                "role": "system",
                "content": "You are a threat hunting analyst. Analyze findings critically and provide actionable insights."
            },
            {
                "role": "user",
                "content": prompt
            }
        ]

        try:
            response = self.llm.chat_completion(
                messages=messages,
                temperature=0.2,
                response_format="json"
            )
            return response
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return json.dumps({
                'analysis': 'Analysis failed',
                'hypothesis_validated': False,
                'true_positives': 0,
                'false_positives': 0,
                'recommendations': [],
                'follow_up_hunts': []
            })

    def run_hunt_cycle(self) -> Dict[str, Any]:
        """
        Complete hunting cycle:
        1. Generate hypotheses
        2. Execute hunts
        3. Analyze results
        4. Generate reports
        """
        logger.info("Starting threat hunting cycle")

        # Generate hypotheses
        hypotheses = self.generate_hypotheses(
            threat_landscape="Increased phishing activity targeting financial sector",
            recent_incidents=None
        )

        if not hypotheses:
            logger.warning("No hypotheses generated")
            return {'status': 'no_hypotheses'}

        # Execute each hypothesis
        results = []
        for hypothesis in hypotheses:
            result = self.execute_hunt(hypothesis)
            results.append(result)

            # Save results
            self._save_hunt_result(result)

        # Generate summary report
        report = self._generate_hunt_report(hypotheses, results)

        logger.info("Hunting cycle complete")

        return {
            'status': 'completed',
            'hypotheses_tested': len(hypotheses),
            'total_findings': sum(r.findings_count for r in results),
            'true_positives': sum(r.true_positives for r in results),
            'report': report
        }

    def _generate_hunt_report(
        self,
        hypotheses: List[HuntingHypothesis],
        results: List[HuntResult]
    ) -> str:
        """Generate comprehensive hunting report"""

        prompt = f"""Generate a professional threat hunting report:

Hypotheses Tested: {len(hypotheses)}
Total Findings: {sum(r.findings_count for r in results)}
True Positives: {sum(r.true_positives for r in results)}

Detailed Results:
{json.dumps([r.to_dict() for r in results], indent=2)}

Generate report in Markdown format with:
1. Executive Summary
2. Hunting Methodology
3. Key Findings
4. Validated Threats
5. Recommendations
6. Next Steps
"""

        messages = [
            {
                "role": "system",
                "content": "You are a threat hunting report writer. Create clear, actionable reports."
            },
            {
                "role": "user",
                "content": prompt
            }
        ]

        try:
            report = self.llm.chat_completion(
                messages=messages,
                temperature=0.3,
                prefer_cloud=True  # Use GPT-4 for reports
            )
            return report
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return "# Threat Hunting Report\n\nReport generation failed."

    def _save_hunt_result(self, result: HuntResult) -> None:
        """Save hunt results"""
        try:
            report_dir = "/app/data/reports/hunting"
            os.makedirs(report_dir, exist_ok=True)

            filename = f"{report_dir}/{result.hunt_id}.json"
            with open(filename, 'w') as f:
                json.dump(result.to_dict(), f, indent=2)

            logger.info(f"Hunt result saved: {filename}")
        except Exception as e:
            logger.error(f"Failed to save hunt result: {e}")


def main():
    """Main execution"""
    agent = ThreatHuntingAgent()

    # Run hunting cycle
    results = agent.run_hunt_cycle()

    print("\n" + "="*80)
    print("THREAT HUNTING CYCLE COMPLETED")
    print(f"Status: {results['status']}")
    print(f"Hypotheses Tested: {results.get('hypotheses_tested', 0)}")
    print(f"Total Findings: {results.get('total_findings', 0)}")
    print(f"True Positives: {results.get('true_positives', 0)}")
    print("="*80)


if __name__ == "__main__":
    main()
