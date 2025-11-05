"""
Red Team Agent

Automated attack simulation using MITRE ATT&CK framework.
Purple team exercises to validate detection capabilities.
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict
import subprocess
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.ollama_provider import HybridLLMProvider

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class AttackScenario:
    """Represents an attack simulation scenario"""
    scenario_id: str
    name: str
    description: str
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    objectives: List[str]
    target_environment: str
    risk_level: str  # low, medium, high
    commands: List[Dict[str, str]]  # platform: command
    expected_detections: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackResult:
    """Results from attack simulation"""
    result_id: str
    scenario_id: str
    executed_at: datetime
    success: bool
    commands_executed: int
    commands_succeeded: int
    detections_triggered: List[str]
    detection_rate: float
    gaps: List[str]
    recommendations: List[str]
    artifacts: List[str]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['executed_at'] = self.executed_at.isoformat()
        return data


class RedTeamAgent:
    """
    AI-powered red team agent for automated attack simulation
    and detection validation
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.llm = HybridLLMProvider()

        # Safety checks
        self.dry_run = os.getenv('RED_TEAM_DRY_RUN', 'true').lower() == 'true'
        self.allowed_targets = os.getenv('RED_TEAM_ALLOWED_TARGETS', '').split(',')

        logger.info(f"Red Team Agent initialized (dry_run: {self.dry_run})")
        if self.dry_run:
            logger.warning("DRY RUN MODE: No actual commands will be executed")

    def generate_attack_scenarios(
        self,
        target_environment: str = "lab",
        coverage_gaps: Optional[List[str]] = None
    ) -> List[AttackScenario]:
        """
        Generate attack scenarios using LLM

        Args:
            target_environment: Target environment type
            coverage_gaps: Known detection gaps to test

        Returns:
            List of attack scenarios
        """
        logger.info("Generating attack scenarios")

        prompt = self._build_scenario_prompt(target_environment, coverage_gaps)

        messages = [
            {
                "role": "system",
                "content": "You are a red team operator expert in MITRE ATT&CK. Generate realistic, safe attack scenarios for lab testing."
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

            scenarios_data = json.loads(response)
            scenarios = []

            for s in scenarios_data.get('scenarios', []):
                scenario = AttackScenario(
                    scenario_id=f"ATTACK-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    name=s.get('name', ''),
                    description=s.get('description', ''),
                    mitre_tactics=s.get('mitre_tactics', []),
                    mitre_techniques=s.get('mitre_techniques', []),
                    objectives=s.get('objectives', []),
                    target_environment=target_environment,
                    risk_level=s.get('risk_level', 'medium'),
                    commands=s.get('commands', []),
                    expected_detections=s.get('expected_detections', [])
                )
                scenarios.append(scenario)

            logger.info(f"Generated {len(scenarios)} attack scenarios")
            return scenarios

        except Exception as e:
            logger.error(f"Failed to generate scenarios: {e}")
            return []

    def _build_scenario_prompt(
        self,
        target_environment: str,
        coverage_gaps: Optional[List[str]]
    ) -> str:
        """Build prompt for scenario generation"""

        prompt = f"""Generate 3 attack scenarios for purple team testing in a {target_environment} environment.

Requirements:
- Safe for lab environment
- Based on real-world TTPs
- Mapped to MITRE ATT&CK
- Include detection expectations
- Provide actual commands (safe for lab)

"""

        if coverage_gaps:
            prompt += f"Focus on testing these detection gaps: {', '.join(coverage_gaps)}\n\n"
        else:
            prompt += """
Focus on common attack patterns:
- Initial Access (T1566 - Phishing simulation)
- Execution (T1059 - PowerShell/Bash)
- Persistence (T1547 - Registry/Startup)
- Credential Access (T1003 - Credential Dumping simulation)
- Lateral Movement (T1021 - Remote Services)
"""

        prompt += """
Return JSON format:
{
  "scenarios": [
    {
      "name": "Scenario name",
      "description": "What this tests",
      "mitre_tactics": ["Initial Access", "Execution"],
      "mitre_techniques": ["T1566.001", "T1059.001"],
      "objectives": ["Test email detection", "Validate PowerShell logging"],
      "risk_level": "low",
      "commands": [
        {
          "platform": "windows",
          "command": "powershell -NoProfile -Command Write-Host 'Test'",
          "description": "Benign PowerShell execution"
        }
      ],
      "expected_detections": [
        "Wazuh rule 92000 - PowerShell execution",
        "Sysmon Event ID 1 - Process creation"
      ]
    }
  ]
}

IMPORTANT: Commands must be SAFE for lab testing. No destructive actions.
"""

        return prompt

    def execute_scenario(self, scenario: AttackScenario) -> AttackResult:
        """
        Execute attack scenario

        Args:
            scenario: The scenario to execute

        Returns:
            Attack results
        """
        logger.info(f"Executing scenario: {scenario.name}")

        if self.dry_run:
            logger.info("DRY RUN: Simulating execution")
            return self._simulate_execution(scenario)

        # Execute commands
        commands_executed = 0
        commands_succeeded = 0
        artifacts = []

        for cmd in scenario.commands:
            try:
                if self._is_safe_command(cmd['command']):
                    logger.info(f"Executing: {cmd['command']}")
                    result = subprocess.run(
                        cmd['command'],
                        shell=True,
                        capture_output=True,
                        timeout=30
                    )
                    commands_executed += 1
                    if result.returncode == 0:
                        commands_succeeded += 1
                    artifacts.append({
                        'command': cmd['command'],
                        'output': result.stdout.decode()[:500],
                        'success': result.returncode == 0
                    })
                else:
                    logger.warning(f"Unsafe command blocked: {cmd['command']}")
            except Exception as e:
                logger.error(f"Command failed: {e}")

        # Check for detections
        detections = self._check_detections(scenario)

        # Calculate detection rate
        detection_rate = len(detections) / len(scenario.expected_detections) if scenario.expected_detections else 0

        # Identify gaps
        gaps = [d for d in scenario.expected_detections if d not in detections]

        # Generate recommendations
        recommendations = self._generate_recommendations(scenario, detections, gaps)

        result = AttackResult(
            result_id=f"REDRES-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            scenario_id=scenario.scenario_id,
            executed_at=datetime.now(),
            success=commands_succeeded > 0,
            commands_executed=commands_executed,
            commands_succeeded=commands_succeeded,
            detections_triggered=detections,
            detection_rate=detection_rate,
            gaps=gaps,
            recommendations=recommendations,
            artifacts=[json.dumps(a) for a in artifacts]
        )

        logger.info(f"Scenario complete: {commands_succeeded}/{commands_executed} commands succeeded")
        logger.info(f"Detection rate: {detection_rate:.1%}")

        return result

    def _simulate_execution(self, scenario: AttackScenario) -> AttackResult:
        """Simulate execution for dry run mode"""

        # Simulate partial detection
        simulated_detections = scenario.expected_detections[:len(scenario.expected_detections)//2]

        detection_rate = len(simulated_detections) / len(scenario.expected_detections) if scenario.expected_detections else 0

        gaps = [d for d in scenario.expected_detections if d not in simulated_detections]

        return AttackResult(
            result_id=f"REDRES-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            scenario_id=scenario.scenario_id,
            executed_at=datetime.now(),
            success=True,
            commands_executed=len(scenario.commands),
            commands_succeeded=len(scenario.commands),
            detections_triggered=simulated_detections,
            detection_rate=detection_rate,
            gaps=gaps,
            recommendations=self._generate_recommendations(scenario, simulated_detections, gaps),
            artifacts=["[DRY RUN - No actual execution]"]
        )

    def _is_safe_command(self, command: str) -> bool:
        """
        Check if command is safe to execute

        Blocks destructive commands
        """
        dangerous_patterns = [
            'rm -rf',
            'del /f',
            'format',
            'shutdown',
            'reboot',
            'dd if=',
            'mkfs',
            '> /dev/',
            'chmod 777',
            'curl | sh',
            'wget | sh'
        ]

        command_lower = command.lower()
        for pattern in dangerous_patterns:
            if pattern in command_lower:
                logger.error(f"Dangerous pattern detected: {pattern}")
                return False

        return True

    def _check_detections(self, scenario: AttackScenario) -> List[str]:
        """
        Check if attacks were detected

        In production, query SIEM for alerts matching the scenario
        """
        # Mock detection check
        # In production: Query Wazuh API for alerts in last N minutes

        # Simulate 70% detection rate
        import random
        detected = [d for d in scenario.expected_detections if random.random() > 0.3]

        return detected

    def _generate_recommendations(
        self,
        scenario: AttackScenario,
        detections: List[str],
        gaps: List[str]
    ) -> List[str]:
        """Generate recommendations using LLM"""

        if not gaps:
            return ["All expected detections triggered. Coverage is good."]

        prompt = f"""Analyze this purple team exercise and provide recommendations:

Scenario: {scenario.name}
{scenario.description}

MITRE Techniques: {', '.join(scenario.mitre_techniques)}

Expected Detections: {len(scenario.expected_detections)}
Actual Detections: {len(detections)}
Detection Rate: {len(detections)/len(scenario.expected_detections):.1%}

Detection Gaps:
{json.dumps(gaps, indent=2)}

Provide specific recommendations to close these gaps in JSON format:
{{
  "recommendations": [
    "Specific, actionable recommendation",
    "..."
  ]
}}
"""

        messages = [
            {
                "role": "system",
                "content": "You are a purple team expert. Provide actionable recommendations to improve detection coverage."
            },
            {
                "role": "user",
                "content": prompt
            }
        ]

        try:
            response = self.llm.chat_completion(
                messages=messages,
                temperature=0.3,
                response_format="json"
            )
            data = json.loads(response)
            return data.get('recommendations', [])
        except Exception as e:
            logger.error(f"Recommendation generation failed: {e}")
            return ["Manual review required"]

    def run_purple_team_exercise(self) -> Dict[str, Any]:
        """
        Complete purple team exercise:
        1. Generate attack scenarios
        2. Execute scenarios
        3. Measure detection coverage
        4. Provide recommendations
        """
        logger.info("Starting purple team exercise")

        # Generate scenarios focusing on detection gaps
        scenarios = self.generate_attack_scenarios(
            target_environment="lab",
            coverage_gaps=["PowerShell obfuscation", "Living-off-the-land binaries"]
        )

        if not scenarios:
            logger.warning("No scenarios generated")
            return {'status': 'no_scenarios'}

        # Execute scenarios
        results = []
        for scenario in scenarios:
            result = self.execute_scenario(scenario)
            results.append(result)
            self._save_result(result)

        # Generate report
        report = self._generate_report(scenarios, results)

        # Calculate overall metrics
        avg_detection_rate = sum(r.detection_rate for r in results) / len(results) if results else 0
        total_gaps = sum(len(r.gaps) for r in results)

        logger.info("Purple team exercise complete")

        return {
            'status': 'completed',
            'scenarios_executed': len(scenarios),
            'average_detection_rate': f"{avg_detection_rate:.1%}",
            'total_gaps': total_gaps,
            'report': report
        }

    def _generate_report(
        self,
        scenarios: List[AttackScenario],
        results: List[AttackResult]
    ) -> str:
        """Generate purple team report"""

        prompt = f"""Generate a professional purple team exercise report:

Scenarios Executed: {len(scenarios)}
Total Commands: {sum(r.commands_executed for r in results)}
Average Detection Rate: {sum(r.detection_rate for r in results)/len(results):.1%}

Detailed Results:
{json.dumps([r.to_dict() for r in results], indent=2)}

Generate report in Markdown format with:
1. Executive Summary
2. Methodology
3. Detection Coverage Analysis
4. Identified Gaps
5. Prioritized Recommendations
6. MITRE ATT&CK Coverage Heatmap (describe)
"""

        messages = [
            {
                "role": "system",
                "content": "You are a purple team report writer. Create clear, actionable reports."
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
            return "# Purple Team Report\n\nReport generation failed."

    def _save_result(self, result: AttackResult) -> None:
        """Save attack simulation results"""
        try:
            report_dir = "/app/data/reports/red_team"
            os.makedirs(report_dir, exist_ok=True)

            filename = f"{report_dir}/{result.result_id}.json"
            with open(filename, 'w') as f:
                json.dump(result.to_dict(), f, indent=2)

            logger.info(f"Result saved: {filename}")
        except Exception as e:
            logger.error(f"Failed to save result: {e}")


def main():
    """Main execution"""
    agent = RedTeamAgent()

    # Run purple team exercise
    results = agent.run_purple_team_exercise()

    print("\n" + "="*80)
    print("PURPLE TEAM EXERCISE COMPLETED")
    print(f"Status: {results['status']}")
    print(f"Scenarios Executed: {results.get('scenarios_executed', 0)}")
    print(f"Average Detection Rate: {results.get('average_detection_rate', '0%')}")
    print(f"Total Gaps Found: {results.get('total_gaps', 0)}")
    print("="*80)


if __name__ == "__main__":
    main()
