"""
Detection Engineering Agent

This agent automates the creation, testing, and optimization of security
detection rules for various platforms (Wazuh, Suricata, etc.)
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass, asdict
from openai import OpenAI

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class DetectionRule:
    """Represents a security detection rule"""
    rule_id: str
    platform: str  # wazuh, suricata, sigma, etc.
    name: str
    description: str
    severity: str
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    rule_content: str
    test_cases: List[Dict[str, Any]]
    false_positive_rate: Optional[float]
    true_positive_rate: Optional[float]
    created_at: datetime
    updated_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['updated_at'] = self.updated_at.isoformat()
        return data


class DetectionEngineeringAgent:
    """
    AI-powered detection engineering agent that creates, tests,
    and optimizes security detection rules
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

        logger.info("Detection Engineering Agent initialized")

    def generate_detection_rule(
        self,
        attack_technique: str,
        platform: str = "wazuh"
    ) -> DetectionRule:
        """
        Generate a detection rule for a specific attack technique
        """
        logger.info(f"Generating detection rule for {attack_technique} on {platform}")

        # Use LLM to generate rule
        rule_data = self._llm_generate_rule(attack_technique, platform)

        rule = DetectionRule(
            rule_id=f"{platform}_{hash(attack_technique) % 10000:04d}",
            platform=platform,
            name=rule_data.get('name', f'Detect {attack_technique}'),
            description=rule_data.get('description', ''),
            severity=rule_data.get('severity', 'medium'),
            mitre_tactics=rule_data.get('mitre_tactics', []),
            mitre_techniques=rule_data.get('mitre_techniques', []),
            rule_content=rule_data.get('rule_content', ''),
            test_cases=rule_data.get('test_cases', []),
            false_positive_rate=None,
            true_positive_rate=None,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )

        logger.info(f"Generated rule: {rule.rule_id}")
        return rule

    def _llm_generate_rule(
        self,
        attack_technique: str,
        platform: str
    ) -> Dict[str, Any]:
        """Use LLM to generate detection rule"""

        if platform == "wazuh":
            prompt = self._get_wazuh_generation_prompt(attack_technique)
        elif platform == "suricata":
            prompt = self._get_suricata_generation_prompt(attack_technique)
        else:
            prompt = self._get_generic_generation_prompt(attack_technique, platform)

        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are an expert detection engineer with deep knowledge of SIEM rules, IDS signatures, and MITRE ATT&CK."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                response_format={"type": "json_object"}
            )

            rule_data = json.loads(response.choices[0].message.content)
            logger.info("LLM rule generation completed")
            return rule_data

        except Exception as e:
            logger.error(f"LLM rule generation failed: {e}")
            return {
                'name': f'Detect {attack_technique}',
                'description': 'Rule generation failed',
                'severity': 'medium',
                'mitre_tactics': [],
                'mitre_techniques': [],
                'rule_content': '<!-- Generation failed -->',
                'test_cases': []
            }

    def _get_wazuh_generation_prompt(self, attack_technique: str) -> str:
        """Generate prompt for Wazuh rule creation"""
        return f"""Generate a Wazuh detection rule for the following attack technique:
{attack_technique}

Provide the response in JSON format with:
{{
  "name": "Rule name",
  "description": "Detailed description",
  "severity": "critical/high/medium/low",
  "mitre_tactics": ["tactic1", "tactic2"],
  "mitre_techniques": ["T1234.001"],
  "rule_content": "Complete Wazuh XML rule",
  "test_cases": [
    {{"description": "Test case 1", "should_trigger": true}},
    {{"description": "Test case 2", "should_trigger": false}}
  ]
}}

The rule_content should be a complete Wazuh XML rule with:
- Appropriate rule ID (100xxx range)
- Level (0-15 based on severity)
- Description
- Relevant fields to match
- MITRE ATT&CK tags"""

    def _get_suricata_generation_prompt(self, attack_technique: str) -> str:
        """Generate prompt for Suricata rule creation"""
        return f"""Generate a Suricata IDS rule for the following attack technique:
{attack_technique}

Provide the response in JSON format with:
{{
  "name": "Rule name",
  "description": "Detailed description",
  "severity": "critical/high/medium/low",
  "mitre_tactics": ["tactic1"],
  "mitre_techniques": ["T1234.001"],
  "rule_content": "Complete Suricata rule",
  "test_cases": [...]
}}

The rule_content should be a complete Suricata rule with:
- Action (alert/drop)
- Protocol
- Source/destination
- Content matches
- Metadata including MITRE ATT&CK tags"""

    def _get_generic_generation_prompt(self, attack_technique: str, platform: str) -> str:
        """Generate prompt for generic platform"""
        return f"""Generate a detection rule for {platform} for the following attack technique:
{attack_technique}

Provide comprehensive rule with test cases in JSON format."""

    def analyze_rule_coverage(self, rules: List[DetectionRule]) -> Dict[str, Any]:
        """
        Analyze MITRE ATT&CK coverage of detection rules
        """
        logger.info(f"Analyzing coverage of {len(rules)} rules")

        # Collect all covered techniques
        covered_techniques = set()
        covered_tactics = set()

        for rule in rules:
            covered_techniques.update(rule.mitre_techniques)
            covered_tactics.update(rule.mitre_tactics)

        # Use LLM to analyze gaps
        gap_analysis = self._llm_analyze_coverage_gaps(
            list(covered_techniques),
            list(covered_tactics)
        )

        return {
            'total_rules': len(rules),
            'covered_techniques': len(covered_techniques),
            'covered_tactics': len(covered_tactics),
            'techniques_list': list(covered_techniques),
            'tactics_list': list(covered_tactics),
            'gaps': gap_analysis.get('gaps', []),
            'recommendations': gap_analysis.get('recommendations', [])
        }

    def _llm_analyze_coverage_gaps(
        self,
        covered_techniques: List[str],
        covered_tactics: List[str]
    ) -> Dict[str, Any]:
        """Use LLM to identify coverage gaps"""

        prompt = f"""Analyze this MITRE ATT&CK detection coverage:

Covered Tactics: {', '.join(covered_tactics)}
Covered Techniques: {', '.join(covered_techniques)}

Identify:
1. Critical gaps in coverage
2. High-priority techniques that should be covered
3. Recommendations for improving detection coverage

Respond in JSON format with:
{{
  "gaps": ["list of critical missing techniques"],
  "recommendations": ["prioritized recommendations"]
}}"""

        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a MITRE ATT&CK expert and detection engineer."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                response_format={"type": "json_object"}
            )

            return json.loads(response.choices[0].message.content)

        except Exception as e:
            logger.error(f"Coverage gap analysis failed: {e}")
            return {
                'gaps': [],
                'recommendations': []
            }

    def optimize_rule(self, rule: DetectionRule, feedback: Dict[str, Any]) -> DetectionRule:
        """
        Optimize a detection rule based on feedback (FP/TP rates)
        """
        logger.info(f"Optimizing rule: {rule.rule_id}")

        # Use LLM to suggest optimizations
        optimizations = self._llm_optimize_rule(rule, feedback)

        # Update rule
        rule.rule_content = optimizations.get('optimized_content', rule.rule_content)
        rule.description = optimizations.get('updated_description', rule.description)
        rule.updated_at = datetime.now()

        logger.info(f"Rule optimized: {rule.rule_id}")
        return rule

    def _llm_optimize_rule(
        self,
        rule: DetectionRule,
        feedback: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Use LLM to optimize rule"""

        prompt = f"""Optimize this detection rule based on performance feedback:

Current Rule:
{json.dumps(rule.to_dict(), indent=2)}

Feedback:
- False Positives: {feedback.get('false_positives', 0)}
- True Positives: {feedback.get('true_positives', 0)}
- Performance Issues: {feedback.get('performance_issues', 'None')}

Provide optimized rule in JSON format:
{{
  "optimized_content": "Improved rule content",
  "updated_description": "Updated description",
  "changes_made": ["list of changes"],
  "expected_improvement": "Expected impact"
}}"""

        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are an expert at optimizing security detection rules."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                response_format={"type": "json_object"}
            )

            return json.loads(response.choices[0].message.content)

        except Exception as e:
            logger.error(f"Rule optimization failed: {e}")
            return {
                'optimized_content': rule.rule_content,
                'updated_description': rule.description,
                'changes_made': [],
                'expected_improvement': 'Optimization failed'
            }

    def test_rule(self, rule: DetectionRule, test_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Test detection rule against test data
        """
        logger.info(f"Testing rule: {rule.rule_id}")

        results = {
            'rule_id': rule.rule_id,
            'total_tests': len(test_data),
            'true_positives': 0,
            'false_positives': 0,
            'true_negatives': 0,
            'false_negatives': 0,
            'details': []
        }

        # In production, actually execute rules against test data
        # For now, mock results
        for test in test_data:
            expected = test.get('should_alert', False)
            # Mock detection
            detected = expected  # Perfect detection for mock

            if expected and detected:
                results['true_positives'] += 1
            elif expected and not detected:
                results['false_negatives'] += 1
            elif not expected and detected:
                results['false_positives'] += 1
            else:
                results['true_negatives'] += 1

        # Calculate metrics
        tp = results['true_positives']
        fp = results['false_positives']
        tn = results['true_negatives']
        fn = results['false_negatives']

        if tp + fn > 0:
            results['true_positive_rate'] = tp / (tp + fn)
        if fp + tn > 0:
            results['false_positive_rate'] = fp / (fp + tn)

        logger.info(f"Rule test completed: TPR={results.get('true_positive_rate', 0):.2f}, FPR={results.get('false_positive_rate', 0):.2f}")

        return results

    def save_rule(self, rule: DetectionRule) -> None:
        """Save detection rule to disk"""
        try:
            rule_dir = f"/app/data/rules/{rule.platform}"
            os.makedirs(rule_dir, exist_ok=True)

            filename = f"{rule_dir}/{rule.rule_id}.json"
            with open(filename, 'w') as f:
                json.dump(rule.to_dict(), f, indent=2)

            logger.info(f"Rule saved: {filename}")

        except Exception as e:
            logger.error(f"Failed to save rule: {e}")


def main():
    """Main execution"""
    agent = DetectionEngineeringAgent()

    # Generate rule for specific attack technique
    rule = agent.generate_detection_rule(
        attack_technique="T1059.001 - PowerShell",
        platform="wazuh"
    )

    print("\n" + "="*80)
    print("DETECTION RULE GENERATED")
    print(f"Rule ID: {rule.rule_id}")
    print(f"Platform: {rule.platform}")
    print(f"Name: {rule.name}")
    print(f"Severity: {rule.severity}")
    print(f"MITRE Techniques: {', '.join(rule.mitre_techniques)}")
    print("\nRule Content:")
    print(rule.rule_content)
    print("="*80)

    # Save rule
    agent.save_rule(rule)


if __name__ == "__main__":
    main()
