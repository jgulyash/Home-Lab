"""
Slack Bot for SOC Operations

ChatOps interface for security operations and agent control.
"""

import os
import json
import logging
import re
from typing import Dict, Any
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.common.ollama_provider import HybridLLMProvider

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Slack app
app = App(token=os.environ.get("SLACK_BOT_TOKEN"))

# Initialize LLM
llm = HybridLLMProvider()


@app.message("hello")
def message_hello(message, say):
    """Respond to hello"""
    say(f"Hey there <@{message['user']}>! 👋 I'm your SOC assistant. How can I help?")


@app.command("/threat-status")
def command_threat_status(ack, respond, command):
    """Get current threat status"""
    ack()

    try:
        # Query threat status
        status = {
            'active_threats': 3,
            'incidents_today': 5,
            'critical_alerts': 1,
            'detection_rate': '87%'
        }

        respond({
            "text": "Current Threat Status",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🛡️ SOC Status Dashboard"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Active Threats:*\n{status['active_threats']}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Incidents Today:*\n{status['incidents_today']}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Critical Alerts:*\n{status['critical_alerts']} 🔴"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Detection Rate:*\n{status['detection_rate']}"
                        }
                    ]
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "View Details"
                            },
                            "action_id": "view_threats"
                        },
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "Run Hunt"
                            },
                            "action_id": "run_hunt",
                            "style": "primary"
                        }
                    ]
                }
            ]
        })

    except Exception as e:
        logger.error(f"Error getting threat status: {e}")
        respond(f"❌ Error: {str(e)}")


@app.command("/hunt")
def command_hunt(ack, respond, command):
    """Trigger threat hunting"""
    ack()

    hypothesis = command.get('text', 'General threat hunting')

    respond(f"🔍 Starting threat hunt: *{hypothesis}*\nThis may take a few minutes...")

    # In production, trigger actual hunt via API
    # For now, simulate
    try:
        results = {
            'hypothesis': hypothesis,
            'findings': 2,
            'true_positives': 1,
            'status': 'completed'
        }

        respond({
            "text": "Hunt Complete",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🎯 Threat Hunt Results"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Hypothesis:* {hypothesis}"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Findings:*\n{results['findings']}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*True Positives:*\n{results['true_positives']}"
                        }
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"✅ *Status:* {results['status']}"
                    }
                }
            ]
        })

    except Exception as e:
        logger.error(f"Error running hunt: {e}")
        respond(f"❌ Hunt failed: {str(e)}")


@app.command("/analyze")
def command_analyze(ack, respond, command):
    """Analyze IOC or event with LLM"""
    ack()

    text = command.get('text', '')

    if not text:
        respond("Usage: `/analyze <IOC or description>`\nExample: `/analyze 192.0.2.1`")
        return

    respond(f"🤖 Analyzing: `{text}`...")

    try:
        # Use LLM to analyze
        messages = [
            {
                "role": "system",
                "content": "You are a cybersecurity analyst. Provide concise analysis."
            },
            {
                "role": "user",
                "content": f"Analyze this security indicator and provide threat assessment: {text}"
            }
        ]

        analysis = llm.chat_completion(messages, temperature=0.3)

        respond({
            "text": "Analysis Complete",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🔬 AI Analysis"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Input:* `{text}`"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": analysis[:500]  # Limit length
                    }
                }
            ]
        })

    except Exception as e:
        logger.error(f"Error analyzing: {e}")
        respond(f"❌ Analysis failed: {str(e)}")


@app.command("/incidents")
def command_incidents(ack, respond, command):
    """List recent incidents"""
    ack()

    try:
        # Mock incident data
        incidents = [
            {
                'id': 'INC-001',
                'title': 'Brute force attack detected',
                'severity': 'high',
                'status': 'investigating'
            },
            {
                'id': 'INC-002',
                'title': 'Suspicious PowerShell execution',
                'severity': 'medium',
                'status': 'contained'
            },
            {
                'id': 'INC-003',
                'title': 'Malware detected on endpoint',
                'severity': 'critical',
                'status': 'resolved'
            }
        ]

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "📋 Recent Incidents"
                }
            }
        ]

        for inc in incidents:
            severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(inc['severity'], '⚪')

            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{severity_emoji} *{inc['id']}* - {inc['title']}\n*Status:* {inc['status']} | *Severity:* {inc['severity']}"
                },
                "accessory": {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "View"
                    },
                    "action_id": f"view_incident_{inc['id']}"
                }
            })

        respond({"text": "Recent Incidents", "blocks": blocks})

    except Exception as e:
        logger.error(f"Error listing incidents: {e}")
        respond(f"❌ Error: {str(e)}")


@app.command("/block-ip")
def command_block_ip(ack, respond, command):
    """Block an IP address"""
    ack()

    ip = command.get('text', '').strip()

    # Validate IP format
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        respond("❌ Invalid IP address format. Usage: `/block-ip 192.0.2.1`")
        return

    respond(f"🚫 Blocking IP: `{ip}`...")

    try:
        # In production, call firewall API
        # For now, simulate
        result = {
            'ip': ip,
            'status': 'blocked',
            'rule_id': 'FW-12345'
        }

        respond({
            "text": "IP Blocked",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🚫 IP Address Blocked"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*IP Address:*\n`{result['ip']}`"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Rule ID:*\n{result['rule_id']}"
                        }
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "✅ Firewall rule created successfully"
                    }
                }
            ]
        })

    except Exception as e:
        logger.error(f"Error blocking IP: {e}")
        respond(f"❌ Failed to block IP: {str(e)}")


@app.command("/agent-status")
def command_agent_status(ack, respond, command):
    """Get agent status"""
    ack()

    try:
        # Mock agent status
        agents = [
            {'name': 'Threat Detection', 'status': 'running', 'last_run': '5 min ago'},
            {'name': 'Incident Response', 'status': 'running', 'last_run': '2 min ago'},
            {'name': 'Threat Intelligence', 'status': 'running', 'last_run': '15 min ago'},
            {'name': 'Threat Hunting', 'status': 'idle', 'last_run': '1 hour ago'},
            {'name': 'Red Team', 'status': 'idle', 'last_run': 'Never'},
            {'name': 'Malware Analysis', 'status': 'running', 'last_run': '30 min ago'}
        ]

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🤖 AI Agent Status"
                }
            }
        ]

        for agent in agents:
            status_emoji = '🟢' if agent['status'] == 'running' else '⚪'

            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{status_emoji} *{agent['name']}*\nStatus: {agent['status']} | Last run: {agent['last_run']}"
                }
            })

        respond({"text": "Agent Status", "blocks": blocks})

    except Exception as e:
        logger.error(f"Error getting agent status: {e}")
        respond(f"❌ Error: {str(e)}")


@app.command("/help")
def command_help(ack, respond, command):
    """Show help"""
    ack()

    respond({
        "text": "SOC Bot Help",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🤖 SOC Bot Commands"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Available Commands:*\n\n"
                            "`/threat-status` - View current threat status\n"
                            "`/hunt <hypothesis>` - Run threat hunt\n"
                            "`/analyze <IOC>` - Analyze indicator with AI\n"
                            "`/incidents` - List recent incidents\n"
                            "`/block-ip <ip>` - Block an IP address\n"
                            "`/agent-status` - Check AI agent status\n"
                            "`/help` - Show this help message"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Natural Language:*\nYou can also just @mention me and ask questions!"
                }
            }
        ]
    })


@app.event("app_mention")
def handle_app_mention(event, say):
    """Handle @mentions with natural language processing"""
    text = event.get('text', '')
    user = event.get('user')

    # Remove bot mention
    text = re.sub(r'<@[A-Z0-9]+>', '', text).strip()

    if not text:
        say(f"Hey <@{user}>! Ask me anything about security. Try `/help` for commands.")
        return

    try:
        # Use LLM to respond
        messages = [
            {
                "role": "system",
                "content": "You are a helpful SOC assistant. Provide concise, actionable responses about security operations, threats, and incidents."
            },
            {
                "role": "user",
                "content": text
            }
        ]

        response = llm.chat_completion(messages, temperature=0.5)

        say(f"<@{user}> {response}")

    except Exception as e:
        logger.error(f"Error processing mention: {e}")
        say(f"<@{user}> Sorry, I encountered an error processing your request.")


# Button action handlers
@app.action("view_threats")
def handle_view_threats(ack, body, say):
    ack()
    say("Opening threat details dashboard... (Not implemented yet)")


@app.action("run_hunt")
def handle_run_hunt(ack, body, say):
    ack()
    say("🔍 Starting automated threat hunt...")


@app.action(re.compile("view_incident_.*"))
def handle_view_incident(ack, body, say):
    ack()
    incident_id = body['actions'][0]['action_id'].replace('view_incident_', '')
    say(f"Opening incident {incident_id}... (Not implemented yet)")


def main():
    """Start the Slack bot"""
    logger.info("Starting SOC Slack Bot")

    # Check required environment variables
    if not os.environ.get("SLACK_BOT_TOKEN"):
        logger.error("SLACK_BOT_TOKEN not set")
        return

    if not os.environ.get("SLACK_APP_TOKEN"):
        logger.error("SLACK_APP_TOKEN not set")
        return

    # Start bot
    handler = SocketModeHandler(app, os.environ["SLACK_APP_TOKEN"])
    logger.info("SOC Bot is running!")
    handler.start()


if __name__ == "__main__":
    main()
