#!/bin/bash
set -e

AGENT_TYPE=${AGENT_TYPE:-threat_detection}

echo "Starting agent: $AGENT_TYPE"

case $AGENT_TYPE in
  threat_detection)
    exec python -m agents.threat_detection.agent
    ;;
  incident_response)
    exec python -m agents.incident_response.agent
    ;;
  threat_intelligence)
    exec python -m agents.threat_intelligence.agent
    ;;
  malware_analysis)
    exec python -m agents.malware_analysis.agent
    ;;
  detection_engineering)
    exec python -m agents.detection_engineering.agent
    ;;
  *)
    echo "Unknown agent type: $AGENT_TYPE"
    exit 1
    ;;
esac
