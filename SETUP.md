# AI-Powered Cybersecurity Home Lab - Setup Guide

This guide will walk you through setting up and running the AI-powered cybersecurity home lab.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Initial Setup](#initial-setup)
3. [Configuration](#configuration)
4. [Starting the Lab](#starting-the-lab)
5. [Verification](#verification)
6. [Using the Lab](#using-the-lab)
7. [Troubleshooting](#troubleshooting)

## Prerequisites

### Required Software
- **Docker** (version 20.10+)
- **Docker Compose** (version 2.0+)
- **Git**
- At least 8GB RAM available for Docker
- 50GB free disk space

### Required API Keys
- **OpenAI API Key** (required for AI agents)
  - Sign up at https://platform.openai.com/
  - Create an API key
  - Estimated cost: $5-20/month depending on usage

### Optional API Keys
- **VirusTotal** (for malware analysis)
- **AlienVault OTX** (for threat intelligence)
- **AbuseIPDB** (for IP reputation)

### Existing Infrastructure (Optional Integration)
- Wazuh SIEM server (if you want real integration)
- OPNsense firewall (for automated rule updates)
- AWS account (for cloud security testing)

## Initial Setup

### 1. Clone the Repository

```bash
cd /path/to/your/workspace
git clone <repository-url>
cd Home-Lab
```

### 2. Run Setup Script

```bash
./scripts/setup.sh
```

This script will:
- Create necessary directories
- Copy environment template
- Initialize database schema
- Build Docker images

## Configuration

### 1. Edit Environment Variables

```bash
cp config/.env.example .env
nano .env  # or use your preferred editor
```

### 2. Required Configuration

At minimum, set the following:

```bash
# Required
OPENAI_API_KEY=sk-your-actual-openai-key-here

# Optional but recommended
VIRUSTOTAL_API_KEY=your-virustotal-key
ALIENVAULT_API_KEY=your-alienvault-key
```

### 3. Wazuh Integration (Optional)

If you have a Wazuh server running:

```bash
WAZUH_API_URL=https://your-wazuh-server:55000
WAZUH_API_USER=your-username
WAZUH_API_PASSWORD=your-password
```

### 4. Notification Configuration (Optional)

For Slack notifications:

```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

For email notifications:

```bash
EMAIL_SMTP_SERVER=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_FROM=security-lab@yourdomain.com
EMAIL_TO=soc-team@yourdomain.com
EMAIL_PASSWORD=your-app-specific-password
```

## Starting the Lab

### 1. Start All Services

```bash
./scripts/start.sh
```

This will start:
- PostgreSQL database
- Redis cache
- RabbitMQ message queue
- Chroma vector database
- AI agent orchestrator
- Individual AI agents
- Celery workers (workflow automation)
- Grafana dashboard
- Prometheus monitoring

### 2. Wait for Initialization

The first startup takes 2-3 minutes as containers initialize.

## Verification

### 1. Check Service Status

```bash
docker-compose ps
```

All services should show "Up" status.

### 2. Check Agent Logs

```bash
# Threat Detection Agent
docker-compose logs -f threat-detection-agent

# Incident Response Agent
docker-compose logs -f incident-response-agent

# All agents
docker-compose logs -f
```

### 3. Access Web Interfaces

#### Grafana Dashboard
- URL: http://localhost:3000
- Default credentials: admin/admin
- Change password on first login

#### Celery Flower (Task Monitor)
- URL: http://localhost:5555
- Monitor agent tasks and workflows

#### RabbitMQ Management
- URL: http://localhost:15672
- Credentials: seclab/seclab
- View message queues

#### Prometheus
- URL: http://localhost:9090
- Query metrics and alerts

## Using the Lab

### Automated Workflows

The lab runs several automated workflows:

#### 1. Threat Detection (Every Hour)
- Fetches alerts from Wazuh or generates mock data
- Performs ML-based anomaly detection
- Uses LLM for behavioral analysis
- Generates threat alerts

#### 2. Threat Intelligence (Every 4 Hours)
- Gathers IOCs from threat feeds
- Enriches indicators with multiple sources
- Correlates IOCs to identify campaigns
- Generates threat intelligence reports

#### 3. Vulnerability Scanning (Daily at 2 AM)
- Scans all lab assets
- Prioritizes vulnerabilities
- Correlates with active threats

#### 4. Daily SOC Report (8 AM)
- Aggregates all security events
- Generates comprehensive report

### Manual Task Execution

You can trigger agents manually:

#### Run Threat Detection
```bash
docker-compose exec celery-worker python -m agents.threat_detection.agent
```

#### Run Incident Response
```bash
docker-compose exec celery-worker python -m agents.incident_response.agent
```

#### Run Threat Intelligence
```bash
docker-compose exec celery-worker python -m agents.threat_intelligence.agent
```

#### Run Malware Analysis
```bash
docker-compose exec celery-worker python -m agents.malware_analysis.agent
```

### Viewing Results

#### Reports
```bash
# View generated reports
ls -lh data/reports/

# View threat intelligence reports
cat data/reports/threat_intel_*.md

# View incident reports
cat data/reports/INC-*.md
```

#### IOCs
```bash
# View collected IOCs
cat data/iocs/iocs_*.json
```

#### Detection Rules
```bash
# View generated detection rules
ls data/rules/

# View YARA rules
cat data/yara/*.yar
```

## Monitoring and Metrics

### Grafana Dashboards

1. Login to Grafana (http://localhost:3000)
2. Navigate to Dashboards
3. Available dashboards:
   - SOC Operations Overview
   - Agent Performance
   - Threat Landscape
   - Incident Response Metrics

### Celery Task Monitoring

1. Access Flower (http://localhost:5555)
2. View:
   - Active tasks
   - Task history
   - Worker status
   - Task success/failure rates

## Integration with Existing Tools

### Wazuh Integration

The agents can fetch real alerts from Wazuh:

1. Configure Wazuh credentials in `.env`
2. Restart services: `./scripts/stop.sh && ./scripts/start.sh`
3. Agents will automatically fetch and analyze real alerts

### OPNsense Integration

For automated firewall rule updates:

1. Configure OPNsense API credentials
2. Enable automatic blocking of malicious IPs
3. Agents will push threat indicators to firewall

### AWS Security

For cloud security monitoring:

1. Configure AWS credentials
2. Enable GuardDuty and CloudTrail
3. Agents will analyze cloud security events

## Troubleshooting

### Agents Not Starting

```bash
# Check logs
docker-compose logs agent-orchestrator

# Common issue: Missing API key
# Solution: Verify OPENAI_API_KEY in .env
```

### Database Connection Errors

```bash
# Restart database
docker-compose restart postgres

# Check if database is ready
docker-compose exec postgres pg_isready
```

### Out of Memory

```bash
# Reduce number of agent instances
# Edit docker-compose.yml and reduce replicas

# Or increase Docker memory limit
# Docker Desktop -> Settings -> Resources -> Memory
```

### Rate Limiting (OpenAI API)

If you hit rate limits:

1. Reduce detection frequency in `.env`:
   ```bash
   DETECTION_INTERVAL_MINUTES=120  # Increase from 60
   ```

2. Or upgrade your OpenAI plan

### No Alerts Being Generated

If using mock data (no Wazuh integration):
- This is expected behavior
- Agents generate mock alerts for testing
- Configure Wazuh integration for real alerts

## Stopping the Lab

### Graceful Shutdown
```bash
./scripts/stop.sh
```

### Complete Cleanup (Removes All Data)
```bash
docker-compose down -v
```

## Next Steps

1. **Explore Dashboards**: Check Grafana dashboards for visualizations
2. **Review Reports**: Read generated threat intelligence and incident reports
3. **Customize Agents**: Modify agent behavior in `agents/` directory
4. **Add Custom Workflows**: Create new workflows in `workflows/tasks.py`
5. **Integrate Tools**: Connect to your existing security infrastructure
6. **Experiment**: Test different attack scenarios and detection capabilities

## Security Considerations

⚠️ **IMPORTANT**: This lab is for educational purposes only

- Run in isolated network environment
- Do not expose services to the internet
- Protect API keys and credentials
- Malware samples should be handled in isolated VMs
- Follow responsible disclosure for any vulnerabilities found

## Getting Help

- Review logs: `docker-compose logs -f`
- Check architecture: See `AI_ARCHITECTURE.md`
- Review code: Agents are in `agents/` directory
- Check issues: GitHub issues (if applicable)

## Cost Estimates

### OpenAI API Usage
- Light usage (testing): $5-10/month
- Moderate usage (active): $20-50/month
- Heavy usage (production): $100+/month

Costs depend on:
- Number of alerts analyzed
- Frequency of agent execution
- Model used (GPT-4 vs GPT-3.5)

### Infrastructure
- Local deployment: Free (just electricity)
- Cloud deployment: $50-200/month depending on instance sizes

## Advanced Configuration

### Custom Agent Development

See `agents/README.md` for agent development guide.

### Custom Workflows

See `workflows/README.md` for workflow development guide.

### Performance Tuning

Edit `docker-compose.yml` to adjust:
- Worker concurrency
- Task rate limits
- Memory limits

## License

Educational and research use only. See LICENSE file.
