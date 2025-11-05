# Quick Deployment Guide

## Prerequisites Checklist

Before deploying, ensure you have:

- [ ] **Docker Desktop** installed and running
  - macOS: Download from https://www.docker.com/products/docker-desktop
  - Minimum 8GB RAM allocated to Docker
  - At least 50GB free disk space

- [ ] **OpenAI API Key** (Required for AI agents)
  - Sign up at https://platform.openai.com/
  - Create API key at https://platform.openai.com/api-keys
  - Cost: ~$20-50/month for moderate usage

- [ ] **Git** (already have this ✓)

## Step-by-Step Deployment

### Step 1: Navigate to the Repository

```bash
cd /home/user/Home-Lab
```

### Step 2: Run Setup Script

```bash
chmod +x scripts/*.sh
./scripts/setup.sh
```

This will:
- Create necessary directories
- Copy environment template (.env)
- Initialize database schema
- Build Docker images (takes 5-10 minutes first time)

### Step 3: Configure Environment Variables

```bash
# Edit the .env file
nano .env
```

**Minimum required configuration:**

```bash
# REQUIRED: Add your OpenAI API key
OPENAI_API_KEY=sk-your-actual-openai-key-here

# Optional but recommended
VIRUSTOTAL_API_KEY=your-key-here
ALIENVAULT_API_KEY=your-key-here
```

**Save and exit**: `Ctrl+X`, then `Y`, then `Enter`

### Step 4: Start the Lab

```bash
./scripts/start.sh
```

This starts all services:
- ✅ PostgreSQL Database
- ✅ Redis Cache
- ✅ RabbitMQ Message Queue
- ✅ Chroma Vector Database
- ✅ AI Agent Orchestrator
- ✅ Threat Detection Agent
- ✅ Incident Response Agent
- ✅ Threat Intelligence Agent
- ✅ Celery Workers
- ✅ Grafana Dashboard
- ✅ Prometheus Monitoring

**Wait 2-3 minutes for all services to initialize.**

### Step 5: Verify Deployment

```bash
# Check if all containers are running
docker-compose ps

# Should see all services with "Up" status
```

### Step 6: Access the Dashboards

Open in your browser:

1. **Grafana Dashboard**: http://localhost:3000
   - Username: `admin`
   - Password: `admin`
   - Change password when prompted

2. **Celery Flower** (Task Monitor): http://localhost:5555
   - Monitor agent tasks and workflows

3. **RabbitMQ Management**: http://localhost:15672
   - Username: `seclab`
   - Password: `seclab`

4. **Prometheus**: http://localhost:9090

### Step 7: Verify Agents Are Working

```bash
# Check threat detection agent logs
docker-compose logs -f threat-detection-agent

# Check all agent logs
docker-compose logs -f

# You should see logs like:
# "Threat Detection Agent initialized"
# "Starting threat detection cycle"
```

### Step 8: Trigger Manual Test

```bash
# Manually run threat detection
docker-compose exec celery-worker python -m agents.threat_detection.agent

# Manually run incident response
docker-compose exec celery-worker python -m agents.incident_response.agent

# Manually run threat intelligence
docker-compose exec celery-worker python -m agents.threat_intelligence.agent
```

### Step 9: View Generated Reports

```bash
# View all generated reports
ls -lh data/reports/

# View threat intelligence reports
cat data/reports/threat_intel_*.md

# View incident reports
cat data/reports/INC-*.md

# View collected IOCs
cat data/iocs/iocs_*.json
```

## Common Issues & Solutions

### Issue: Docker not running
```bash
# macOS: Start Docker Desktop from Applications
open -a Docker

# Wait for Docker to start (whale icon in menu bar)
```

### Issue: Port already in use
```bash
# Check what's using the port
lsof -i :3000  # or :5555, :15672, etc.

# Kill the process or change ports in docker-compose.yml
```

### Issue: Out of memory
```bash
# Increase Docker memory
# Docker Desktop → Settings → Resources → Memory
# Increase to at least 8GB
```

### Issue: "OPENAI_API_KEY not set" warning
```bash
# Edit .env and add your API key
nano .env

# Then restart
./scripts/stop.sh
./scripts/start.sh
```

### Issue: Containers fail to start
```bash
# View logs for specific service
docker-compose logs [service-name]

# Rebuild images
docker-compose build --no-cache

# Start again
./scripts/start.sh
```

## Stopping the Lab

```bash
# Graceful shutdown (keeps data)
./scripts/stop.sh

# Complete cleanup (removes all data)
docker-compose down -v
```

## What Happens After Deployment?

### Automated Workflows (No Action Needed)

The lab automatically runs:

1. **Every Hour**: Threat detection cycle
   - Analyzes alerts with ML + LLM
   - Generates threat reports

2. **Every 4 Hours**: Threat intelligence gathering
   - Collects IOCs from feeds
   - Enriches and correlates data
   - Identifies campaigns

3. **Daily at 2 AM**: Vulnerability scanning
   - Scans lab assets
   - Prioritizes vulnerabilities

4. **Daily at 8 AM**: SOC report generation
   - Comprehensive daily summary

5. **Every 15 Minutes**: Health checks
   - Monitors all services

### Monitoring the Lab

**Option 1: Grafana (Recommended)**
- URL: http://localhost:3000
- Visual dashboards with metrics

**Option 2: Flower**
- URL: http://localhost:5555
- See all tasks and their status

**Option 3: Command Line**
```bash
# Follow all logs
docker-compose logs -f

# Follow specific agent
docker-compose logs -f threat-detection-agent
```

## Integration with Your Existing Infrastructure

### Connect to Real Wazuh Server

If you have Wazuh running:

```bash
# Edit .env
nano .env

# Add Wazuh connection details
WAZUH_API_URL=https://your-wazuh-server:55000
WAZUH_API_USER=your-username
WAZUH_API_PASSWORD=your-password

# Restart
./scripts/stop.sh
./scripts/start.sh
```

Now agents will fetch REAL alerts from your Wazuh server!

### Connect to OPNsense Firewall

```bash
# Edit .env
OPNSENSE_API_URL=https://your-opnsense-firewall
OPNSENSE_API_KEY=your-api-key
OPNSENSE_API_SECRET=your-api-secret
```

Agents will automatically update firewall rules with threat IOCs!

## Getting Optional API Keys

### VirusTotal (Free Tier Available)
1. Sign up: https://www.virustotal.com/gui/join-us
2. Get API key: https://www.virustotal.com/gui/my-apikey
3. Add to .env: `VIRUSTOTAL_API_KEY=your-key`

### AlienVault OTX (Free)
1. Sign up: https://otx.alienvault.com/
2. Get API key: Settings → API Integration
3. Add to .env: `ALIENVAULT_API_KEY=your-key`

### AbuseIPDB (Free Tier)
1. Sign up: https://www.abuseipdb.com/register
2. Get API key: https://www.abuseipdb.com/account/api
3. Add to .env: `ABUSEIPDB_API_KEY=your-key`

## Testing the Lab

### Simulate a Threat Detection Scenario

```bash
# Run threat detection manually
docker-compose exec celery-worker python -m agents.threat_detection.agent

# Check for generated alerts
ls -lh data/reports/
```

### Simulate an Incident

```bash
# Trigger incident response
docker-compose exec celery-worker python -m agents.incident_response.agent

# View incident report
cat data/reports/INC-*.md
```

### Generate Threat Intelligence Report

```bash
# Run threat intel cycle
docker-compose exec celery-worker python -m agents.threat_intelligence.agent

# View report
cat data/reports/threat_intel_*.md
```

## Performance Tuning

### Reduce API Costs

Edit `.env`:
```bash
# Run less frequently
DETECTION_INTERVAL_MINUTES=120  # Every 2 hours instead of 1
THREAT_INTEL_INTERVAL_HOURS=8   # Every 8 hours instead of 4
```

### Use GPT-3.5 Instead of GPT-4

Edit agent files to use `gpt-3.5-turbo` instead of `gpt-4`:
```python
# In agents/*/agent.py
model="gpt-3.5-turbo"  # Cheaper, faster, less accurate
```

## Next Steps

1. ✅ Deploy and verify all services are running
2. 📊 Explore Grafana dashboards
3. 📝 Review generated reports in `data/reports/`
4. 🔌 Connect to your existing security tools (Wazuh, OPNsense)
5. 🎯 Customize agents for your specific use cases
6. 📚 Read AI_ARCHITECTURE.md for deep dive

## Need Help?

- **Setup Issues**: See SETUP.md for detailed troubleshooting
- **Architecture Questions**: See AI_ARCHITECTURE.md
- **Docker Issues**: Run `docker-compose logs [service-name]`
- **Agent Errors**: Check logs in `data/logs/`

## Security Note

⚠️ This lab should run in an **isolated environment**:
- Do not expose ports to the internet
- Use for educational/research purposes only
- Keep API keys secure
- Run in a separate network from production systems

---

**You're all set! The AI agents will start working automatically.** 🚀
