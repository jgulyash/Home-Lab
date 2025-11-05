#!/bin/bash
set -e

echo "================================================"
echo "Starting AI-Powered Cybersecurity Home Lab"
echo "================================================"
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "❌ .env file not found. Run ./scripts/setup.sh first"
    exit 1
fi

# Load environment variables
source .env

# Check if required API keys are set
if [ -z "$OPENAI_API_KEY" ] || [ "$OPENAI_API_KEY" = "your_openai_api_key_here" ]; then
    echo "⚠️  Warning: OPENAI_API_KEY not set in .env file"
    echo "   AI agents will not function without an API key"
    echo ""
fi

echo "Starting services..."
docker-compose up -d

echo ""
echo "Waiting for services to start..."
sleep 10

echo ""
echo "================================================"
echo "Lab Started Successfully!"
echo "================================================"
echo ""
echo "Services running:"
echo "  ✅ PostgreSQL Database"
echo "  ✅ Redis Cache"
echo "  ✅ RabbitMQ Message Queue"
echo "  ✅ Chroma Vector Database"
echo "  ✅ AI Agent Orchestrator"
echo "  ✅ Threat Detection Agent"
echo "  ✅ Incident Response Agent"
echo "  ✅ Threat Intelligence Agent"
echo "  ✅ Celery Workers"
echo "  ✅ Grafana Dashboard"
echo "  ✅ Prometheus Monitoring"
echo ""
echo "Access points:"
echo "  📊 Grafana: http://localhost:3000"
echo "  🌺 Flower: http://localhost:5555"
echo "  🐰 RabbitMQ: http://localhost:15672"
echo "  📈 Prometheus: http://localhost:9090"
echo ""
echo "View logs:"
echo "  docker-compose logs -f [service-name]"
echo ""
echo "Stop lab:"
echo "  ./scripts/stop.sh"
echo ""
