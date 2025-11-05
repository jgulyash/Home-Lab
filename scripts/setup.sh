#!/bin/bash
set -e

echo "================================================"
echo "AI-Powered Cybersecurity Home Lab Setup"
echo "================================================"
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "Creating .env file from template..."
    cp config/.env.example .env
    echo "⚠️  Please edit .env file with your API keys and configuration"
    echo ""
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Docker and Docker Compose are installed"
echo ""

# Create necessary directories
echo "Creating data directories..."
mkdir -p data/{logs,reports,iocs,models,rules,yara}
mkdir -p data/reports/{incidents,malware,threat_intel}
echo "✅ Directories created"
echo ""

# Initialize database
echo "Setting up database..."
cat > scripts/init-db.sql << 'EOF'
-- Security Lab Database Schema

CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(50) UNIQUE NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity VARCHAR(20),
    status VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS threat_alerts (
    id SERIAL PRIMARY KEY,
    alert_id VARCHAR(50) UNIQUE NOT NULL,
    severity VARCHAR(20),
    threat_type VARCHAR(50),
    description TEXT,
    confidence FLOAT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS iocs (
    id SERIAL PRIMARY KEY,
    ioc_type VARCHAR(20),
    value TEXT NOT NULL,
    confidence FLOAT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sources TEXT[]
);

CREATE TABLE IF NOT EXISTS detection_rules (
    id SERIAL PRIMARY KEY,
    rule_id VARCHAR(50) UNIQUE NOT NULL,
    platform VARCHAR(20),
    name TEXT,
    severity VARCHAR(20),
    rule_content TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
EOF

echo "✅ Database schema created"
echo ""

# Build Docker images
echo "Building Docker images..."
docker-compose build
echo "✅ Docker images built"
echo ""

echo "================================================"
echo "Setup Complete!"
echo "================================================"
echo ""
echo "Next steps:"
echo "1. Edit .env file with your API keys and configuration"
echo "2. Start the lab: ./scripts/start.sh"
echo "3. Access dashboards:"
echo "   - Grafana: http://localhost:3000 (admin/admin)"
echo "   - Flower (Celery): http://localhost:5555"
echo "   - RabbitMQ: http://localhost:15672 (seclab/seclab)"
echo ""
echo "For more information, see docs/SETUP.md"
echo ""
