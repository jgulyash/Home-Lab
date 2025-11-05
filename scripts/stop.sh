#!/bin/bash
set -e

echo "================================================"
echo "Stopping AI-Powered Cybersecurity Home Lab"
echo "================================================"
echo ""

docker-compose down

echo ""
echo "✅ Lab stopped successfully"
echo ""
echo "To start again: ./scripts/start.sh"
echo "To remove all data: docker-compose down -v"
echo ""
