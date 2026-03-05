#!/usr/bin/env bash
set -euo pipefail

# Setup script for test Docker infrastructure
# Pull images and start containers defined in docker-compose.yml

COMPOSE_FILE="$( dirname "${BASH_SOURCE[0]}" )/docker-compose.yml"
EVIDENCE_DIR="/c/Users/$(whoami)/.sisyphus/evidence" || EVIDENCE_DIR="$(pwd)/.sisyphus/evidence"
mkdir -p "${EVIDENCE_DIR}"

echo "Using compose file: ${COMPOSE_FILE}"
echo "Pulling images..."
docker-compose -f "${COMPOSE_FILE}" pull 2>&1 | tee "${EVIDENCE_DIR}/task-1-docker-start.log"

echo "Starting containers..."
docker-compose -f "${COMPOSE_FILE}" up -d --wait 2>&1 | tee -a "${EVIDENCE_DIR}/task-1-docker-start.log"

echo "Waiting 30s for services to initialize..."
sleep 30

echo "Listing running containers..." | tee -a "${EVIDENCE_DIR}/task-1-docker-start.log"
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" | tee -a "${EVIDENCE_DIR}/task-1-docker-start.log"

echo "Health checks" | tee "${EVIDENCE_DIR}/task-1-health-checks.txt"
curl -f -m 10 http://127.0.0.1:8080/login.php >> "${EVIDENCE_DIR}/task-1-health-checks.txt" 2>&1 || echo "DVWA unreachable" >> "${EVIDENCE_DIR}/task-1-health-checks.txt"
curl -f -m 10 http://127.0.0.1:9001/WebGoat/login >> "${EVIDENCE_DIR}/task-1-health-checks.txt" 2>&1 || echo "WebGoat unreachable" >> "${EVIDENCE_DIR}/task-1-health-checks.txt"

echo "Setup complete. Evidence saved to ${EVIDENCE_DIR}"
