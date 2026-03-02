#!/bin/bash
# POD-002: Logto IAM Setup Script
#
# This script:
# 1. Creates the Logto database in PostgreSQL (POD-003)
# 2. Deploys Logto container
# 3. Waits for Logto to be ready
# 4. Outputs the admin console URL
#
# Usage:
#   sudo ./setup.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${GREEN}=== HookProbe Logto IAM Setup ===${NC}"

# Load environment variables
if [ -f .env ]; then
    source .env
else
    echo -e "${YELLOW}No .env file found. Creating from example...${NC}"
    cp .env.example .env
    echo -e "${RED}Please edit .env with your PostgreSQL password and run again.${NC}"
    echo "  nano $SCRIPT_DIR/.env"
    exit 1
fi

# Validate required variables
if [ -z "$POSTGRES_PASSWORD" ] || [ "$POSTGRES_PASSWORD" = "CHANGE_ME_SECURE_PASSWORD" ]; then
    echo -e "${RED}ERROR: POSTGRES_PASSWORD not set in .env${NC}"
    echo "Please edit .env and set a secure password."
    exit 1
fi

POSTGRES_HOST="${POSTGRES_HOST:-10.200.3.12}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_DB="${POSTGRES_DB:-logto}"
POSTGRES_USER="${POSTGRES_USER:-logto}"
LOGTO_ENDPOINT="${LOGTO_ENDPOINT:-http://localhost:3001}"
LOGTO_ADMIN_ENDPOINT="${LOGTO_ADMIN_ENDPOINT:-http://localhost:3002}"

echo -e "${YELLOW}Configuration:${NC}"
echo "  PostgreSQL: $POSTGRES_HOST:$POSTGRES_PORT"
echo "  Database: $POSTGRES_DB"
echo "  User: $POSTGRES_USER"
echo "  Logto API: $LOGTO_ENDPOINT"
echo "  Logto Admin: $LOGTO_ADMIN_ENDPOINT"
echo ""

# Step 1: Create PostgreSQL database
echo -e "${YELLOW}Step 1: Creating PostgreSQL database...${NC}"

# Check if we can connect to PostgreSQL
if command -v psql &> /dev/null; then
    # Try to create database and user
    PGPASSWORD="${POSTGRES_PASSWORD}" psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U postgres -tc \
        "SELECT 1 FROM pg_database WHERE datname = '$POSTGRES_DB'" | grep -q 1 || {
        echo "Creating database $POSTGRES_DB..."
        PGPASSWORD="${POSTGRES_PASSWORD}" psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U postgres <<EOF
CREATE USER $POSTGRES_USER WITH PASSWORD '$POSTGRES_PASSWORD';
CREATE DATABASE $POSTGRES_DB OWNER $POSTGRES_USER;
GRANT ALL PRIVILEGES ON DATABASE $POSTGRES_DB TO $POSTGRES_USER;
EOF
        echo -e "${GREEN}Database created successfully.${NC}"
    }
    echo -e "${GREEN}Database $POSTGRES_DB exists.${NC}"
else
    echo -e "${YELLOW}psql not found. Please ensure PostgreSQL database exists:${NC}"
    echo "  CREATE DATABASE $POSTGRES_DB;"
    echo "  CREATE USER $POSTGRES_USER WITH PASSWORD 'your_password';"
    echo "  GRANT ALL PRIVILEGES ON DATABASE $POSTGRES_DB TO $POSTGRES_USER;"
fi

# Step 2: Deploy Logto container
echo -e "${YELLOW}Step 2: Deploying Logto container...${NC}"

# Stop existing container if running
podman-compose down 2>/dev/null || true

# Start Logto
podman-compose up -d

echo -e "${GREEN}Logto container started.${NC}"

# Step 3: Wait for Logto to be ready
echo -e "${YELLOW}Step 3: Waiting for Logto to be ready...${NC}"

MAX_RETRIES=30
RETRY_INTERVAL=5
RETRIES=0

while [ $RETRIES -lt $MAX_RETRIES ]; do
    if curl -s "http://localhost:3001/health" | grep -q "healthy"; then
        echo -e "${GREEN}Logto is ready!${NC}"
        break
    fi
    RETRIES=$((RETRIES + 1))
    echo "  Waiting for Logto... (attempt $RETRIES/$MAX_RETRIES)"
    sleep $RETRY_INTERVAL
done

if [ $RETRIES -eq $MAX_RETRIES ]; then
    echo -e "${RED}Logto did not become ready in time.${NC}"
    echo "Check logs: podman logs hookprobe-logto"
    exit 1
fi

# Step 4: Output information
echo ""
echo -e "${GREEN}=== Logto IAM Deployed Successfully ===${NC}"
echo ""
echo "Admin Console: $LOGTO_ADMIN_ENDPOINT"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Open the Admin Console and complete initial setup"
echo "2. Create OIDC applications for:"
echo "   - hookprobe.com (Redirect: https://hookprobe.com/oidc/callback/)"
echo "   - mssp.hookprobe.com (Redirect: https://mssp.hookprobe.com/oidc/callback/)"
echo "3. Create roles: admin, soc_analyst, editor, customer"
echo "4. Note the Client IDs and Secrets for each application"
echo ""
echo "Environment variables to set in your applications:"
echo "  LOGTO_ENDPOINT=$LOGTO_ENDPOINT"
echo "  LOGTO_APP_ID=<your-client-id>"
echo "  LOGTO_APP_SECRET=<your-client-secret>"
