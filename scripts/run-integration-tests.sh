#!/bin/bash
# run-integration-tests.sh
# Run Django integration tests with full service stack
# Usage: ./scripts/run-integration-tests.sh [--full] [pytest-args]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔗 HookProbe Integration Tests - ARM64${NC}"
echo "============================================"
echo ""

# Check if podman-compose is available
if ! command -v podman-compose &> /dev/null; then
    echo -e "${YELLOW}Warning: podman-compose not found. Installing...${NC}"
    pip3 install podman-compose || {
        echo -e "${RED}Error: Failed to install podman-compose${NC}"
        echo -e "${YELLOW}Please install manually: pip3 install podman-compose${NC}"
        exit 1
    }
fi

COMPOSE_CMD="podman-compose"

# Parse arguments
PROFILE=""
PYTEST_ARGS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --full)
            PROFILE="--profile full-integration"
            echo -e "${YELLOW}Running full integration tests (including IAM)${NC}"
            shift
            ;;
        *)
            PYTEST_ARGS="$PYTEST_ARGS $1"
            shift
            ;;
    esac
done

# Default pytest args if none provided
PYTEST_ARGS="${PYTEST_ARGS:-tests/integration/}"

echo -e "${YELLOW}Test target:${NC} $PYTEST_ARGS"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo -e "${YELLOW}🧹 Cleaning up...${NC}"
    $COMPOSE_CMD -f docker-compose.test.yml down -v
    echo -e "${GREEN}✓ Cleanup complete${NC}"
}

# Register cleanup on exit
trap cleanup EXIT

# Start services
echo -e "${BLUE}🚀 Starting test services...${NC}"
$COMPOSE_CMD -f docker-compose.test.yml $PROFILE up -d

# Wait for services to be healthy
echo ""
echo -e "${YELLOW}⏳ Waiting for services to be ready...${NC}"
sleep 10

# Check service health
echo -e "${BLUE}🏥 Checking service health...${NC}"
$COMPOSE_CMD -f docker-compose.test.yml ps

# Wait for database to be ready
MAX_TRIES=30
TRIES=0
until $COMPOSE_CMD -f docker-compose.test.yml exec -T db-test pg_isready -U hookprobe > /dev/null 2>&1; do
    TRIES=$((TRIES+1))
    if [ $TRIES -ge $MAX_TRIES ]; then
        echo -e "${RED}❌ Database did not become ready in time${NC}"
        exit 1
    fi
    echo -n "."
    sleep 1
done
echo ""
echo -e "${GREEN}✓ Database is ready${NC}"

# Wait for Redis to be ready
until $COMPOSE_CMD -f docker-compose.test.yml exec -T redis-test redis-cli ping > /dev/null 2>&1; do
    echo -n "."
    sleep 1
done
echo -e "${GREEN}✓ Redis is ready${NC}"
echo ""

# Run migrations
echo -e "${BLUE}🗄️  Running database migrations...${NC}"
$COMPOSE_CMD -f docker-compose.test.yml exec -T web-test \
    python manage.py migrate --noinput || {
    echo -e "${RED}❌ Migrations failed${NC}"
    exit 1
}
echo -e "${GREEN}✓ Migrations completed${NC}"
echo ""

# Collect static files (optional)
echo -e "${BLUE}📦 Collecting static files...${NC}"
$COMPOSE_CMD -f docker-compose.test.yml exec -T web-test \
    python manage.py collectstatic --noinput --clear || true
echo ""

# Run integration tests
echo -e "${BLUE}🧪 Running integration tests...${NC}"
echo ""

$COMPOSE_CMD -f docker-compose.test.yml exec -T web-test \
    pytest $PYTEST_ARGS -v --tb=short

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✅ Integration tests completed successfully${NC}"
else
    echo -e "${RED}❌ Integration tests failed with exit code: $EXIT_CODE${NC}"
fi

# Show logs on failure
if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo -e "${YELLOW}📋 Service logs:${NC}"
    $COMPOSE_CMD -f docker-compose.test.yml logs --tail=50
fi

echo ""

exit $EXIT_CODE
