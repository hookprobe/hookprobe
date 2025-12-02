#!/bin/bash
# run-performance-tests.sh
# Run performance baseline tests for HookProbe on ARM64
# Usage: ./scripts/run-performance-tests.sh [--requests N] [--concurrency N]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}📊 HookProbe Performance Tests - ARM64${NC}"
echo "=============================================="
echo ""

# Check if podman-compose is available
if ! command -v podman-compose &> /dev/null; then
    echo -e "${YELLOW}Warning: podman-compose not found. Installing...${NC}"
    pip3 install podman-compose || {
        echo -e "${RED}Error: Failed to install podman-compose${NC}"
        exit 1
    }
fi

COMPOSE_CMD="podman-compose"

# Default test parameters
REQUESTS=1000
CONCURRENCY=10
TEST_URL="/"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --requests|-n)
            REQUESTS="$2"
            shift 2
            ;;
        --concurrency|-c)
            CONCURRENCY="$2"
            shift 2
            ;;
        --url)
            TEST_URL="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

echo -e "${YELLOW}Test parameters:${NC}"
echo "  Requests: $REQUESTS"
echo "  Concurrency: $CONCURRENCY"
echo "  Target URL: $TEST_URL"
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
$COMPOSE_CMD -f docker-compose.test.yml up -d

# Wait for services
echo ""
echo -e "${YELLOW}⏳ Waiting for services to be ready...${NC}"
sleep 15

# Get web container IP
WEB_CONTAINER="hookprobe-web-test"
WEB_PORT=8000

# Wait for web service to be ready
MAX_TRIES=60
TRIES=0
until podman exec $WEB_CONTAINER curl -sf http://localhost:$WEB_PORT/ > /dev/null 2>&1; do
    TRIES=$((TRIES+1))
    if [ $TRIES -ge $MAX_TRIES ]; then
        echo -e "${RED}❌ Web service did not become ready in time${NC}"
        exit 1
    fi
    echo -n "."
    sleep 1
done
echo ""
echo -e "${GREEN}✓ Web service is ready${NC}"
echo ""

# Run migrations
echo -e "${BLUE}🗄️  Running database migrations...${NC}"
$COMPOSE_CMD -f docker-compose.test.yml exec -T web-test \
    python manage.py migrate --noinput
echo -e "${GREEN}✓ Migrations completed${NC}"
echo ""

# Create test data
echo -e "${BLUE}📝 Creating test data...${NC}"
$COMPOSE_CMD -f docker-compose.test.yml exec -T web-test \
    python manage.py seed_demo_data || echo "Demo data seeding skipped"
echo ""

# Performance baseline tests
echo -e "${BLUE}📊 Running performance tests...${NC}"
echo ""

# Create results directory
RESULTS_DIR="test-results/performance-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RESULTS_DIR"

# Test 1: Apache Bench
echo -e "${YELLOW}Test 1: Apache Bench${NC}"
if command -v ab &> /dev/null; then
    podman exec $WEB_CONTAINER ab \
        -n $REQUESTS \
        -c $CONCURRENCY \
        http://localhost:$WEB_PORT$TEST_URL \
        > "$RESULTS_DIR/ab-results.txt" 2>&1

    echo -e "${GREEN}✓ Apache Bench test completed${NC}"

    # Extract key metrics
    echo ""
    echo -e "${BLUE}Key Metrics:${NC}"
    grep "Requests per second:" "$RESULTS_DIR/ab-results.txt" || true
    grep "Time per request:" "$RESULTS_DIR/ab-results.txt" || true
    grep "Transfer rate:" "$RESULTS_DIR/ab-results.txt" || true
else
    echo -e "${YELLOW}⚠ Apache Bench (ab) not installed, skipping${NC}"
fi
echo ""

# Test 2: Resource monitoring during load
echo -e "${YELLOW}Test 2: Resource Monitoring${NC}"
echo "Monitoring resources during load test..."

# Start resource monitoring in background
podman stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}" \
    > "$RESULTS_DIR/resource-usage.txt" &
STATS_PID=$!

# Run a load test with wget
echo "Running load test..."
for i in $(seq 1 100); do
    podman exec $WEB_CONTAINER curl -sf http://localhost:$WEB_PORT$TEST_URL > /dev/null &
done
wait

# Wait for stats to finish
sleep 2
kill $STATS_PID 2>/dev/null || true

echo -e "${GREEN}✓ Resource monitoring completed${NC}"
echo ""
echo -e "${BLUE}Resource Usage:${NC}"
cat "$RESULTS_DIR/resource-usage.txt"
echo ""

# Test 3: Response time distribution
echo -e "${YELLOW}Test 3: Response Time Distribution${NC}"
echo "Measuring response times..."

RESPONSE_TIMES_FILE="$RESULTS_DIR/response-times.txt"
> "$RESPONSE_TIMES_FILE"

for i in $(seq 1 50); do
    START=$(date +%s%N)
    podman exec $WEB_CONTAINER curl -sf http://localhost:$WEB_PORT$TEST_URL > /dev/null
    END=$(date +%s%N)
    DURATION=$(( (END - START) / 1000000 ))  # Convert to milliseconds
    echo "$DURATION" >> "$RESPONSE_TIMES_FILE"
done

# Calculate statistics
if command -v awk &> /dev/null; then
    AVG=$(awk '{ sum += $1; n++ } END { if (n > 0) print sum / n; }' "$RESPONSE_TIMES_FILE")
    MIN=$(sort -n "$RESPONSE_TIMES_FILE" | head -1)
    MAX=$(sort -n "$RESPONSE_TIMES_FILE" | tail -1)

    echo -e "${GREEN}✓ Response time test completed${NC}"
    echo ""
    echo -e "${BLUE}Response Times (ms):${NC}"
    echo "  Average: ${AVG}ms"
    echo "  Min: ${MIN}ms"
    echo "  Max: ${MAX}ms"
fi
echo ""

# Generate summary report
echo -e "${BLUE}📋 Generating summary report...${NC}"
SUMMARY_FILE="$RESULTS_DIR/summary.txt"

cat > "$SUMMARY_FILE" <<EOF
HookProbe Performance Test Report
==================================
Date: $(date)
Platform: ARM64
Container Runtime: Podman

Test Configuration
------------------
Requests: $REQUESTS
Concurrency: $CONCURRENCY
Target URL: $TEST_URL

Test Results
------------
$(if [ -f "$RESULTS_DIR/ab-results.txt" ]; then
    echo "Apache Bench Results:"
    grep "Requests per second:" "$RESULTS_DIR/ab-results.txt" || echo "N/A"
    grep "Time per request:" "$RESULTS_DIR/ab-results.txt" || echo "N/A"
    grep "Failed requests:" "$RESULTS_DIR/ab-results.txt" || echo "N/A"
fi)

Resource Usage
--------------
$(cat "$RESULTS_DIR/resource-usage.txt" 2>/dev/null || echo "N/A")

Response Time Statistics
------------------------
$(if [ -n "$AVG" ]; then
    echo "Average: ${AVG}ms"
    echo "Min: ${MIN}ms"
    echo "Max: ${MAX}ms"
else
    echo "N/A"
fi)

Test Files
----------
Results saved to: $RESULTS_DIR/
- ab-results.txt: Apache Bench detailed results
- resource-usage.txt: Container resource usage
- response-times.txt: Individual response times
- summary.txt: This summary report
EOF

echo -e "${GREEN}✓ Summary report generated${NC}"
echo ""

# Display summary
cat "$SUMMARY_FILE"

echo ""
echo -e "${GREEN}✅ Performance tests completed successfully${NC}"
echo -e "${YELLOW}Results saved to:${NC} $RESULTS_DIR/"
echo ""

exit 0
