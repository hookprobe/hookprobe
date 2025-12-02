#!/bin/bash
# run-unit-tests.sh
# Run Django unit tests in ARM64 container
# Usage: ./scripts/run-unit-tests.sh [pytest-args]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🧪 HookProbe Unit Tests - ARM64${NC}"
echo "========================================"
echo ""

# Detect platform
PLATFORM="${PLATFORM:-linux/arm64}"
echo -e "${YELLOW}Target platform:${NC} $PLATFORM"
echo ""

# Check if Podman is available (required)
if command -v podman &> /dev/null; then
    CONTAINER_CMD="podman"
else
    echo -e "${RED}Error: Podman not found. Please install podman.${NC}"
    exit 1
fi

echo -e "${YELLOW}Using:${NC} $CONTAINER_CMD"
echo ""

# Build test image
echo -e "${BLUE}📦 Building test image...${NC}"
$CONTAINER_CMD build \
  --arch arm64 \
  -t hookprobe-web-test:latest \
  -f src/web/Dockerfile.test \
  src/web || {
    echo -e "${RED}❌ Build failed${NC}"
    exit 1
  }

echo -e "${GREEN}✓ Build successful${NC}"
echo ""

# Run unit tests
echo -e "${BLUE}🧪 Running unit tests...${NC}"
echo ""

# Pass any additional pytest arguments
PYTEST_ARGS="${@:-tests/}"

$CONTAINER_CMD run --rm \
  -e DJANGO_ENV=test \
  -e DJANGO_SETTINGS_MODULE=hookprobe.settings.test \
  -e POSTGRES_DB=hookprobe_test \
  -e POSTGRES_USER=hookprobe \
  -e POSTGRES_PASSWORD=test_password \
  -e POSTGRES_HOST=localhost \
  -e REDIS_HOST=localhost \
  hookprobe-web-test:latest \
  pytest --cov=apps --cov-report=term-missing --cov-report=html -v $PYTEST_ARGS

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✅ Unit tests completed successfully${NC}"
else
    echo -e "${RED}❌ Unit tests failed with exit code: $EXIT_CODE${NC}"
fi

echo ""
echo -e "${YELLOW}Coverage report saved to:${NC} htmlcov/index.html"
echo ""

exit $EXIT_CODE
