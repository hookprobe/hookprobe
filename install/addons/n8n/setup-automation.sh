#!/bin/bash
#
# setup-automation.sh - Deploy HookProbe N8N Automation with QSECBIT Integration
# Version: 2.0 - Threat Intelligence Edition
#
# This script deploys the enhanced automation framework with:
# - QSECBIT-integrated workflows
# - Enhanced MCP server with threat intelligence
# - ClickHouse schemas for automation data
# - Automated response engine
#

set -e
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================================"
echo "   HOOKPROBE N8N AUTOMATION FRAMEWORK DEPLOYMENT"
echo "   Version 2.0 - QSECBIT Integration Edition"
echo "============================================================"
echo ""

# Check if main n8n setup was run first
if ! podman pod exists hookprobe-pod-008-automation 2>/dev/null; then
    echo "ERROR: POD 008 not found. Please run setup.sh first:"
    echo "  sudo ./setup.sh"
    exit 1
fi

echo "✓ POD 008 found"

# ============================================================
# STEP 1: INITIALIZE CLICKHOUSE SCHEMAS
# ============================================================
echo ""
echo "[STEP 1] Initializing ClickHouse schemas for automation..."

if [ -f "$SCRIPT_DIR/clickhouse-schemas.sql" ]; then
    echo "  → Creating security database and tables..."

    # Read and execute SQL file
    if command -v clickhouse-client &> /dev/null; then
        clickhouse-client --host 10.200.5.13 --multiquery < "$SCRIPT_DIR/clickhouse-schemas.sql"
        echo "✓ ClickHouse schemas created"
    else
        echo "  → clickhouse-client not found, using HTTP API..."
        # Send SQL via HTTP
        while IFS= read -r line; do
            # Skip comments and empty lines
            if [[ ! "$line" =~ ^-- ]] && [[ -n "$line" ]]; then
                curl -s -X POST "http://10.200.5.13:8123/" --data-binary "$line" > /dev/null
            fi
        done < "$SCRIPT_DIR/clickhouse-schemas.sql"
        echo "✓ ClickHouse schemas created via HTTP"
    fi
else
    echo "⚠️  WARNING: clickhouse-schemas.sql not found, skipping"
fi

# ============================================================
# STEP 2: REBUILD MCP SERVER WITH ENHANCED FEATURES
# ============================================================
echo ""
echo "[STEP 2] Rebuilding MCP server with threat intelligence..."

MCP_BUILD_DIR="/tmp/mcp-server-automation-build"
rm -rf "$MCP_BUILD_DIR"
mkdir -p "$MCP_BUILD_DIR"

# Copy enhanced MCP server
if [ -f "$SCRIPT_DIR/mcp-server-enhanced.py" ]; then
    cp "$SCRIPT_DIR/mcp-server-enhanced.py" "$MCP_BUILD_DIR/mcp_server.py"
else
    echo "ERROR: mcp-server-enhanced.py not found"
    exit 1
fi

# Create requirements.txt
cat > "$MCP_BUILD_DIR/requirements.txt" << 'EOF'
Flask==3.0.0
flask-limiter==3.5.0
requests==2.31.0
python-dotenv==1.0.0
gunicorn==21.2.0
redis==5.0.1
EOF

# Create Dockerfile
cat > "$MCP_BUILD_DIR/Dockerfile" << 'EOF'
FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    nmap \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY mcp_server.py .

EXPOSE 8889

CMD ["gunicorn", "--bind", "0.0.0.0:8889", "--workers", "4", "--timeout", "300", "mcp_server:app"]
EOF

echo "  → Building enhanced MCP server image..."
cd "$MCP_BUILD_DIR"
podman build -t hookprobe-mcp-server:2.0 .

# Stop and remove old MCP container
if podman ps -a | grep -q hookprobe-pod-008-automation-mcp; then
    echo "  → Stopping old MCP server..."
    podman stop hookprobe-pod-008-automation-mcp 2>/dev/null || true
    podman rm hookprobe-pod-008-automation-mcp 2>/dev/null || true
fi

# Start new MCP server
echo "  → Starting enhanced MCP server..."
podman run -d --restart always \
    --pod hookprobe-pod-008-automation \
    --name hookprobe-pod-008-automation-mcp \
    -e OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
    -e ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}" \
    -e DJANGO_CMS_API_URL="http://10.200.1.12:8000/api" \
    -e QSECBIT_API_URL="http://10.200.7.12:8888" \
    -e CLICKHOUSE_URL="http://10.200.5.13:8123" \
    -e VICTORIA_METRICS_URL="http://10.200.5.14:8428" \
    --log-driver=journald \
    --log-opt tag="hookprobe-mcp-enhanced" \
    hookprobe-mcp-server:2.0

echo "✓ Enhanced MCP server deployed"

# ============================================================
# STEP 3: IMPORT N8N WORKFLOWS
# ============================================================
echo ""
echo "[STEP 3] Preparing n8n workflows for import..."

WORKFLOW_DIR="$SCRIPT_DIR/workflows"
WORKFLOW_IMPORT_DIR="/tmp/hookprobe-n8n-workflows"

mkdir -p "$WORKFLOW_IMPORT_DIR"

if [ -d "$WORKFLOW_DIR" ]; then
    cp "$WORKFLOW_DIR"/*.json "$WORKFLOW_IMPORT_DIR/" 2>/dev/null || true

    echo "✓ Workflows prepared for import:"
    ls -1 "$WORKFLOW_IMPORT_DIR"/*.json 2>/dev/null | while read workflow; do
        echo "  • $(basename "$workflow")"
    done

    echo ""
    echo "📋 To import workflows into n8n:"
    echo "  1. Open n8n UI: http://$(hostname -I | awk '{print $1}'):5678"
    echo "  2. Go to: Workflows → Import from File"
    echo "  3. Import each workflow from: $WORKFLOW_IMPORT_DIR"
    echo "  4. Activate workflows after configuring credentials"
else
    echo "⚠️  WARNING: workflows directory not found"
fi

# ============================================================
# STEP 4: CREATE WORKFLOW LOADER SCRIPT
# ============================================================
echo ""
echo "[STEP 4] Creating workflow management scripts..."

# Create workflow activation script
cat > "/usr/local/bin/hookprobe-workflows" << 'EOF'
#!/bin/bash
#
# hookprobe-workflows - Manage HookProbe N8N automation workflows
#

N8N_API="http://10.200.8.10:5678/api/v1"
N8N_USER="admin"
N8N_PASS="${N8N_BASIC_AUTH_PASSWORD:-admin}"

case "$1" in
    list)
        echo "Listing workflows..."
        curl -u "$N8N_USER:$N8N_PASS" "$N8N_API/workflows" | jq -r '.data[] | "\(.id) - \(.name) - Active: \(.active)"'
        ;;
    activate)
        if [ -z "$2" ]; then
            echo "Usage: hookprobe-workflows activate <workflow_id>"
            exit 1
        fi
        curl -u "$N8N_USER:$N8N_PASS" -X PATCH "$N8N_API/workflows/$2" \
            -H "Content-Type: application/json" \
            -d '{"active": true}'
        echo "Workflow $2 activated"
        ;;
    deactivate)
        if [ -z "$2" ]; then
            echo "Usage: hookprobe-workflows deactivate <workflow_id>"
            exit 1
        fi
        curl -u "$N8N_USER:$N8N_PASS" -X PATCH "$N8N_API/workflows/$2" \
            -H "Content-Type: application/json" \
            -d '{"active": false}'
        echo "Workflow $2 deactivated"
        ;;
    status)
        echo "N8N Automation Status:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        curl -s -u "$N8N_USER:$N8N_PASS" "$N8N_API/workflows" | \
            jq -r '.data[] | "  [\(if .active then "✓" else "✗" end)] \(.name)"'
        ;;
    *)
        echo "HookProbe Workflow Management"
        echo ""
        echo "Usage: hookprobe-workflows <command>"
        echo ""
        echo "Commands:"
        echo "  list                List all workflows"
        echo "  activate <id>       Activate a workflow"
        echo "  deactivate <id>     Deactivate a workflow"
        echo "  status              Show workflow status"
        ;;
esac
EOF

chmod +x /usr/local/bin/hookprobe-workflows

echo "✓ Workflow management script created: hookprobe-workflows"

# ============================================================
# STEP 5: VERIFY DEPLOYMENT
# ============================================================
echo ""
echo "[STEP 5] Verifying deployment..."

# Check MCP server
echo "  → Checking MCP server..."
sleep 5
if curl -s http://localhost:8889/health > /dev/null; then
    MCP_HEALTH=$(curl -s http://localhost:8889/health | jq -r '.status')
    echo "    ✓ MCP server: $MCP_HEALTH"
else
    echo "    ⚠️  MCP server not responding (may need more time)"
fi

# Check ClickHouse
echo "  → Checking ClickHouse..."
if curl -s http://10.200.5.13:8123/ping > /dev/null; then
    echo "    ✓ ClickHouse: available"
else
    echo "    ⚠️  ClickHouse not available"
fi

# Check QSECBIT
echo "  → Checking QSECBIT integration..."
if curl -s http://10.200.7.12:8888/health > /dev/null; then
    echo "    ✓ QSECBIT: available"
else
    echo "    ⚠️  QSECBIT not available"
fi

# ============================================================
# FINAL SUMMARY
# ============================================================
echo ""
echo "============================================================"
echo "   🎉 N8N AUTOMATION FRAMEWORK DEPLOYED!"
echo "============================================================"
echo ""
echo "✨ Deployed Components:"
echo "  ✓ Enhanced MCP Server v2.0 (Threat Intelligence)"
echo "  ✓ ClickHouse Automation Schemas"
echo "  ✓ N8N Workflow Templates"
echo "  ✓ Workflow Management Tools"
echo ""
echo "🔌 API Endpoints:"
echo "  • MCP Server:    http://$(hostname -I | awk '{print $1}'):8889"
echo "  • n8n UI:        http://$(hostname -I | awk '{print $1}'):5678"
echo "  • ClickHouse:    http://10.200.5.13:8123"
echo ""
echo "📋 Next Steps:"
echo "  1. Import workflows from: $WORKFLOW_IMPORT_DIR"
echo "  2. Configure n8n credentials:"
echo "     • QSECBIT API: http://10.200.7.12:8888"
echo "     • MCP Server: http://10.200.8.15:8889"
echo "     • Django CMS: http://10.200.1.12:8000/api"
echo "  3. Activate workflows: hookprobe-workflows status"
echo "  4. Monitor execution: n8n UI → Executions"
echo ""
echo "📖 Workflows Available:"
echo "  • 01-qsecbit-defense-pipeline.json - Main threat defense"
echo "  • 02-attack-surface-mapper.json - Network discovery"
echo ""
echo "🎯 Test MCP Server:"
echo "  curl http://localhost:8889/health"
echo "  curl http://localhost:8889/api/qsecbit/status"
echo ""
echo "============================================================"
echo "  🚀 Automation framework ready!"
echo "  📌 Import and activate workflows to begin autonomous defense"
echo "============================================================"
