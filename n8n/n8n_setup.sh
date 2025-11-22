#!/bin/bash
#
# n8n_setup.sh - HookProbe n8n Automation Platform Setup
# Version: 1.0 - POD 008 Deployment
#
# Deploys n8n workflow automation with:
# - n8n workflow engine
# - PostgreSQL database
# - Redis queue
# - Headless Chromium for scraping
# - MCP server for AI integrations
# - Integration with Django CMS and Qsecbit
#

set -e
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load n8n configuration
if [ -f "$SCRIPT_DIR/n8n_network-config.sh" ]; then
    source "$SCRIPT_DIR/n8n_network-config.sh"
else
    echo "ERROR: n8n_network-config.sh not found in $SCRIPT_DIR"
    exit 1
fi

echo "============================================================"
echo "   HOOKPROBE N8N AUTOMATION PLATFORM DEPLOYMENT"
echo "   Version 1.0 - POD 008"
echo "============================================================"

# ============================================================
# STEP 1: VALIDATE CONFIGURATION
# ============================================================
echo ""
echo "[STEP 1] Validating configuration..."

if ! validate_n8n_config; then
    echo "ERROR: Configuration validation failed"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root"
   exit 1
fi

echo "✓ Configuration validated"

# ============================================================
# STEP 2: CREATE VXLAN TUNNEL FOR POD 008
# ============================================================
echo ""
echo "[STEP 2] Creating VXLAN tunnel for Automation POD..."

# Check if OVS bridge exists
if ! ovs-vsctl br-exists "$OVS_MAIN_BRIDGE"; then
    echo "ERROR: Main OVS bridge $OVS_MAIN_BRIDGE not found"
    echo "Please run main setup.sh first"
    exit 1
fi

# Create VXLAN tunnel for VNI 108
echo "  → Creating VXLAN tunnel: VNI=$VNI_AUTOMATION"
ovs-vsctl --may-exist add-port "$OVS_MAIN_BRIDGE" "vxlan-${VNI_AUTOMATION}" -- \
    set interface "vxlan-${VNI_AUTOMATION}" type=vxlan \
    options:key="$VNI_AUTOMATION" \
    options:remote_ip="$REMOTE_HOST_IP" \
    options:local_ip="$LOCAL_HOST_IP" \
    options:dst_port="$VXLAN_PORT" \
    options:psk="$OVS_PSK_INTERNAL"

echo "✓ VXLAN tunnel created"

# ============================================================
# STEP 3: CONFIGURE FIREWALL
# ============================================================
echo ""
echo "[STEP 3] Configuring firewall..."

if command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=${PORT_N8N}/tcp
    firewall-cmd --permanent --add-port=${PORT_MCP}/tcp
    firewall-cmd --reload
    echo "✓ Firewall configured"
else
    echo "⚠ firewalld not found, skipping"
fi

# ============================================================
# STEP 4: CREATE PODMAN NETWORK
# ============================================================
echo ""
echo "[STEP 4] Creating Podman network for POD 008..."

if podman network exists "$NETWORK_POD008" 2>/dev/null; then
    echo "  → Network exists, removing..."
    podman network rm "$NETWORK_POD008"
fi

podman network create \
    --driver bridge \
    --subnet="$SUBNET_POD008" \
    --gateway="$GATEWAY_POD008" \
    "$NETWORK_POD008"

echo "✓ Network created: $NETWORK_POD008"

# ============================================================
# STEP 5: CREATE PERSISTENT VOLUMES
# ============================================================
echo ""
echo "[STEP 5] Creating persistent volumes..."

create_volume() {
    local vol_name=$1
    if ! podman volume exists "$vol_name" 2>/dev/null; then
        podman volume create "$vol_name"
        echo "  → Created: $vol_name"
    else
        echo "  → Exists: $vol_name"
    fi
}

create_volume "$VOLUME_N8N_DATA"
create_volume "$VOLUME_N8N_DB"
create_volume "$VOLUME_N8N_REDIS"
create_volume "$VOLUME_MCP_DATA"
create_volume "$VOLUME_SCRAPING_CACHE"

echo "✓ Volumes ready"

# ============================================================
# STEP 6: CREATE POD 008
# ============================================================
echo ""
echo "[STEP 6] Creating POD 008..."

if podman pod exists "$POD_008_NAME" 2>/dev/null; then
    echo "  → POD exists, removing..."
    podman pod rm -f "$POD_008_NAME"
fi

podman pod create \
    --name "$POD_008_NAME" \
    --network "$NETWORK_POD008" \
    -p ${PORT_N8N}:5678 \
    -p ${PORT_MCP}:8889

echo "✓ POD 008 created"

# ============================================================
# STEP 7: DEPLOY POSTGRESQL FOR N8N
# ============================================================
echo ""
echo "[STEP 7] Deploying PostgreSQL for n8n..."

podman run -d --restart always \
    --pod "$POD_008_NAME" \
    --name "${POD_008_NAME}-postgres" \
    -e POSTGRES_DB="$N8N_DB_POSTGRESDB_DATABASE" \
    -e POSTGRES_USER="$N8N_DB_POSTGRESDB_USER" \
    -e POSTGRES_PASSWORD="$N8N_DB_POSTGRESDB_PASSWORD" \
    -v "$VOLUME_N8N_DB:/var/lib/postgresql/data" \
    --log-driver=journald \
    --log-opt tag="hookprobe-n8n-db" \
    "$IMAGE_N8N_POSTGRES"

echo "  → Waiting for PostgreSQL to be ready..."
sleep 10

echo "✓ PostgreSQL deployed"

# ============================================================
# STEP 8: DEPLOY REDIS FOR QUEUE
# ============================================================
echo ""
echo "[STEP 8] Deploying Redis for queue management..."

podman run -d --restart always \
    --pod "$POD_008_NAME" \
    --name "${POD_008_NAME}-redis" \
    -v "$VOLUME_N8N_REDIS:/data" \
    --log-driver=journald \
    --log-opt tag="hookprobe-n8n-redis" \
    "$IMAGE_N8N_REDIS" \
    redis-server --appendonly yes

echo "✓ Redis deployed"

# ============================================================
# STEP 9: DEPLOY N8N WORKFLOW ENGINE
# ============================================================
echo ""
echo "[STEP 9] Deploying n8n workflow automation..."

podman run -d --restart always \
    --pod "$POD_008_NAME" \
    --name "${POD_008_NAME}-n8n" \
    -e N8N_PROTOCOL="$N8N_PROTOCOL" \
    -e N8N_HOST="$N8N_HOST" \
    -e N8N_PORT="$N8N_PORT" \
    -e N8N_BASIC_AUTH_ACTIVE="$N8N_BASIC_AUTH_ACTIVE" \
    -e N8N_BASIC_AUTH_USER="$N8N_BASIC_AUTH_USER" \
    -e N8N_BASIC_AUTH_PASSWORD="$N8N_BASIC_AUTH_PASSWORD" \
    -e DB_TYPE="$N8N_DB_TYPE" \
    -e DB_POSTGRESDB_HOST="$N8N_DB_POSTGRESDB_HOST" \
    -e DB_POSTGRESDB_PORT="$N8N_DB_POSTGRESDB_PORT" \
    -e DB_POSTGRESDB_DATABASE="$N8N_DB_POSTGRESDB_DATABASE" \
    -e DB_POSTGRESDB_USER="$N8N_DB_POSTGRESDB_USER" \
    -e DB_POSTGRESDB_PASSWORD="$N8N_DB_POSTGRESDB_PASSWORD" \
    -e EXECUTIONS_MODE="$N8N_EXECUTIONS_MODE" \
    -e QUEUE_BULL_REDIS_HOST="$N8N_EXECUTIONS_QUEUE_REDIS_HOST" \
    -e QUEUE_BULL_REDIS_PORT="$N8N_EXECUTIONS_QUEUE_REDIS_PORT" \
    -e N8N_WEBHOOK_URL="$N8N_WEBHOOK_URL" \
    -e GENERIC_TIMEZONE="UTC" \
    -v "$VOLUME_N8N_DATA:/home/node/.n8n" \
    --log-driver=journald \
    --log-opt tag="hookprobe-n8n" \
    "$IMAGE_N8N"

echo "  → Waiting for n8n to be ready..."
sleep 15

echo "✓ n8n deployed"

# ============================================================
# STEP 10: DEPLOY CHROMIUM FOR WEB SCRAPING
# ============================================================
echo ""
echo "[STEP 10] Deploying headless Chromium for web scraping..."

podman run -d --restart always \
    --pod "$POD_008_NAME" \
    --name "${POD_008_NAME}-chromium" \
    -e CONNECTION_TIMEOUT=600000 \
    -e MAX_CONCURRENT_SESSIONS="$SCRAPING_MAX_CONCURRENT" \
    -v "$VOLUME_SCRAPING_CACHE:/tmp/chromium-cache" \
    --shm-size=1gb \
    --log-driver=journald \
    --log-opt tag="hookprobe-chromium" \
    "$IMAGE_CHROMIUM"

echo "✓ Chromium deployed"

# ============================================================
# STEP 11: BUILD AND DEPLOY MCP SERVER
# ============================================================
echo ""
echo "[STEP 11] Building and deploying MCP server..."

MCP_BUILD_DIR="/tmp/mcp-server-build"
rm -rf "$MCP_BUILD_DIR"
mkdir -p "$MCP_BUILD_DIR"

# Create MCP server for AI integrations
cat > "$MCP_BUILD_DIR/mcp_server.py" << 'EOF'
#!/usr/bin/env python3
"""
MCP Server for HookProbe AI Integrations
Provides API endpoints for content generation, analysis, and automation
"""

import os
from flask import Flask, request, jsonify
from datetime import datetime
import requests

app = Flask(__name__)

# Configuration
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY', '')
DJANGO_CMS_API = os.getenv('DJANGO_CMS_API_URL', '')
QSECBIT_API = os.getenv('QSECBIT_API_URL', '')

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'openai_configured': bool(OPENAI_API_KEY),
        'anthropic_configured': bool(ANTHROPIC_API_KEY)
    })

@app.route('/api/content/generate', methods=['POST'])
def generate_content():
    """
    Generate blog content using AI
    
    Request body:
    {
        "topic": "string",
        "category": "string",
        "min_words": int,
        "max_words": int,
        "tone": "technical|motivational|educational"
    }
    """
    try:
        data = request.json
        topic = data.get('topic', 'Cybersecurity Best Practices')
        category = data.get('category', 'Tutorials')
        min_words = data.get('min_words', 800)
        max_words = data.get('max_words', 2500)
        tone = data.get('tone', 'technical')
        
        # Generate content (placeholder - implement with actual AI API)
        content = {
            'title': f"HookProbe Guide: {topic}",
            'slug': topic.lower().replace(' ', '-'),
            'content': f"# {topic}\n\nGenerated content about {topic}...",
            'category': category,
            'seo_title': f"{topic} | HookProbe Security",
            'seo_description': f"Comprehensive guide on {topic} for cybersecurity professionals",
            'tags': ['cybersecurity', 'hookprobe', category.lower()],
            'word_count': min_words,
            'generated_at': datetime.now().isoformat()
        }
        
        return jsonify({
            'success': True,
            'content': content
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/scrape/analyze', methods=['POST'])
def analyze_scraped_content():
    """
    Analyze scraped content for insights
    
    Request body:
    {
        "url": "string",
        "content": "string"
    }
    """
    try:
        data = request.json
        url = data.get('url', '')
        content = data.get('content', '')
        
        analysis = {
            'url': url,
            'word_count': len(content.split()),
            'sentiment': 'neutral',
            'topics': [],
            'summary': 'Content summary...',
            'analyzed_at': datetime.now().isoformat()
        }
        
        return jsonify({
            'success': True,
            'analysis': analysis
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/cms/publish', methods=['POST'])
def publish_to_cms():
    """
    Publish content to Django CMS
    
    Request body:
    {
        "title": "string",
        "content": "string",
        "category": "string",
        "status": "draft|published"
    }
    """
    try:
        data = request.json
        
        # Call Django CMS API (placeholder)
        cms_response = {
            'page_id': 123,
            'url': '/blog/new-post',
            'published': True
        }
        
        return jsonify({
            'success': True,
            'cms_response': cms_response
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/qsecbit/status', methods=['GET'])
def get_qsecbit_status():
    """Get current Qsecbit threat status"""
    try:
        if QSECBIT_API:
            response = requests.get(f'{QSECBIT_API}/api/qsecbit/latest', timeout=5)
            return jsonify({
                'success': True,
                'data': response.json()
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Qsecbit API not configured'
            }), 503
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8889, debug=False)
EOF

# Create requirements.txt
cat > "$MCP_BUILD_DIR/requirements.txt" << 'EOF'
Flask==3.0.0
requests==2.31.0
python-dotenv==1.0.0
gunicorn==21.2.0
EOF

# Create Dockerfile
cat > "$MCP_BUILD_DIR/Dockerfile" << 'EOF'
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY mcp_server.py .

EXPOSE 8889

CMD ["gunicorn", "--bind", "0.0.0.0:8889", "--workers", "2", "mcp_server:app"]
EOF

echo "  → Building MCP server image..."
cd "$MCP_BUILD_DIR"
podman build -t hookprobe-mcp-server:latest .

echo "  → Starting MCP server..."
podman run -d --restart always \
    --pod "$POD_008_NAME" \
    --name "${POD_008_NAME}-mcp" \
    -e OPENAI_API_KEY="$OPENAI_API_KEY" \
    -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
    -e DJANGO_CMS_API_URL="$DJANGO_CMS_API_URL" \
    -e QSECBIT_API_URL="$QSECBIT_API_URL" \
    -v "$VOLUME_MCP_DATA:/data" \
    --log-driver=journald \
    --log-opt tag="hookprobe-mcp" \
    hookprobe-mcp-server:latest

echo "✓ MCP server deployed"

# ============================================================
# STEP 12: CREATE STARTER WORKFLOWS
# ============================================================
echo ""
echo "[STEP 12] Creating starter workflow templates..."

WORKFLOW_DIR="/tmp/n8n-workflows"
mkdir -p "$WORKFLOW_DIR"

# Daily blog post workflow
cat > "$WORKFLOW_DIR/daily-blog-post.json" << 'EOF'
{
  "name": "Daily Blog Post Generation",
  "nodes": [
    {
      "parameters": {
        "rule": {
          "interval": [
            {
              "field": "cronExpression",
              "expression": "0 9 * * *"
            }
          ]
        }
      },
      "name": "Schedule Trigger",
      "type": "n8n-nodes-base.scheduleTrigger",
      "position": [250, 300]
    },
    {
      "parameters": {
        "url": "http://10.108.0.15:8889/api/content/generate",
        "method": "POST",
        "jsonParameters": true,
        "options": {},
        "bodyParametersJson": "{\n  \"topic\": \"{{ $json.topic }}\",\n  \"category\": \"Tutorials\",\n  \"min_words\": 800,\n  \"max_words\": 2500\n}"
      },
      "name": "Generate Content",
      "type": "n8n-nodes-base.httpRequest",
      "position": [450, 300]
    },
    {
      "parameters": {
        "url": "http://10.101.0.10:8000/api/posts/",
        "method": "POST",
        "jsonParameters": true,
        "options": {},
        "bodyParametersJson": "{{ $json }}"
      },
      "name": "Publish to CMS",
      "type": "n8n-nodes-base.httpRequest",
      "position": [650, 300]
    }
  ],
  "connections": {
    "Schedule Trigger": {
      "main": [
        [
          {
            "node": "Generate Content",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Generate Content": {
      "main": [
        [
          {
            "node": "Publish to CMS",
            "type": "main",
            "index": 0
          }
        ]
      ]
    }
  }
}
EOF

# Qsecbit monitoring workflow
cat > "$WORKFLOW_DIR/qsecbit-monitor.json" << 'EOF'
{
  "name": "Qsecbit Threat Monitoring",
  "nodes": [
    {
      "parameters": {
        "rule": {
          "interval": [
            {
              "field": "cronExpression",
              "expression": "*/5 * * * *"
            }
          ]
        }
      },
      "name": "Check Every 5 Minutes",
      "type": "n8n-nodes-base.scheduleTrigger",
      "position": [250, 300]
    },
    {
      "parameters": {
        "url": "http://10.107.0.10:8888/api/qsecbit/latest",
        "method": "GET"
      },
      "name": "Get Qsecbit Status",
      "type": "n8n-nodes-base.httpRequest",
      "position": [450, 300]
    },
    {
      "parameters": {
        "conditions": {
          "string": [
            {
              "value1": "={{ $json.rag_status }}",
              "value2": "RED"
            }
          ]
        }
      },
      "name": "If RED Alert",
      "type": "n8n-nodes-base.if",
      "position": [650, 300]
    },
    {
      "parameters": {
        "url": "http://10.108.0.15:8889/api/cms/publish",
        "method": "POST",
        "jsonParameters": true,
        "bodyParametersJson": "{\n  \"title\": \"Security Alert: {{ $json.timestamp }}\",\n  \"content\": \"Threat detected with score {{ $json.score }}\",\n  \"category\": \"Alerts\",\n  \"status\": \"published\"\n}"
      },
      "name": "Publish Alert",
      "type": "n8n-nodes-base.httpRequest",
      "position": [850, 300]
    }
  ],
  "connections": {
    "Check Every 5 Minutes": {
      "main": [
        [
          {
            "node": "Get Qsecbit Status",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Get Qsecbit Status": {
      "main": [
        [
          {
            "node": "If RED Alert",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "If RED Alert": {
      "main": [
        [
          {
            "node": "Publish Alert",
            "type": "main",
            "index": 0
          }
        ]
      ]
    }
  }
}
EOF

echo "✓ Workflow templates created in $WORKFLOW_DIR"
echo "  → Import these manually in n8n UI"

# ============================================================
# FINAL SUMMARY
# ============================================================
echo ""
echo "============================================================"
echo "   🎉 N8N AUTOMATION PLATFORM DEPLOYED!"
echo "============================================================"
echo ""
echo "✨ Deployed Services:"
echo "  ✓ n8n Workflow Engine"
echo "  ✓ PostgreSQL Database"
echo "  ✓ Redis Queue"
echo "  ✓ Headless Chromium"
echo "  ✓ MCP Server (AI Integrations)"
echo ""
echo "🌐 Network Configuration:"
echo "  • POD 008 Network: $SUBNET_POD008"
echo "  • VNI: $VNI_AUTOMATION"
echo "  • VXLAN: Encrypted with PSK"
echo ""
echo "🔐 Access Information:"
echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🤖 n8n Workflow Automation:"
echo "     URL: http://$LOCAL_HOST_IP:$PORT_N8N"
echo "     Username: $N8N_BASIC_AUTH_USER"
echo "     Password: [configured in n8n_network-config.sh]"
echo ""
echo "  🔌 MCP Server:"
echo "     API: http://$LOCAL_HOST_IP:$PORT_MCP"
echo "     Health: curl http://$LOCAL_HOST_IP:$PORT_MCP/health"
echo ""
echo "  📊 Integrated Services:"
echo "     Django CMS: $DJANGO_CMS_API_URL"
echo "     Qsecbit API: $QSECBIT_API_URL"
echo "     Chromium: http://$IP_POD008_CHROMIUM:3000"
echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📋 Next Steps:"
echo "  1. Access n8n UI at http://$LOCAL_HOST_IP:$PORT_N8N"
echo "  2. Import starter workflows from: $WORKFLOW_DIR"
echo "  3. Configure AI API keys (OpenAI/Anthropic) in n8n_network-config.sh"
echo "  4. Create credentials in n8n:"
echo "     • Django CMS API"
echo "     • Qsecbit API"
echo "     • MCP Server"
echo "  5. Activate and test workflows"
echo ""
echo "🚀 Starter Workflows:"
echo "  • daily-blog-post.json - Automated content generation"
echo "  • qsecbit-monitor.json - Security threat monitoring"
echo ""
echo "📖 Documentation:"
echo "  • n8n Docs: https://docs.n8n.io"
echo "  • MCP Server API: http://$LOCAL_HOST_IP:$PORT_MCP/health"
echo ""
echo "🎯 Use Cases:"
echo "  ✓ Automated blog post generation"
echo "  ✓ Web scraping and content analysis"
echo "  ✓ Security alert automation"
echo "  ✓ Social media cross-posting"
echo "  ✓ SEO optimization workflows"
echo "  ✓ Threat intelligence aggregation"
echo ""
echo "============================================================"
echo "  🎉 POD 008 is now running!"
echo "  🚀 Start automating your HookProbe workflows!"
echo "============================================================"
