# HookProbe n8n Automation Integration

**POD 008 - Autonomous Content Generation & Workflow Automation**

## 🎯 Overview

This integration adds n8n workflow automation to HookProbe, enabling:

- **Autonomous Blog Posting**: AI-generated content published to Django CMS
- **Web Scraping**: Automated content gathering and analysis
- **Security Automation**: Qsecbit-triggered workflows
- **Content Generation**: MCP server with AI API integrations
- **Social Media**: Cross-posting to multiple platforms

## 📋 What's Included

### Services Deployed (POD 008)
- **n8n**: Workflow automation engine
- **PostgreSQL**: n8n database
- **Redis**: Queue management
- **Chromium**: Headless browser for scraping
- **MCP Server**: AI content generation API

### Network Details
- **VNI**: 108 (isolated automation network)
- **Subnet**: 10.108.0.0/24
- **Encryption**: PSK-encrypted VXLAN
- **Integration**: Full access to PODs 001-007

## 🚀 Quick Start

### 1. Prerequisites

Ensure main HookProbe is deployed:
```bash
# Check if main PODs are running
podman pod ps | grep hookprobe

# You should see PODs 001-007
```

### 2. Configure

Edit `n8n_network-config.sh`:

```bash
nano n8n_network-config.sh
```

**Critical settings to change:**
```bash
# Authentication
N8N_BASIC_AUTH_PASSWORD="CHANGE_ME_N8N_PASSWORD"      # ⚠️ CHANGE
N8N_DB_POSTGRESDB_PASSWORD="CHANGE_ME_N8N_DB_PASSWORD"  # ⚠️ CHANGE

# AI API Keys (optional but recommended)
OPENAI_API_KEY="sk-..."           # For GPT integration
ANTHROPIC_API_KEY="sk-ant-..."    # For Claude integration
```

### 3. Deploy

```bash
# Make executable
chmod +x n8n_network-config.sh n8n_setup.sh n8n_uninstall.sh

# Deploy POD 008
sudo ./n8n_setup.sh
```

Installation takes **5-10 minutes**.

### 4. Access n8n

Open in browser:
```
http://YOUR_SERVER_IP:5678
```

Login with credentials from `n8n_network-config.sh`.

---

## 🔧 Configuration Guide

### Network Architecture

```
Internet
  ↓
HookProbe Host
  ↓
OVS Bridge (ovs-br0)
  ├─ VNI 101: POD 001 (Django CMS)
  ├─ VNI 107: POD 007 (Qsecbit AI)
  └─ VNI 108: POD 008 (n8n Automation) ← NEW
       ├─ n8n (10.108.0.10:5678)
       ├─ PostgreSQL (10.108.0.11)
       ├─ Redis (10.108.0.12)
       ├─ Chromium (10.108.0.13)
       └─ MCP Server (10.108.0.15:8889)
```

### Service URLs

| Service | Internal IP | External URL | Purpose |
|---------|-------------|--------------|---------|
| n8n | 10.108.0.10 | http://HOST:5678 | Workflow UI |
| MCP Server | 10.108.0.15 | http://HOST:8889 | AI API |
| Django CMS | 10.101.0.10 | http://HOST:80 | Content target |
| Qsecbit | 10.107.0.10 | http://HOST:8888 | Security data |

### AI API Configuration

#### OpenAI (GPT)
1. Get API key: https://platform.openai.com/api-keys
2. Add to `n8n_network-config.sh`:
```bash
OPENAI_API_KEY="sk-proj-..."
```

#### Anthropic (Claude)
1. Get API key: https://console.anthropic.com/
2. Add to `n8n_network-config.sh`:
```bash
ANTHROPIC_API_KEY="sk-ant-api03-..."
```

---

## 📊 Starter Workflows

### 1. Daily Blog Post Generation

**Workflow**: `daily-blog-post.json`

**Schedule**: Every day at 9 AM

**Flow**:
```
Schedule Trigger (9 AM)
  ↓
MCP Server: Generate Content
  ↓
Django CMS: Publish Post
```

**Setup in n8n**:
1. Import workflow from `/tmp/n8n-workflows/daily-blog-post.json`
2. Add credentials:
   - HTTP Request node → MCP Server
   - HTTP Request node → Django CMS API
3. Activate workflow

**Customization**:
```javascript
// Edit "Generate Content" node body:
{
  "topic": "{{ $json.topic }}",      // Dynamic topic
  "category": "Tutorials",            // Change category
  "min_words": 800,
  "max_words": 2500,
  "tone": "technical"                 // technical|motivational|educational
}
```

### 2. Qsecbit Threat Monitoring

**Workflow**: `qsecbit-monitor.json`

**Schedule**: Every 5 minutes

**Flow**:
```
Schedule Trigger (*/5 * * * *)
  ↓
Qsecbit API: Get Status
  ↓
If RED Alert →
  ↓
  Publish Alert Post
  ↓
  Send Email Notification
```

**Setup**:
1. Import workflow
2. Add Qsecbit API credential
3. Configure email notification (optional)
4. Activate

### 3. Web Scraping & Analysis

**Custom Workflow** (create new):

```
Webhook Trigger
  ↓
Chromium: Scrape URL
  ↓
MCP Server: Analyze Content
  ↓
If Relevant →
  ↓
  Generate Summary
  ↓
  Publish to CMS
```

**Nodes**:
1. **Webhook**: Receive scraping requests
2. **HTTP Request**: Call Chromium service
3. **HTTP Request**: Call MCP `/api/scrape/analyze`
4. **IF**: Check relevance score
5. **HTTP Request**: Call MCP `/api/content/generate`
6. **HTTP Request**: Publish to Django

---

## 🔌 MCP Server API Reference

Base URL: `http://10.108.0.15:8889`

### Health Check
```bash
GET /health

Response:
{
  "status": "healthy",
  "timestamp": "2025-01-15T09:00:00",
  "openai_configured": true,
  "anthropic_configured": true
}
```

### Generate Content
```bash
POST /api/content/generate

Body:
{
  "topic": "XDP/eBPF for DDoS Protection",
  "category": "Tutorials",
  "min_words": 1200,
  "max_words": 2000,
  "tone": "technical"
}

Response:
{
  "success": true,
  "content": {
    "title": "HookProbe Guide: XDP/eBPF for DDoS Protection",
    "slug": "xdp-ebpf-ddos-protection",
    "content": "# XDP/eBPF for DDoS Protection\n\n...",
    "category": "Tutorials",
    "seo_title": "XDP/eBPF DDoS Protection | HookProbe",
    "seo_description": "...",
    "tags": ["cybersecurity", "hookprobe", "tutorials"],
    "word_count": 1456
  }
}
```

### Analyze Scraped Content
```bash
POST /api/scrape/analyze

Body:
{
  "url": "https://example.com/article",
  "content": "Scraped content here..."
}

Response:
{
  "success": true,
  "analysis": {
    "url": "https://example.com/article",
    "word_count": 1234,
    "sentiment": "positive",
    "topics": ["security", "networking"],
    "summary": "Article discusses...",
    "analyzed_at": "2025-01-15T09:15:00"
  }
}
```

### Publish to CMS
```bash
POST /api/cms/publish

Body:
{
  "title": "New Security Alert",
  "content": "# Alert\n\nThreat detected...",
  "category": "Alerts",
  "status": "published"
}

Response:
{
  "success": true,
  "cms_response": {
    "page_id": 123,
    "url": "/blog/new-security-alert",
    "published": true
  }
}
```

### Get Qsecbit Status
```bash
GET /api/qsecbit/status

Response:
{
  "success": true,
  "data": {
    "score": 0.72,
    "rag_status": "RED",
    "components": {
      "drift": 0.45,
      "attack_probability": 0.85,
      "classifier_decay": 0.30,
      "quantum_drift": 0.25
    }
  }
}
```

---

## 🎨 Use Case Examples

### 1. Autonomous Blog for HookProbe

**Goal**: Publish daily technical content automatically

**Workflow**:
```
Daily Trigger (9 AM)
  ↓
Fetch Trending CVEs (API)
  ↓
Generate Blog Post (MCP)
  ↓
SEO Optimization
  ↓
Publish to Django CMS
  ↓
Cross-post to Social Media
```

**Topics Rotation**:
- Monday: Threat Intelligence
- Tuesday: SBC Security Tutorial
- Wednesday: Red vs Blue Simulation
- Thursday: DevSecOps Guide
- Friday: Industry News Recap
- Saturday: Quick Tips
- Sunday: Long-form Deep Dive

### 2. Security Alert Automation

**Goal**: Auto-publish when Qsecbit detects RED status

**Workflow**:
```
Poll Qsecbit (Every 5 min)
  ↓
If RED Status →
  ↓
  Generate Alert Post
  ↓
  Publish to CMS
  ↓
  Send Email to Admin
  ↓
  Post to Slack Channel
```

### 3. Competitor Intelligence

**Goal**: Monitor security blogs and extract insights

**Workflow**:
```
RSS Feed Monitor
  ↓
New Article Detected →
  ↓
  Scrape Full Content (Chromium)
  ↓
  Analyze with AI (MCP)
  ↓
  If Relevant →
    ↓
    Generate Summary
    ↓
    Save to Database
    ↓
    (Optional) Create Response Post
```

### 4. Social Media Automation

**Goal**: Cross-post blog content to multiple platforms

**Workflow**:
```
New Django CMS Post →
  ↓
  Extract Title + Summary
  ↓
  Generate Short Caption (AI)
  ↓
  Post to:
    - LinkedIn
    - X (Twitter)
    - Mastodon
  ↓
  Track Engagement
```

---

## 🔒 Security Best Practices

### 1. API Key Management

**Don't**:
```bash
# ❌ Never commit keys to git
OPENAI_API_KEY="sk-proj-abc123..."
```

**Do**:
```bash
# ✅ Use environment variables
OPENAI_API_KEY="${OPENAI_KEY_FROM_VAULT}"

# ✅ Or use secrets manager
# Store in HashiCorp Vault or similar
```

### 2. Rate Limiting

Configure in MCP server:
```python
# Rate limit: 100 requests per hour per IP
from flask_limiter import Limiter

limiter = Limiter(
    app,
    default_limits=["100 per hour"]
)
```

### 3. Network Isolation

n8n runs in isolated VNI 108:
- No direct internet access (proxied)
- Can only reach specified PODs
- All traffic encrypted via VXLAN

### 4. Webhook Security

```javascript
// Add signature verification to webhooks
const crypto = require('crypto');

function verifySignature(payload, signature, secret) {
  const hash = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(hash)
  );
}
```

---

## 🐛 Troubleshooting

### n8n Won't Start

```bash
# Check logs
podman logs hookprobe-pod-008-automation-n8n

# Common issues:
# 1. Database not ready
podman exec hookprobe-pod-008-automation-postgres pg_isready

# 2. Port conflict
sudo netstat -tulpn | grep 5678

# 3. Restart POD
podman pod restart hookprobe-pod-008-automation
```

### MCP Server Errors

```bash
# Check MCP logs
podman logs hookprobe-pod-008-automation-mcp

# Test API
curl http://localhost:8889/health

# Common issues:
# 1. AI API keys not configured
grep "API_KEY" n8n_network-config.sh

# 2. Can't reach Django CMS
curl http://10.101.0.10:8000/api/

# 3. Restart MCP
podman restart hookprobe-pod-008-automation-mcp
```

### Workflow Execution Fails

```bash
# Check Redis queue
podman exec hookprobe-pod-008-automation-redis redis-cli ping

# Check execution logs in n8n UI:
# Settings → Executions → View Failed

# Common issues:
# 1. Credentials not configured
# 2. Target service unreachable
# 3. Rate limit exceeded
```

### Web Scraping Fails

```bash
# Check Chromium
podman logs hookprobe-pod-008-automation-chromium

# Test Chromium endpoint
curl http://10.108.0.13:3000

# Common issues:
# 1. Memory limit reached (increase with --shm-size)
# 2. Blocked by target site (use delays)
# 3. JavaScript-heavy site (increase timeout)
```

---

## 📊 Monitoring

### n8n Metrics

Access in UI:
- **Executions**: Settings → Executions
- **Workflows**: Workflows → Status
- **Queue**: Check Redis queue length

### MCP Server Metrics

```bash
# Health check
curl http://localhost:8889/health

# Check logs
podman logs --tail 100 hookprobe-pod-008-automation-mcp

# Monitor requests
podman logs -f hookprobe-pod-008-automation-mcp | grep "POST /api"
```

### Integration with Grafana

Add to existing monitoring (POD 005):

```yaml
# Add to Prometheus config
scrape_configs:
  - job_name: 'n8n'
    static_configs:
      - targets: ['10.108.0.10:5678']
  
  - job_name: 'mcp-server'
    static_configs:
      - targets: ['10.108.0.15:8889']
```

---

## 🔄 Updating

### Update n8n

```bash
# Pull latest image
podman pull docker.io/n8nio/n8n:latest

# Restart container
podman restart hookprobe-pod-008-automation-n8n
```

### Update MCP Server

```bash
# Rebuild image
cd /tmp/mcp-server-build
# Edit mcp_server.py
podman build -t hookprobe-mcp-server:latest .

# Restart container
podman restart hookprobe-pod-008-automation-mcp
```

---

## 📦 Backup & Restore

### Backup n8n Data

```bash
# Create backup
podman volume export hookprobe-n8n-data > n8n-data-backup.tar
podman volume export hookprobe-n8n-db > n8n-db-backup.tar

# Backup workflows (export from UI)
# Settings → Import/Export → Export
```

### Restore n8n Data

```bash
# Stop POD
podman pod stop hookprobe-pod-008-automation

# Restore volumes
podman volume import hookprobe-n8n-data < n8n-data-backup.tar
podman volume import hookprobe-n8n-db < n8n-db-backup.tar

# Restart
podman pod start hookprobe-pod-008-automation
```

---

## 🎯 Advanced Configuration

### Custom AI Models

Edit `mcp_server.py` to add custom models:

```python
# Add Llama or other local models
from transformers import pipeline

generator = pipeline('text-generation', model='meta-llama/Llama-2-7b')

@app.route('/api/content/generate-local', methods=['POST'])
def generate_local():
    # Use local model instead of API
    pass
```

### Custom Scrapers

Add domain-specific scrapers:

```python
@app.route('/api/scrape/custom/<domain>', methods=['POST'])
def scrape_custom(domain):
    if domain == 'github':
        # GitHub-specific scraping logic
        pass
    elif domain == 'twitter':
        # Twitter-specific logic
        pass
```

### Workflow Templates

Create reusable templates in n8n:
1. Settings → Templates
2. Save workflow as template
3. Share with team

---

## 📄 License

Same as main HookProbe project (check LICENSE file).

## 🙏 Credits

- **n8n**: https://n8n.io
- **HookProbe Team**: Integration and MCP server
- **Community**: Workflow contributions

---

## 📞 Support

### Check Logs
```bash
# All POD 008 logs
podman pod logs hookprobe-pod-008-automation

# Specific service
podman logs hookprobe-pod-008-automation-n8n
podman logs hookprobe-pod-008-automation-mcp
```

### Community
- GitHub Issues: https://github.com/hookprobe/hookprobe
- Documentation: See main README.md

---

## 🎉 Quick Reference

```
┌─────────────────────────────────────────┐
│  HOOKPROBE N8N AUTOMATION               │
├─────────────────────────────────────────┤
│  n8n UI:     http://HOST:5678           │
│  MCP API:    http://HOST:8889           │
│                                          │
│  Deploy:     sudo ./n8n_setup.sh        │
│  Remove:     sudo ./n8n_uninstall.sh    │
│                                          │
│  Workflows:  /tmp/n8n-workflows/        │
│  Logs:       podman pod logs POD_008    │
│                                          │
│  POD 008: Automation & Content Gen      │
│  VNI: 108 | Subnet: 10.108.0.0/24       │
└─────────────────────────────────────────┘
```

---

**Version**: 1.0  
**Last Updated**: 2025  
**Status**: Production Ready 🚀
