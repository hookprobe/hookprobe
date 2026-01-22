# HookProbe Dashboard Implementation Plan

**Version:** 1.0
**Date:** 2025-11-25
**Status:** Planning Phase

## Executive Summary

This document outlines the implementation plan for three major HookProbe components:
1. **Admin Dashboard** - Content management and AI-powered blogging for HookProbe team
2. **Security Dashboard** - SIEM-like security monitoring interface for customers
3. **Email System** - Integrated email solution with DKIM and Cloudflare Tunnel support

---

## 1. Admin Dashboard (HookProbe Team)

### 1.1 Overview

**Purpose:** Internal dashboard for HookProbe team to manage content, merchandise, and leverage AI for content creation.

**Technology Stack:**
- **Frontend:** AdminLTE 3.2+ (Bootstrap-based)
- **Backend:** Django 4.2+
- **Database:** PostgreSQL (POD-003)
- **Cache:** Redis (POD-004)
- **AI Integration:** OpenAI API / Anthropic Claude API
- **Automation:** n8n webhooks (POD-008)

### 1.2 Features

#### 1.2.1 Blog Post Management (Extend existing CMS)
- ✅ **Already exists:** Basic blog CRUD operations in `apps/cms/`
- **Enhancements needed:**
  - Rich text editor (CKEditor 5 or TinyMCE)
  - Media library integration
  - SEO optimization tools
  - Draft/Scheduled/Published workflow
  - Categories and tags
  - Author management

#### 1.2.2 Merchandise Product Management (NEW)
- **Product catalog:**
  - Product name, description, images
  - SKU, price, inventory tracking
  - Categories (e.g., Hardware, Apparel, Accessories)
  - Variants (size, color, model)
  - Stock management
- **Integration:**
  - Connect to Stripe/PayPal for payments
  - WooCommerce-style admin interface
  - Product search and filtering

#### 1.2.3 AI-Powered Content Creation (NEW)
- **Web Research:**
  - Integration with OpenAI/Anthropic for web scraping summaries
  - CVE feed integration
  - Security news aggregation
  - Automated topic suggestions
- **Draft Generation:**
  - AI-generated blog post drafts based on research
  - SEO keyword optimization
  - Title and meta description generation
  - Image suggestions (DALL-E integration)
- **Publishing Workflow:**
  - Human review and editing
  - One-click publish
  - Social media post generation

#### 1.2.4 n8n Integration for Autonomous Blogging (NEW)
- **Webhook Endpoints:**
  - `/api/v1/admin/n8n/trigger-research/` - Trigger content research
  - `/api/v1/admin/n8n/create-draft/` - Create draft from n8n
  - `/api/v1/admin/n8n/publish/` - Auto-publish (with approval)
- **Workflow Examples:**
  - **Daily CVE Monitor:** n8n → CVE API → AI summary → Draft post → Email team for approval → Publish
  - **Security News Aggregation:** n8n → RSS feeds → AI analysis → Draft post → Auto-publish (if confidence > 90%)
  - **Social Media Cross-Posting:** New blog post → n8n → LinkedIn/Twitter/Mastodon

### 1.3 Implementation Steps

#### Step 1: Extend CMS App
```python
# apps/cms/models.py additions
class BlogPost:
    # Existing fields...
    ai_generated = models.BooleanField(default=False)
    ai_confidence_score = models.FloatField(null=True)
    research_sources = models.JSONField(default=list)
    seo_score = models.IntegerField(default=0)
    scheduled_publish_date = models.DateTimeField(null=True)
```

#### Step 2: Create Merchandise App
```bash
cd src/web
python manage.py startapp merchandise
```

```python
# apps/merchandise/models.py
class Product:
    name = models.CharField(max_length=200)
    description = models.TextField()
    sku = models.CharField(max_length=50, unique=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    stock = models.IntegerField(default=0)
    category = models.ForeignKey('ProductCategory', on_delete=models.CASCADE)
    images = models.ManyToManyField('ProductImage')
    active = models.BooleanField(default=True)
```

#### Step 3: AI Integration Service
```python
# apps/admin_dashboard/services/ai_service.py
class AIContentService:
    def __init__(self, provider='openai'):
        self.provider = provider  # 'openai' or 'anthropic'

    def research_topic(self, topic):
        """Use AI to research a topic from web sources."""
        pass

    def generate_draft(self, research_data):
        """Generate blog post draft from research."""
        pass

    def optimize_seo(self, content):
        """Optimize content for SEO."""
        pass
```

#### Step 4: n8n Webhook Integration
```python
# apps/admin_dashboard/api/n8n_hooks.py
class N8NWebhookView(APIView):
    def post(self, request):
        """Handle incoming n8n webhooks for autonomous blogging."""
        action = request.data.get('action')

        if action == 'create_draft':
            # Create blog post draft from n8n data
            pass
        elif action == 'publish':
            # Auto-publish (with approval rules)
            pass
```

### 1.4 AdminLTE Integration

```html
<!-- templates/admin_dashboard/index.html -->
<div class="content-wrapper">
  <section class="content-header">
    <h1>HookProbe Admin Dashboard</h1>
  </section>

  <section class="content">
    <div class="row">
      <!-- Blog Management Card -->
      <div class="col-md-4">
        <div class="small-box bg-info">
          <div class="inner">
            <h3>{{ blog_post_count }}</h3>
            <p>Blog Posts</p>
          </div>
          <div class="icon"><i class="fas fa-newspaper"></i></div>
          <a href="{% url 'cms:post_list' %}" class="small-box-footer">
            Manage Posts <i class="fas fa-arrow-circle-right"></i>
          </a>
        </div>
      </div>

      <!-- Merchandise Card -->
      <div class="col-md-4">
        <div class="small-box bg-success">
          <div class="inner">
            <h3>{{ product_count }}</h3>
            <p>Products</p>
          </div>
          <div class="icon"><i class="fas fa-shopping-cart"></i></div>
          <a href="{% url 'merchandise:product_list' %}" class="small-box-footer">
            Manage Products <i class="fas fa-arrow-circle-right"></i>
          </a>
        </div>
      </div>

      <!-- AI Content Generator Card -->
      <div class="col-md-4">
        <div class="small-box bg-warning">
          <div class="inner">
            <h3>{{ draft_count }}</h3>
            <p>AI Drafts Pending</p>
          </div>
          <div class="icon"><i class="fas fa-robot"></i></div>
          <a href="{% url 'admin_dashboard:ai_drafts' %}" class="small-box-footer">
            Review Drafts <i class="fas fa-arrow-circle-right"></i>
          </a>
        </div>
      </div>
    </div>
  </section>
</div>
```

---

## 2. Security Dashboard (Customer-Facing)

### 2.1 Overview

**Purpose:** SIEM-like security monitoring dashboard for HookProbe customers to monitor their edge devices and security posture.

**Technology Stack:**
- **Frontend:** AdminLTE 3.2+ with custom security theme
- **Charts:** Chart.js, ApexCharts
- **Maps:** MapBox GL JS
- **Real-time:** Django Channels (WebSocket) + Redis
- **Data Sources:** ClickHouse (POD-005), Qsecbit API (POD-006)
- **Automation:** n8n integration for SOAR workflows

### 2.2 Dashboard Tabs

#### Tab 1: Home (Dashboard Overview)
**Metrics displayed:**
- **Qsecbit Score:** Real-time RAG status (Red/Amber/Green)
- **IDS/IPS Alerts:** Suricata, Zeek, Snort events (last 24h)
- **WAF Blocks:** NAXSI/ModSecurity blocked attacks
- **Network Traffic:** Total bytes in/out, top protocols
- **Top Attackers:** Geographic map with attack origins
- **System Health:** CPU, RAM, disk, network interface status
- **eBPF/XDP Stats:** Packets dropped, DDoS mitigation events
- **OpenFlow Stats:** Flow table entries, switch status

**Data Sources:**
```python
# apps/security_dashboard/services/metrics.py
class MetricsAggregator:
    def get_qsecbit_score(self, device_id):
        """Query ClickHouse for latest Qsecbit score."""
        query = """
        SELECT rag_status, score, drift, attack_probability
        FROM security.qsecbit_scores
        WHERE device_id = {device_id}
        ORDER BY timestamp DESC
        LIMIT 1
        """
        return clickhouse_client.execute(query)

    def get_ids_alerts(self, device_id, hours=24):
        """Get IDS/IPS alerts from ClickHouse."""
        pass

    def get_network_traffic(self, device_id):
        """Get real-time network traffic stats."""
        pass
```

#### Tab 2: Endpoints (Geographic Device View)
**Features:**
- **MapBox Integration:**
  - Interactive map showing all edge devices
  - Device markers colored by health status (green/yellow/red)
  - Click device → Show details panel
  - Clustering for multiple devices in same location
- **Device Details Panel:**
  - Device name, location, IP address
  - Online/Offline status
  - Last heartbeat timestamp
  - Quick metrics: CPU, RAM, disk
  - Link to detailed device view

**MapBox Implementation:**
```html
<!-- templates/security_dashboard/endpoints.html -->
<div id="map" style="height: 600px;"></div>

<script>
mapboxgl.accessToken = '{{ MAPBOX_API_KEY }}';
const map = new mapboxgl.Map({
    container: 'map',
    style: 'mapbox://styles/mapbox/dark-v10',
    center: [-74.5, 40],
    zoom: 9
});

// Add device markers
devices.forEach(device => {
    const color = device.status === 'healthy' ? '#00ff00' :
                  device.status === 'warning' ? '#ffff00' : '#ff0000';

    new mapboxgl.Marker({ color: color })
        .setLngLat([device.longitude, device.latitude])
        .setPopup(new mapboxgl.Popup().setHTML(`
            <h3>${device.name}</h3>
            <p>Status: ${device.status}</p>
            <p>Qsecbit: ${device.qsecbit_score}</p>
        `))
        .addTo(map);
});
</script>
```

#### Tab 3: Vulnerabilities
**Features:**
- **Vulnerability List:**
  - CVE ID, severity, affected systems
  - Detected date, status (open/mitigated/false positive)
  - CVSS score, exploitability
- **AI-Powered Recommendations:**
  - AI analysis of vulnerability context
  - Suggested mitigation steps
  - Patch availability
  - Risk assessment
- **Filters:**
  - By severity (Critical, High, Medium, Low)
  - By status (Open, In Progress, Resolved)
  - By affected device

**AI Integration:**
```python
# apps/security_dashboard/services/vulnerability_ai.py
class VulnerabilityAI:
    def get_mitigation_recommendations(self, cve_id):
        """Use AI to generate mitigation recommendations."""
        prompt = f"""
        Analyze CVE-{cve_id} and provide:
        1. Technical summary (2-3 sentences)
        2. Affected HookProbe components
        3. Recommended mitigation steps (prioritized)
        4. Patch/update availability
        5. Estimated risk score (0-100)
        """
        return ai_service.generate(prompt)
```

#### Tab 4: SOAR (Security Orchestration & Automation)
**Features:**
- **Playbook Management:**
  - List of available playbooks
  - Create new playbook (drag-and-drop workflow builder)
  - Edit existing playbooks
  - Enable/Disable playbooks
- **Playbook Examples:**
  - **DDoS Mitigation:** IDS alert → Enable XDP filtering → Block IP → Notify SOC
  - **Malware Detection:** File hash match → Quarantine → Scan with Kali → Alert
  - **Brute Force:** Failed login threshold → Block IP → Add to WAF blacklist
- **Execution History:**
  - Playbook runs (success/failure)
  - Execution logs
  - Performance metrics

**Playbook Data Model:**
```python
# apps/security_dashboard/models.py
class SOARPlaybook(models.Model):
    name = models.CharField(max_length=200)
    description = models.TextField()
    trigger_type = models.CharField(max_length=50)  # 'ids_alert', 'threshold', 'manual'
    trigger_conditions = models.JSONField()  # Conditions to activate
    actions = models.JSONField()  # List of actions to execute
    enabled = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
```

#### Tab 5: xSOC (Extended Security Operations Center)
**Features:**
- **Red xSOC (Offensive Security):**
  - **Threat Hunting Dashboard:**
    - Active threat hunts
    - IOC (Indicators of Compromise) tracking
    - Adversary TTPs (MITRE ATT&CK mapping)
  - **Penetration Testing Results:**
    - Kali Linux automated scan results
    - Vulnerability assessment reports
    - Exploit attempts (authorized)
  - **Attack Simulation:**
    - Trigger simulated attacks to test defenses
    - Red team exercises

- **Blue xSOC (Defensive Security):**
  - **Incident Response:**
    - Active incidents
    - Incident timeline
    - Response actions taken
  - **Security Monitoring:**
    - Real-time alert feed
    - Threat intelligence feeds
    - Anomaly detection
  - **Defensive Posture:**
    - Security controls status
    - Coverage gaps
    - Recommended hardening

- **n8n Automation Integration:**
  - **Workflow Triggers:**
    - `/api/v1/security/xsoc/trigger-hunt/` - Trigger automated threat hunt
    - `/api/v1/security/xsoc/incident-response/` - Automated incident response
  - **Example Workflows:**
    - **Automated Threat Hunt:** n8n → Query ClickHouse for IOCs → Analyze with AI → Create hunt report → Notify SOC
    - **Incident Escalation:** Critical alert → n8n → Assess severity → Notify on-call → Create incident ticket → Execute playbook

**xSOC UI Layout:**
```html
<!-- Red/Blue Team Tabs -->
<ul class="nav nav-tabs">
  <li class="nav-item">
    <a class="nav-link active" data-toggle="tab" href="#red-xsoc">
      <i class="fas fa-user-ninja text-danger"></i> Red xSOC
    </a>
  </li>
  <li class="nav-item">
    <a class="nav-link" data-toggle="tab" href="#blue-xsoc">
      <i class="fas fa-shield-alt text-primary"></i> Blue xSOC
    </a>
  </li>
</ul>

<div class="tab-content">
  <div class="tab-pane fade show active" id="red-xsoc">
    <!-- Threat hunting, pen testing, attack simulation -->
  </div>
  <div class="tab-pane fade" id="blue-xsoc">
    <!-- Incident response, monitoring, defensive posture -->
  </div>
</div>
```

### 2.3 Real-Time Updates (WebSocket)

```python
# apps/security_dashboard/consumers.py
from channels.generic.websocket import AsyncWebsocketConsumer
import json

class DashboardConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.device_id = self.scope['url_route']['kwargs']['device_id']
        await self.channel_layer.group_add(f"device_{self.device_id}", self.channel_name)
        await self.accept()

    async def send_metric_update(self, event):
        """Send real-time metric updates to frontend."""
        await self.send(text_data=json.dumps({
            'type': 'metric_update',
            'metric': event['metric'],
            'value': event['value']
        }))
```

```javascript
// Frontend WebSocket connection
const ws = new WebSocket(`ws://${window.location.host}/ws/dashboard/${deviceId}/`);

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    if (data.type === 'metric_update') {
        updateDashboardMetric(data.metric, data.value);
    }
};
```

---

## 3. Email System Integration

### 3.1 Overview

**Purpose:** Integrated email solution for sending notifications, alerts, and transactional emails from HookProbe.

### 3.2 Email Server Options

| Option | Pros | Cons | Recommendation |
|--------|------|------|----------------|
| **Postfix** | Industry standard, well-documented | Complex configuration | ✅ **Recommended** |
| **Mailu** | All-in-one (SMTP, IMAP, webmail), Docker-based | Heavier resource usage | Good for full mail server |
| **Mox** | Modern, written in Go, easy config | Newer, smaller community | Good alternative |
| **Maddy** | Lightweight, easy to configure | Less mature | Testing/dev environments |

**Decision:** Use **Postfix** for production SMTP relay.

### 3.3 Architecture

```
Django App → Postfix (SMTP Relay) → Cloudflare Tunnel → Internet
                                   ↓
                              DKIM Signing
                              SPF Record
                              DMARC Policy
```

### 3.4 Implementation

#### Step 1: Create Postfix Container

```dockerfile
# install/addons/email/Dockerfile
FROM docker.io/library/ubuntu:22.04

RUN apt-get update && apt-get install -y \
    postfix \
    opendkim \
    opendkim-tools \
    libsasl2-modules \
    mailutils

COPY postfix-config/ /etc/postfix/
COPY dkim-config/ /etc/opendkim/

EXPOSE 25 587

CMD ["postfix", "start-fg"]
```

#### Step 2: Postfix Configuration

```bash
# /etc/postfix/main.cf
myhostname = mail.hookprobe.local
mydomain = hookprobe.local
myorigin = $mydomain
inet_interfaces = all
inet_protocols = ipv4

# SASL authentication
smtpd_sasl_auth_enable = yes
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth

# TLS
smtpd_tls_cert_file = /etc/ssl/certs/hookprobe.crt
smtpd_tls_key_file = /etc/ssl/private/hookprobe.key
smtpd_use_tls = yes

# DKIM
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:localhost:8891
non_smtpd_milters = $smtpd_milters
```

#### Step 3: DKIM Setup

```bash
# Generate DKIM keys
opendkim-genkey -t -s mail -d hookprobe.local

# /etc/opendkim.conf
Domain                  hookprobe.local
KeyFile                 /etc/opendkim/keys/mail.private
Selector                mail
Socket                  inet:8891@localhost
```

**DNS Records to Add:**
```
# SPF Record
hookprobe.local. IN TXT "v=spf1 ip4:YOUR_SERVER_IP ~all"

# DKIM Record
mail._domainkey.hookprobe.local. IN TXT "v=DKIM1; k=rsa; p=YOUR_PUBLIC_KEY"

# DMARC Record
_dmarc.hookprobe.local. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@hookprobe.local"
```

#### Step 4: Cloudflare Tunnel Integration

```bash
# Install cloudflared in container
wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
mv cloudflared-linux-amd64 /usr/local/bin/cloudflared
chmod +x /usr/local/bin/cloudflared

# Create tunnel
cloudflared tunnel create hookprobe-email

# Configure tunnel for SMTP
# /etc/cloudflared/config.yml
tunnel: TUNNEL_ID
credentials-file: /etc/cloudflared/TUNNEL_ID.json

ingress:
  - hostname: mail.hookprobe.com
    service: smtp://localhost:25
  - service: http_status:404
```

#### Step 5: Django Email Backend

```python
# src/web/hookprobe/settings/base.py

# Email configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = '10.200.9.10'  # Postfix container IP (new POD-009)
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'noreply@hookprobe.local'
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_PASSWORD')
DEFAULT_FROM_EMAIL = 'HookProbe <noreply@hookprobe.local>'
```

**Send Test Email:**
```python
from django.core.mail import send_mail

send_mail(
    'Test Email from HookProbe',
    'This is a test email sent through the new SMTP system.',
    'noreply@hookprobe.local',
    ['admin@example.com'],
    fail_silently=False,
)
```

### 3.5 Email Templates

```python
# apps/admin_dashboard/services/email_service.py
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives

class EmailService:
    def send_security_alert(self, device, alert):
        """Send security alert email."""
        context = {
            'device': device,
            'alert': alert,
            'dashboard_url': f'https://dashboard.hookprobe.com/devices/{device.id}/'
        }

        html_content = render_to_string('emails/security_alert.html', context)
        text_content = render_to_string('emails/security_alert.txt', context)

        email = EmailMultiAlternatives(
            subject=f'Security Alert: {alert.severity} on {device.name}',
            body=text_content,
            from_email='alerts@hookprobe.local',
            to=[device.admin_email]
        )
        email.attach_alternative(html_content, "text/html")
        email.send()
```

---

## 4. Documentation Updates

### 4.1 Update Main README with Logo

```markdown
# README.md

<p align="center">
  <svg xmlns="http://www.w3.org/2000/svg" width="200" height="70" viewBox="0 0 1080 1080">
    <!-- SVG content -->
  </svg>
</p>

# hookprobe
```

### 4.2 Simplify HLD with Component Links

```markdown
## Architecture

HookProbe v5.0 implements a modular architecture with the following components:

### Core Infrastructure
- [POD-001: Web DMZ](docs/components/POD-001.md) - Web interface, API, WAF
- [POD-002: IAM](docs/components/POD-002.md) - Authentication & authorization
- [POD-003: Database](docs/components/POD-003.md) - PostgreSQL persistent storage
- [POD-004: Cache](docs/components/POD-004.md) - Redis caching layer
- [POD-005: Monitoring](docs/components/POD-005.md) - Grafana, ClickHouse, metrics
- [POD-006: Security](docs/components/POD-006.md) - IDS/IPS, Qsecbit AI
- [POD-007: Response](docs/components/POD-007.md) - Kali Linux, automated response

### Optional Components
- [POD-008: Automation](docs/components/POD-008.md) - n8n workflow automation
- [POD-009: Email](docs/components/POD-009.md) - SMTP server, DKIM, notifications

### Dashboards
- [Admin Dashboard](docs/dashboards/admin-dashboard.md) - Content & merchandise management
- [Security Dashboard](docs/dashboards/) - Security monitoring (see hookprobe-com repository)
```

### 4.3 Create Component README Files

Each component gets its own detailed README:

```markdown
# docs/components/POD-009.md

# POD-009: Email System

## Overview
Integrated SMTP server for sending notifications, alerts, and transactional emails.

## Architecture
- **Container:** Podman container running Postfix
- **Network:** 10.200.9.0/24
- **Ports:** 25 (SMTP), 587 (Submission)
- **Dependencies:** POD-001 (Django), Cloudflare Tunnel

## Configuration
[Detailed configuration steps...]

## Integration
[How other PODs integrate with email...]

## Troubleshooting
[Common issues and solutions...]
```

---

## 5. Implementation Timeline

### Week 1-2: Foundation
- [ ] Set up AdminLTE theme integration
- [ ] Create base dashboard layouts
- [ ] Extend CMS app with AI fields
- [ ] Create merchandise app skeleton

### Week 3-4: Admin Dashboard
- [ ] Implement blog management enhancements
- [ ] Build merchandise management interface
- [ ] Integrate AI API (OpenAI/Anthropic)
- [ ] Create n8n webhook endpoints

### Week 5-7: Security Dashboard
- [ ] Build Home tab with real-time metrics
- [ ] Implement Endpoints tab with MapBox
- [ ] Create Vulnerabilities tab with AI recommendations
- [ ] Build SOAR playbook management

### Week 8-9: xSOC Features
- [ ] Implement Red xSOC (threat hunting)
- [ ] Implement Blue xSOC (incident response)
- [ ] Integrate n8n automation workflows
- [ ] Add WebSocket real-time updates

### Week 10-11: Email System
- [ ] Set up Postfix container (POD-009)
- [ ] Configure DKIM, SPF, DMARC
- [ ] Integrate Cloudflare Tunnel
- [ ] Connect Django email backend
- [ ] Create email templates

### Week 12: Documentation & Testing
- [ ] Update README with logo
- [ ] Create all component READMEs
- [ ] Write comprehensive documentation
- [ ] End-to-end testing
- [ ] Performance optimization

---

## 6. Technical Requirements

### 6.1 New Dependencies

```txt
# src/web/requirements.txt additions

# AI Integration
openai==1.3.0
anthropic==0.7.0

# Real-time updates
channels==4.0.0
channels-redis==4.1.0

# Rich text editor
django-ckeditor==6.7.0

# Maps
mapbox-sdk==3.0.0

# Charts
plotly==5.18.0

# Payment processing (for merchandise)
stripe==7.7.0

# Email validation
django-email-verification==0.3.4
```

### 6.2 New Environment Variables

```bash
# AI Integration
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...

# MapBox
MAPBOX_API_KEY=pk.eyJ...

# Stripe (merchandise)
STRIPE_PUBLIC_KEY=pk_test_...
STRIPE_SECRET_KEY=sk_test_...

# Email
EMAIL_HOST=10.200.9.10
EMAIL_PASSWORD=...
CLOUDFLARE_TUNNEL_TOKEN=...
```

---

## 7. API Endpoints Summary

### Admin Dashboard APIs
```
POST /api/v1/admin/ai/research/           - AI web research
POST /api/v1/admin/ai/generate-draft/     - Generate blog draft
GET  /api/v1/admin/merchandise/products/  - List products
POST /api/v1/admin/merchandise/products/  - Create product
POST /api/v1/admin/n8n/webhook/           - n8n webhook receiver
```

### Security Dashboard APIs
```
GET  /api/v1/security/dashboard/metrics/      - Real-time metrics
GET  /api/v1/security/endpoints/              - Device locations
GET  /api/v1/security/vulnerabilities/        - Vulnerability list
POST /api/v1/security/vulnerabilities/{id}/recommend/ - AI recommendations
GET  /api/v1/security/soar/playbooks/         - List playbooks
POST /api/v1/security/soar/playbooks/         - Create playbook
POST /api/v1/security/xsoc/threat-hunt/       - Trigger threat hunt
GET  /api/v1/security/xsoc/incidents/         - List incidents
```

---

## 8. Next Steps

**Before starting implementation, we need to:**

1. **Prioritize features** - Which component should we build first?
2. **Choose AI provider** - OpenAI, Anthropic, or both?
3. **Select email solution** - Confirm Postfix or alternative?
4. **Define success criteria** - What does "done" look like for each phase?
5. **Resource allocation** - How much time can you dedicate weekly?

**Recommended starting point:**
- Start with **Phase 4** (Documentation + Logo) - Quick wins
- Then **Phase 1** (Admin Dashboard) - Foundation for content
- Then **Phase 2** (Security Dashboard) - Customer-facing features
- Finally **Phase 3** (Email System) - Infrastructure support

---

## Questions for You

1. **Priority:** Which component should we tackle first?
2. **Timeline:** Is the 12-week timeline realistic for your team?
3. **AI Provider:** Do you have a preference between OpenAI and Anthropic?
4. **MapBox:** Do you have a MapBox account or should we use the free tier?
5. **Email Domain:** What domain will you use for sending emails?
6. **n8n Status:** Is POD-008 (n8n) already deployed and accessible?

Let me know your priorities and I'll start implementation immediately!
