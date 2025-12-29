# HookProbe Dashboards

**Visualization & Management Interfaces**

This directory contains documentation for HookProbe's web-based dashboards and user interfaces.

---

## 📊 Available Dashboards

### 1. Admin Dashboard (AdminLTE)
**Purpose**: System administration and content management

**Features**:
- 📝 Blog post management with AI content generation
- 🛒 Merchandise and product catalog
- 👥 User management and permissions
- 📊 System overview and POD health monitoring
- ⚙️ Configuration management

**Access**: http://YOUR_IP/admin/

**Documentation**: [admin-dashboard.md](admin-dashboard.md) *(to be created)*

---

### 2. MSSP Dashboard (Security Operations)
**Purpose**: Multi-tenant security monitoring and device management

**Features**:
- 🔒 **Security Monitoring** (SIEM capabilities)
  - Real-time threat detection and alerts
  - Qsecbit RAG status across all devices
  - IDS/IPS event correlation
  - Attack pattern visualization

- 📱 **Multi-Device Management**
  - Customer edge device inventory
  - Device health and connectivity status
  - Per-tenant security posture
  - Remote configuration

- 📈 **Analytics & Reporting**
  - Security metrics and KPIs
  - Threat intelligence trends
  - Compliance reporting
  - Custom dashboards per tenant

- 🎯 **Threat Hunting Interface**
  - Advanced query builder (ClickHouse/Doris)
  - Historical event analysis
  - IOC (Indicators of Compromise) tracking
  - Investigation workflows

- 🚨 **Incident Response**
  - Alert management and triage
  - Automated response tracking
  - Playbook execution
  - Remediation verification

**Access**: http://YOUR_IP/dashboard/

**Documentation**: [mssp-dashboard.md](mssp-dashboard.md) *(to be created)*

---

### 3. Grafana Dashboards
**Purpose**: Real-time metrics and observability

**Built-in Dashboards**:
- **System Overview** - All POD health and resources
- **Qsecbit Analysis** - AI threat scores and trends
- **Security Events** - IDS/IPS alerts and incidents
- **Network Traffic** - Flow analysis and top talkers
- **WAF Activity** - Blocked attacks and patterns
- **POD-009 Email** - Mail queue, traffic, IDS alerts (if installed)
- **Container Metrics** - Podman resource usage

**Access**: http://YOUR_IP:3000

**Default Credentials**: admin / admin (change immediately!)

---

## 🏗️ Dashboard Architecture

```
┌─────────────────────────────────────────────┐
│           User Browser                      │
└──────────────┬──────────────────────────────┘
               │
        ┌──────▼──────┐
        │   Nginx     │  ← Reverse proxy (POD-001)
        │  (POD-001)  │
        └──────┬──────┘
               │
    ┌──────────┴──────────┬──────────────┐
    │                     │              │
┌───▼───────┐      ┌──────▼────┐  ┌─────▼──────┐
│   Django  │      │  Grafana  │  │   Logto    │
│    Web    │      │ (POD-005) │  │  (POD-002) │
│ (POD-001) │      └───────────┘  └────────────┘
└───┬───────┘
    │
    ├─────► PostgreSQL (POD-003)
    ├─────► Redis (POD-004)
    ├─────► ClickHouse (POD-005)
    └─────► Qsecbit API (POD-007)
```

---

## 🚀 Quick Start

### Access Dashboards After Installation

```bash
# 1. Install HookProbe core
sudo ./install.sh
# Select: 2) Select Deployment Mode → 1) Edge Deployment

# 2. Install web server (optional)
cd install/addons/webserver
sudo ./setup-webserver.sh edge

# 3. Access dashboards
# Admin: http://YOUR_IP/admin/
# MSSP:  http://YOUR_IP/dashboard/
# Grafana: http://YOUR_IP:3000
```

### First-Time Setup

1. **Change Default Passwords**:
   ```bash
   # Grafana (via UI)
   http://YOUR_IP:3000
   Login: admin / admin
   Click profile → Change password

   # Django admin (via UI)
   http://YOUR_IP/admin/
   ```

2. **Configure SSO** (optional):
   - Enable Logto integration
   - Configure OAuth providers
   - See [IAM Integration Guide](../IAM-INTEGRATION-GUIDE.md)

3. **Import Grafana Dashboards**:
   ```bash
   # Dashboards are pre-installed, but you can customize
   http://YOUR_IP:3000/dashboards
   ```

---

## 🎨 Customization

### Admin Dashboard Themes

**Built-in Themes**:
- AdminLTE 3 (default)
- Dark mode support
- Responsive design (mobile-friendly)

**Custom Branding**:
```python
# src/web/hookprobe/settings.py
ADMIN_SITE_HEADER = "Your Company Security Center"
ADMIN_SITE_TITLE = "Your Company Admin"
ADMIN_INDEX_TITLE = "Welcome to Your Security Platform"
```

### Grafana Dashboard Customization

```bash
# Export existing dashboard
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://YOUR_IP:3000/api/dashboards/uid/YOUR_DASHBOARD_UID

# Import modified dashboard
curl -X POST -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d @dashboard.json \
  http://YOUR_IP:3000/api/dashboards/db
```

---

## 🔐 Access Control

### Role-Based Access (RBAC)

**Admin Dashboard Roles**:
- **Superuser**: Full system access
- **Staff**: Content management only
- **Viewer**: Read-only access

**MSSP Dashboard Roles**:
- **MSSP Admin**: All tenants, full access
- **MSSP Analyst**: Read-only, all tenants
- **Tenant Admin**: Single tenant, full access
- **Tenant Viewer**: Single tenant, read-only

**Grafana Roles**:
- **Admin**: Dashboard management, user management
- **Editor**: Create and edit dashboards
- **Viewer**: View dashboards only

### Configure User Permissions

```bash
# Django admin users
python manage.py createsuperuser

# Add staff user (content management only)
python manage.py shell
>>> from django.contrib.auth.models import User
>>> user = User.objects.create_user('editor', 'editor@example.com', 'password')
>>> user.is_staff = True
>>> user.save()

# Grafana users (via UI)
http://YOUR_IP:3000/org/users
```

---

## 📊 Dashboard Features

### Admin Dashboard

#### Blog Management
- Rich text editor with markdown support
- Image upload and media management
- SEO optimization (meta tags, descriptions)
- Category and tag management
- Draft/publish workflow
- AI content generation (via n8n integration)

#### Merchandise Catalog
- Product management with variants
- Inventory tracking
- Pricing and promotions
- Order management
- AI product description generation

#### System Monitoring
- POD health status (all 7-9 PODs)
- Container resource usage
- Network traffic overview
- Recent security events
- Quick links to Grafana dashboards

### MSSP Dashboard

#### Security Monitoring Tabs

1. **Home**: Overview and summaries
   - Active devices and connectivity
   - Recent alerts and incidents
   - Qsecbit score trends
   - Top threats and attackers

2. **Endpoints**: Device management
   - Device inventory and status
   - Per-device Qsecbit scores
   - Configuration management
   - Remote access (SSH/Cloudflare Tunnel)

3. **Vulnerabilities**: Risk assessment
   - CVE tracking and remediation
   - Vulnerability scanner integration
   - Patch management
   - Risk scoring

4. **SOAR**: Automated response
   - Playbook management
   - Incident workflows
   - Response action history
   - Integration with POD-007 (Kali)

5. **xSOC**: Extended SOC capabilities
   - Threat intelligence feeds
   - Cross-tenant correlation
   - Advanced analytics
   - Custom queries (ClickHouse/Doris)

---

## 🔔 Alerting

### Grafana Alerts

Configure alerts for critical events:

```yaml
# Example: High Qsecbit score alert
- name: Qsecbit RED Alert
  condition: avg() OF query(A, 5m) > 0.70
  notification: email, slack
  message: "CRITICAL: Qsecbit score RED ({{ $value }})"
```

### Django Admin Notifications

- Email notifications for security events
- Webhook integration (Slack, Discord, Teams)
- SMS alerts (via Twilio integration)
- In-dashboard notification center

---

## 📱 Mobile Access

All dashboards are mobile-responsive:

- **Admin Dashboard**: Full mobile UI
- **MSSP Dashboard**: Optimized for tablets
- **Grafana**: Mobile app available (iOS/Android)

---

## 🛠️ Troubleshooting

### Dashboard Not Loading

```bash
# Check web server status
podman ps | grep django

# Check nginx
podman ps | grep nginx

# View logs
podman logs hookprobe-pod-001-web-dmz-nginx
podman logs hookprobe-pod-001-web-dmz-django
```

### Grafana Connection Issues

```bash
# Check Grafana container
podman ps | grep grafana

# Check datasource connectivity
curl http://localhost:8428/api/v1/query?query=up

# Restart Grafana
podman restart hookprobe-pod-005-monitoring-grafana
```

### Authentication Errors

```bash
# Check Logto (IAM)
podman ps | grep logto

# View Logto logs
podman logs hookprobe-pod-002-iam-logto

# Test OAuth flow
curl http://YOUR_IP:3001/.well-known/openid-configuration
```

---

## 📈 Performance Optimization

### Database Query Optimization

```python
# Use select_related() for foreign keys
posts = BlogPost.objects.select_related('author').all()

# Use prefetch_related() for many-to-many
posts = BlogPost.objects.prefetch_related('categories').all()

# Add database indexes
class BlogPost(models.Model):
    created_at = models.DateTimeField(db_index=True)
    slug = models.SlugField(db_index=True, unique=True)
```

### Caching Strategy

```python
# Cache expensive queries (Redis POD-004)
from django.core.cache import cache

def get_security_events():
    events = cache.get('recent_security_events')
    if not events:
        events = SecurityEvent.objects.filter(
            timestamp__gte=datetime.now() - timedelta(hours=24)
        )
        cache.set('recent_security_events', events, 300)  # 5 min
    return events
```

### Grafana Performance

- Limit dashboard query range (last 24h by default)
- Use recording rules for expensive queries
- Enable query caching in VictoriaMetrics
- Use dashboard variables to reduce panel count

---

## 🤝 Contributing

Help improve dashboard documentation!

### Areas for Contribution

- Screenshot tutorials
- Video walkthroughs
- Custom dashboard templates
- Integration guides
- Mobile app documentation

See [../CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

---

## 📚 Resources

- **Django Admin**: https://docs.djangoproject.com/en/stable/ref/contrib/admin/
- **Grafana Docs**: https://grafana.com/docs/grafana/latest/
- **AdminLTE Theme**: https://adminlte.io/docs/

### HookProbe Documentation

- **Main README**: [../../README.md](../../README.md)
- **Web Server Setup**: [../../deploy/addons/webserver/README.md](../../deploy/addons/webserver/README.md)
- **IAM Integration**: [../IAM-INTEGRATION-GUIDE.md](../IAM-INTEGRATION-GUIDE.md)

---

**HookProbe Dashboards** - *Visualizing Security at Scale*

Built with ❤️ for security operations by the HookProbe Team
