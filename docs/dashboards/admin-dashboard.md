# Admin Dashboard (AdminLTE)

**System Administration & Content Management Interface**

The HookProbe Admin Dashboard provides comprehensive system administration, content management, and POD monitoring capabilities using the AdminLTE 3 theme.

---

## 🎯 Overview

The Admin Dashboard is the primary interface for HookProbe system administrators to:
- Manage blog content and pages
- Configure merchandise and products
- Monitor POD health and security
- Manage users and permissions
- Configure system settings

### Key Features

- ✅ **Blog Management** - Full CMS with AI content generation
- ✅ **Merchandise Catalog** - Product management with variants and inventory
- ✅ **POD Monitoring** - Real-time health status for all 7-9 PODs
- ✅ **User Management** - RBAC with Logto integration
- ✅ **Security Overview** - Qsecbit scores and recent alerts
- ✅ **System Configuration** - Network, security, and service settings

---

## 🚀 Quick Access

**URL**: `http://YOUR_IP/admin/`

**Default Credentials**: Set during installation via Logto IAM

**Required**:
- POD-001 (Web DMZ) must be running
- POD-002 (Logto IAM) for authentication
- POD-003 (PostgreSQL) for database

---

## 📊 Dashboard Overview

### Home Dashboard

The main dashboard provides at-a-glance visibility:

```
┌─────────────────────────────────────────────────┐
│         HookProbe Admin Dashboard               │
├─────────────────────────────────────────────────┤
│                                                 │
│  System Health          Security Status         │
│  ┌────────────┐         ┌────────────┐         │
│  │ 7/7 PODs   │         │ Qsecbit:   │         │
│  │   ONLINE   │         │   GREEN    │         │
│  └────────────┘         └────────────┘         │
│                                                 │
│  Recent Activity        Quick Actions           │
│  • Blog post created    • Create Post           │
│  • 3 new products       • Add Product           │
│  • IDS alert: SQL inj   • View Alerts           │
│  • 15 WAF blocks        • System Settings       │
│                                                 │
└─────────────────────────────────────────────────┘
```

**Widgets**:
- **POD Status Cards**: Health indicator for each POD (001-009)
- **Qsecbit Score**: Real-time RAG status (Green/Amber/Red)
- **Recent Security Events**: IDS/IPS/WAF alerts (last 24h)
- **System Resources**: CPU, RAM, disk usage
- **Network Traffic**: Top talkers and bandwidth usage
- **User Activity**: Recent logins and actions

---

## 📝 Blog Management

### Features

- **Rich Text Editor**: TinyMCE with markdown support
- **AI Content Generation**: Generate blog posts via n8n (POD-008)
- **Media Library**: Image upload and management
- **SEO Optimization**: Meta tags, descriptions, slugs
- **Categories & Tags**: Organize content
- **Draft/Publish Workflow**: Review before publishing
- **Comments**: User comments with moderation
- **Analytics**: View counts, engagement metrics

### Creating a Blog Post

**Manual Creation**:

1. Navigate to **Content → Blog Posts → Add Post**
2. Enter title and content (rich text or markdown)
3. Upload featured image
4. Add categories and tags
5. Set SEO metadata
6. Save as draft or publish

**AI-Generated Content** (requires POD-008):

1. Navigate to **Content → AI Generator**
2. Select topic or keyword
3. Choose content type (tutorial, news, analysis)
4. Click **Generate with AI**
5. Review generated content
6. Edit as needed and publish

**Example AI Workflow**:
```
Topic: "CVE-2025-12345 Analysis"
   ↓
n8n workflow triggered
   ↓
Scrape CVE database
   ↓
Generate content with GPT-4
   ↓
Create draft in Django
   ↓
Admin reviews and publishes
```

### Blog Categories

Pre-configured categories:
- **Security Advisories**: CVE analysis, threat intelligence
- **Tutorials**: How-to guides, deployment tips
- **Product Updates**: Release notes, new features
- **Community**: User stories, case studies
- **Research**: Threat research, attack analysis

---

## 🛒 Merchandise Management

### Features

- **Product Catalog**: Manage HookProbe-branded merchandise
- **Variants**: Multiple sizes, colors, configurations
- **Inventory Tracking**: Stock levels and alerts
- **Pricing**: Base price, discounts, promotions
- **Product Images**: Multiple images per product
- **AI Descriptions**: Auto-generate product copy
- **Categories**: Organize products (apparel, hardware, services)
- **Order Management**: View and process orders

### Adding a Product

1. Navigate to **Merchandise → Products → Add Product**
2. Enter product details:
   - Name: "HookProbe T-Shirt"
   - SKU: "HP-TSHIRT-001"
   - Description: Product features and benefits
   - Base Price: $25.00
3. Add variants:
   - Size: S, M, L, XL
   - Color: Black, Navy, Gray
4. Upload product images
5. Set inventory levels
6. Save and publish

**AI Product Description**:
- Click **Generate Description**
- AI creates SEO-optimized product copy
- Review and edit as needed

### Product Categories

- **Apparel**: T-shirts, hoodies, hats
- **Hardware**: SBCs, NICs, cables
- **Services**: Support plans, training
- **Digital**: E-books, courses, licenses

---

## 👥 User Management

### Features

- **User Directory**: View all registered users
- **Role-Based Access Control (RBAC)**: Assign permissions
- **Logto Integration**: SSO and OAuth authentication
- **User Groups**: Organize users by team/role
- **Activity Logs**: Audit user actions
- **Permissions**: Granular access control

### User Roles

| Role | Permissions | Use Case |
|------|------------|----------|
| **Superuser** | Full system access | System administrator |
| **Staff** | Content management | Blog editor, content creator |
| **MSSP Admin** | All tenants, full access | MSSP provider admin |
| **Tenant Admin** | Single tenant, full access | Customer administrator |
| **Viewer** | Read-only access | Security analyst, viewer |

### Creating a User

**Via Logto (Recommended)**:
1. Users self-register via Logto
2. Admin assigns roles and groups
3. Automatic provisioning to Django

**Manual Creation**:
1. Navigate to **Users → Add User**
2. Enter username, email, password
3. Assign roles and groups
4. Set permissions
5. Save

### Managing Permissions

```python
# Example: Create content editor role
from django.contrib.auth.models import Group, Permission

editor_group = Group.objects.create(name='Content Editor')
permissions = Permission.objects.filter(
    codename__in=['add_blogpost', 'change_blogpost', 'view_blogpost']
)
editor_group.permissions.set(permissions)

# Assign user to group
user.groups.add(editor_group)
```

---

## 🔒 Security Monitoring

### Features

- **Qsecbit Score Dashboard**: Real-time threat analysis
- **IDS/IPS Alerts**: Zeek, Snort, Suricata events
- **WAF Activity**: NAXSI/ModSecurity blocks
- **Attack Correlation**: Multi-source threat intelligence
- **Incident Response**: Quick actions for threats
- **Security Graphs**: Historical trends and patterns

### Security Dashboard Widgets

**Qsecbit RAG Status**:
```
┌─────────────────────────┐
│  Qsecbit Score: 0.32    │
│                         │
│  Status: 🟢 GREEN       │
│                         │
│  System Resilient       │
│  No threats detected    │
└─────────────────────────┘
```

**Recent Security Events** (last 24h):
- **IDS Alerts**: 23 events (3 critical)
- **WAF Blocks**: 156 attacks (SQL injection, XSS)
- **DDoS Mitigation**: 2 incidents (XDP blocked)
- **Anomalies**: 1 energy spike detected

**Top Threats**:
| Source IP | Attack Type | Count | Blocked |
|-----------|-------------|-------|---------|
| 192.168.1.0 | SQL Injection | 45 | ✅ |
| 10.0.0.0 | XSS Attempt | 32 | ✅ |
| 172.16.0.0 | Port Scan | 18 | ✅ |

### Quick Actions

- **View Detailed Alert**: Click on event for full analysis
- **Block IP Address**: Add attacker to blocklist
- **Trigger Response**: Manually activate Kali response
- **Export Report**: Generate incident report
- **Acknowledge Alert**: Mark event as reviewed

---

## ⚙️ System Configuration

### Network Settings

**Location**: **System → Network Configuration**

Configure:
- **Physical Interface**: eth0, wlan0, etc.
- **VXLAN Settings**: VNI assignments, PSK keys
- **IP Addressing**: Host IPs, subnet assignments
- **DNS**: Primary and secondary DNS servers
- **Routing**: Default gateway, static routes

### POD Management

**Location**: **System → POD Management**

View and manage all PODs:
- **POD Status**: Running, stopped, error
- **Resource Usage**: CPU, RAM, network
- **Container Actions**: Start, stop, restart
- **Logs**: View container logs
- **Configuration**: POD-specific settings

### Service Configuration

**Location**: **System → Services**

Manage HookProbe services:
- **Qsecbit**: Enable/disable, adjust thresholds
- **IDS/IPS**: Snort, Suricata, Zeek rules
- **WAF**: NAXSI/ModSecurity rulesets
- **Monitoring**: Grafana, VictoriaMetrics settings
- **Backups**: Scheduled backups, retention

### Security Settings

**Location**: **System → Security**

Configure security features:
- **Firewall Rules**: nftables configuration
- **OpenFlow ACLs**: Inter-POD traffic rules
- **Encryption**: VXLAN PSK keys
- **Authentication**: Logto settings, MFA
- **GDPR**: Data retention, anonymization

---

## 📈 Monitoring Integration

### Grafana Integration

The Admin Dashboard embeds Grafana dashboards:

**Location**: **Monitoring → Grafana Dashboards**

**Available Dashboards**:
- System Overview (all PODs)
- Qsecbit Analysis
- Security Events
- Network Traffic
- WAF Activity
- POD-009 Email (if installed)

**Features**:
- **Embedded iframes**: View Grafana without leaving admin
- **Single Sign-On**: Auto-login with Logto credentials
- **Custom Timeframes**: Last hour, day, week, month
- **Export**: Download graphs and reports

### API Integration

The Admin Dashboard exposes REST APIs:

**Base URL**: `http://YOUR_IP/api/v1/`

**Endpoints**:
- `/api/v1/pods/` - POD status and management
- `/api/v1/security/events/` - Security events
- `/api/v1/qsecbit/scores/` - Qsecbit scores
- `/api/v1/blog/posts/` - Blog posts
- `/api/v1/products/` - Merchandise catalog
- `/api/v1/users/` - User management

**Authentication**: JWT tokens via Logto

---

## 🎨 Customization

### Branding

**Location**: **System → Appearance**

Customize:
- **Site Title**: "Your Company Security Center"
- **Logo**: Upload custom logo (replaces HookProbe logo)
- **Color Scheme**: Primary, secondary, accent colors
- **Favicon**: Custom favicon icon
- **Footer**: Copyright text, links

**Example**:
```python
# src/web/hookprobe/settings.py
ADMIN_SITE_HEADER = "Acme Corp Security Center"
ADMIN_SITE_TITLE = "Acme Security Admin"
ADMIN_INDEX_TITLE = "Welcome to Acme Security Platform"
```

### Theme

**Built-in Themes**:
- **Light Mode** (default)
- **Dark Mode**

**Toggle**: Click user avatar → **Dark Mode**

### Custom Widgets

Add custom dashboard widgets:

```python
# Create custom widget in src/web/dashboard/widgets.py
from django.db.models import Count
from .models import SecurityEvent

def get_attack_stats():
    return SecurityEvent.objects.filter(
        timestamp__gte=timezone.now() - timedelta(days=7)
    ).values('attack_type').annotate(count=Count('id')).order_by('-count')
```

---

## 📱 Mobile Support

The Admin Dashboard is fully responsive:

- **Mobile-Optimized**: Works on phones and tablets
- **Touch-Friendly**: Large buttons and inputs
- **Adaptive Layout**: Adjusts to screen size
- **Progressive Web App** (PWA): Install as app

**Accessing on Mobile**:
1. Open browser on mobile device
2. Navigate to `http://YOUR_IP/admin/`
3. Login with credentials
4. (Optional) Add to Home Screen for quick access

---

## 🛠️ Troubleshooting

### Dashboard Not Loading

```bash
# Check Django container
podman ps | grep django
podman logs hookprobe-pod-001-web-dmz-django

# Check nginx reverse proxy
podman ps | grep nginx
podman logs hookprobe-pod-001-web-dmz-nginx

# Test database connection
podman exec hookprobe-pod-001-web-dmz-django python manage.py check

# Restart services
podman restart hookprobe-pod-001-web-dmz-django
podman restart hookprobe-pod-001-web-dmz-nginx
```

### Login Issues

```bash
# Check Logto IAM
podman ps | grep logto
podman logs hookprobe-pod-002-iam-logto

# Test OAuth endpoint
curl http://YOUR_IP:3001/.well-known/openid-configuration

# Reset admin password (if needed)
podman exec -it hookprobe-pod-001-web-dmz-django \
    python manage.py changepassword admin
```

### POD Status Not Updating

```bash
# Check metrics collection
curl http://localhost:9100/metrics

# Verify VictoriaMetrics
curl http://localhost:8428/api/v1/query?query=up

# Restart monitoring POD
podman restart hookprobe-pod-005-monitoring-grafana
podman restart hookprobe-pod-005-monitoring-victoria
```

---

## 📚 Additional Resources

- **Main README**: [../../README.md](../../README.md)
- **Dashboard Overview**: [README.md](README.md)
- **MSSP Dashboard**: [mssp-dashboard.md](mssp-dashboard.md)
- **Web Server Setup**: [../../deploy/addons/webserver/README.md](../../deploy/addons/webserver/README.md)
- **IAM Integration**: [../IAM-INTEGRATION-GUIDE.md](../IAM-INTEGRATION-GUIDE.md)

---

## 📞 Support

- **GitHub Issues**: https://github.com/hookprobe/hookprobe/issues
- **Documentation**: Check relevant README files
- **Community**: See [CONTRIBUTING.md](../../docs/CONTRIBUTING.md)

---

**Admin Dashboard (AdminLTE)** - *Comprehensive System Administration*

Built with ❤️ for system administrators and security teams
