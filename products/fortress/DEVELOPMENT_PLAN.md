# Fortress MVP Development Plan

**Version**: 1.0.0
**Date**: 2025-12-14
**Target**: Small Business Security Gateway

---

## Executive Summary

Fortress is the "Guardian on steroids" - taking the proven Guardian MVP and adding:
1. **AdminLTE Dashboard** - Professional admin interface
2. **Authentication** - Username/password with sessions
3. **Business Reporting** - Weekly reports, device inventory
4. **VLAN Management UI** - Visual network segmentation
5. **Multi-user Support** - Admin, Operator, Viewer roles

---

## Phase 1: Core Infrastructure (MVP)

### 1.1 Authentication System

**Files to Create:**
- `web/modules/auth/__init__.py` - Auth blueprint
- `web/modules/auth/views.py` - Login/logout routes
- `web/modules/auth/models.py` - User model (JSON-based for MVP)
- `web/modules/auth/decorators.py` - @login_required, @admin_required
- `web/templates/auth/login.html` - AdminLTE login page

**Features:**
- [x] Username/password authentication
- [x] Session management with Flask-Login
- [x] Password hashing with bcrypt
- [x] Remember me functionality
- [ ] Password reset (future)

**User Roles:**
```python
class UserRole(Enum):
    ADMIN = "admin"       # Full access
    OPERATOR = "operator" # Manage devices, view reports
    VIEWER = "viewer"     # Read-only dashboard access
```

### 1.2 AdminLTE Integration

**Files to Create:**
- `web/templates/base.html` - AdminLTE base layout
- `web/templates/partials/sidebar.html` - Navigation sidebar
- `web/templates/partials/header.html` - Top navbar
- `web/templates/partials/footer.html` - Footer
- `web/static/vendor/adminlte/` - AdminLTE assets (CDN or bundled)

**AdminLTE Sections:**
1. Dashboard (main overview)
2. Security (Qsecbit, threats)
3. Clients (device management)
4. Networks (VLAN configuration)
5. dnsXai (DNS protection)
6. Reports (business reports)
7. Settings (system config, users)

### 1.3 Flask Application Structure

```python
# web/app.py
from flask import Flask
from flask_login import LoginManager

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    # Initialize extensions
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    # Register blueprints
    from modules.auth import auth_bp
    from modules.dashboard import dashboard_bp
    from modules.security import security_bp
    from modules.clients import clients_bp
    from modules.networks import networks_bp
    from modules.dnsxai import dnsxai_bp
    from modules.reports import reports_bp
    from modules.settings import settings_bp
    from modules.api import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(security_bp, url_prefix='/security')
    app.register_blueprint(clients_bp, url_prefix='/clients')
    app.register_blueprint(networks_bp, url_prefix='/networks')
    app.register_blueprint(dnsxai_bp, url_prefix='/dnsxai')
    app.register_blueprint(reports_bp, url_prefix='/reports')
    app.register_blueprint(settings_bp, url_prefix='/settings')
    app.register_blueprint(api_bp, url_prefix='/api')

    return app
```

---

## Phase 2: Reuse Guardian Components

### 2.1 Components to Copy from Guardian

| Guardian Module | Fortress Module | Changes Needed |
|-----------------|-----------------|----------------|
| `modules/security/views.py` | `modules/security/views.py` | Add auth decorators |
| `modules/clients/views.py` | `modules/clients/views.py` | Add VLAN assignment |
| `modules/dnsxai/views.py` | `modules/dnsxai/views.py` | Add per-VLAN policies |
| `modules/config/views.py` | `modules/networks/views.py` | Rename, add VLANs |
| `modules/system/views.py` | `modules/settings/views.py` | Add user management |
| `modules/cortex/views.py` | `modules/dashboard/views.py` | Embed in dashboard |
| `modules/qsecbit/views.py` | `modules/security/qsecbit.py` | Integrate |

### 2.2 Shared Libraries to Import

```python
# These can be imported directly from Guardian
from products.guardian.lib.layer_threat_detector import LayerThreatDetector
from products.guardian.lib.mesh_integration import GuardianMeshAgent
from products.guardian.lib.htp_client import HTPClient

# Or copy and modify for Fortress
# Fortress may need enhanced versions
```

### 2.3 Templates to Adapt

| Guardian Template | Fortress Template | AdminLTE Conversion |
|-------------------|-------------------|---------------------|
| `core/dashboard.html` | `dashboard/index.html` | Widgets → Info boxes |
| `security/metrics.html` | `security/index.html` | Cards → AdminLTE cards |
| `clients/index.html` | `clients/index.html` | Table → DataTables |
| `dnsxai/index.html` | `dnsxai/index.html` | Add VLAN selector |
| `cortex/embedded.html` | `dashboard/globe.html` | Full-width embed |

---

## Phase 3: New Fortress Features

### 3.1 VLAN Management UI

**New Features:**
- Visual VLAN topology diagram
- Drag-and-drop device assignment
- Per-VLAN bandwidth limits
- Inter-VLAN firewall rules

**API Endpoints:**
```
GET    /api/vlans                    # List all VLANs
POST   /api/vlans                    # Create VLAN
PUT    /api/vlans/<id>               # Update VLAN
DELETE /api/vlans/<id>               # Delete VLAN
POST   /api/vlans/<id>/devices       # Assign device to VLAN
GET    /api/vlans/<id>/stats         # VLAN traffic stats
```

### 3.2 Business Reports

**Report Types:**
1. **Weekly Security Summary** - Threats blocked, Qsecbit score
2. **Device Inventory** - All connected devices
3. **Bandwidth Usage** - Per-device, per-VLAN
4. **DNS Analytics** - Blocked domains, queries

**Implementation:**
```python
# modules/reports/generator.py
class ReportGenerator:
    def weekly_security_report(self, start_date, end_date):
        """Generate PDF security report."""
        pass

    def device_inventory_csv(self):
        """Export device list as CSV."""
        pass

    def schedule_report(self, report_type, schedule, email):
        """Schedule automatic report generation."""
        pass
```

### 3.3 User Management

**Features:**
- Add/edit/delete users
- Role assignment
- Password policies
- Login history
- Session management

**Storage (MVP):**
```json
// /etc/hookprobe/users.json
{
  "users": {
    "admin": {
      "password_hash": "$2b$12$...",
      "role": "admin",
      "email": "admin@business.com",
      "created": "2025-01-01T00:00:00Z",
      "last_login": "2025-01-15T10:30:00Z"
    }
  }
}
```

---

## Phase 4: UI/UX Design

### 4.1 AdminLTE Theme Customization

**Color Scheme (HookProbe brand):**
```css
:root {
    --hp-prussian: #002742;
    --hp-siren: #850033;
    --hp-tangerine: #e69500;
    --hp-ebb: #e6dbdb;
    --hp-black-pearl: #02040d;
}

/* AdminLTE overrides */
.main-sidebar {
    background-color: var(--hp-prussian);
}
.brand-link {
    background-color: var(--hp-black-pearl);
}
.nav-sidebar .nav-link.active {
    background-color: var(--hp-tangerine);
}
```

### 4.2 Dashboard Layout

```
┌────────────────────────────────────────────────────────────────┐
│ [Logo] HookProbe Fortress              [🔔] [👤 Admin ▼]      │
├──────────┬─────────────────────────────────────────────────────┤
│          │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐│
│ Dashboard│  │ Qsecbit  │ │ Devices  │ │ Threats  │ │ DNS Blk ││
│ Security │  │   GREEN  │ │    12    │ │    3     │ │  1,234  ││
│ Clients  │  └──────────┘ └──────────┘ └──────────┘ └─────────┘│
│ Networks │  ┌─────────────────────────────────────────────────┐│
│ dnsXai   │  │                                                 ││
│ Reports  │  │              Network Traffic Chart              ││
│ Settings │  │                                                 ││
│          │  └─────────────────────────────────────────────────┘│
│          │  ┌─────────────────────┐ ┌─────────────────────────┐│
│          │  │   Recent Threats    │ │    Connected Devices    ││
│          │  │   - SYN Flood       │ │    - iPhone (Guest)     ││
│          │  │   - Port Scan       │ │    - POS Terminal       ││
│          │  └─────────────────────┘ └─────────────────────────┘│
└──────────┴─────────────────────────────────────────────────────┘
```

---

## Phase 5: API Layer

### 5.1 REST API Endpoints

All Guardian API endpoints plus:

```
# Authentication
POST   /api/auth/login               # Login
POST   /api/auth/logout              # Logout
GET    /api/auth/me                  # Current user

# VLAN Management
GET    /api/vlans                    # List VLANs
POST   /api/vlans                    # Create VLAN
PUT    /api/vlans/<id>               # Update VLAN
DELETE /api/vlans/<id>               # Delete VLAN

# Reports
GET    /api/reports                  # List available reports
POST   /api/reports/generate         # Generate report
GET    /api/reports/<id>/download    # Download report

# Users (admin only)
GET    /api/users                    # List users
POST   /api/users                    # Create user
PUT    /api/users/<id>               # Update user
DELETE /api/users/<id>               # Delete user
```

### 5.2 WebSocket Events

Reuse Guardian WebSocket for real-time updates:
```javascript
// Real-time dashboard updates
socket.on('qsecbit_update', updateQsecbitWidget);
socket.on('threat_detected', showThreatAlert);
socket.on('device_connected', updateDeviceList);
socket.on('vlan_traffic', updateTrafficChart);
```

---

## Implementation Timeline

### Week 1: Foundation
- [ ] Set up Flask app with AdminLTE
- [ ] Implement authentication system
- [ ] Create base templates (sidebar, header, footer)
- [ ] Port Guardian security module

### Week 2: Core Features
- [ ] Port clients module with VLAN assignment
- [ ] Port dnsXai module with per-VLAN policies
- [ ] Create dashboard with widgets
- [ ] Implement user management

### Week 3: Advanced Features
- [ ] VLAN management UI
- [ ] Basic reporting (device inventory)
- [ ] Settings page
- [ ] API documentation

### Week 4: Polish & Testing
- [ ] Mobile responsive testing
- [ ] Security audit
- [ ] Performance optimization
- [ ] Documentation

---

## File Structure (Complete)

```
products/fortress/web/
├── app.py                          # Flask application factory
├── config.py                       # Configuration
├── requirements.txt                # Python dependencies
├── wsgi.py                         # WSGI entry point
│
├── modules/
│   ├── __init__.py                 # Blueprint registration
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── views.py                # Login, logout, register
│   │   ├── models.py               # User model
│   │   └── decorators.py           # @login_required, @admin_required
│   ├── dashboard/
│   │   ├── __init__.py
│   │   └── views.py                # Main dashboard
│   ├── security/
│   │   ├── __init__.py
│   │   ├── views.py                # Security overview
│   │   └── qsecbit.py              # Qsecbit integration
│   ├── clients/
│   │   ├── __init__.py
│   │   └── views.py                # Device management
│   ├── networks/
│   │   ├── __init__.py
│   │   └── views.py                # VLAN configuration
│   ├── dnsxai/
│   │   ├── __init__.py
│   │   └── views.py                # DNS protection
│   ├── reports/
│   │   ├── __init__.py
│   │   ├── views.py                # Report UI
│   │   └── generator.py            # Report generation
│   ├── settings/
│   │   ├── __init__.py
│   │   └── views.py                # System settings, users
│   └── api/
│       ├── __init__.py
│       └── routes.py               # REST API endpoints
│
├── templates/
│   ├── base.html                   # AdminLTE base layout
│   ├── auth/
│   │   └── login.html              # Login page
│   ├── dashboard/
│   │   └── index.html              # Main dashboard
│   ├── security/
│   │   └── index.html              # Security overview
│   ├── clients/
│   │   └── index.html              # Device list
│   ├── networks/
│   │   └── index.html              # VLAN management
│   ├── dnsxai/
│   │   └── index.html              # DNS protection
│   ├── reports/
│   │   └── index.html              # Reports
│   ├── settings/
│   │   ├── index.html              # General settings
│   │   └── users.html              # User management
│   └── partials/
│       ├── sidebar.html            # Left sidebar
│       ├── header.html             # Top navbar
│       ├── footer.html             # Footer
│       └── alerts.html             # Flash messages
│
└── static/
    ├── css/
    │   └── fortress.css            # Custom styles
    ├── js/
    │   └── fortress.js             # Custom scripts
    ├── img/
    │   └── logo.png                # HookProbe logo
    └── vendor/
        └── adminlte/               # AdminLTE assets (or CDN)
```

---

## Dependencies

```
# requirements.txt
Flask>=2.3.0
Flask-Login>=0.6.0
Flask-WTF>=1.2.0
bcrypt>=4.0.0
gunicorn>=21.0.0

# Optional for reports
reportlab>=4.0.0          # PDF generation
xlsxwriter>=3.1.0         # Excel export

# Inherited from Guardian
requests>=2.31.0
psutil>=5.9.0
```

---

## Security Considerations

1. **HTTPS Required** - Use self-signed cert or Let's Encrypt
2. **CSRF Protection** - Flask-WTF tokens on all forms
3. **Session Security** - HTTPOnly, Secure cookies
4. **Password Policy** - Minimum 8 chars, complexity optional
5. **Rate Limiting** - Prevent brute force on login
6. **Audit Logging** - Log all admin actions

---

## Migration from Guardian

For users upgrading from Guardian to Fortress:

1. Guardian settings are preserved
2. New admin user created during install
3. All existing clients visible in new UI
4. dnsXai settings maintained
5. No re-configuration needed

---

## Success Metrics

MVP is complete when:
- [ ] Can login with username/password
- [ ] Dashboard shows Qsecbit score, device count, threats
- [ ] Can view and manage connected devices
- [ ] Can configure VLAN assignments
- [ ] Can view dnsXai statistics
- [ ] Can generate basic device inventory report
- [ ] Can add/edit users (admin only)
- [ ] Mobile-responsive design works

---

## Next Steps After MVP

1. **PDF Reports** - Weekly security summaries
2. **Email Alerts** - Threat notifications
3. **Captive Portal** - Guest WiFi login page
4. **Backup/Restore** - Configuration backup
5. **Multi-site** - Manage multiple Fortress nodes
6. **Mesh Integration** - Cloud dashboard sync
