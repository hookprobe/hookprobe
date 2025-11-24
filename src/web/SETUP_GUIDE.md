# HookProbe Web Application - Setup Guide

## Project Structure

The HookProbe web application has been set up with a clean, modular Django structure designed for scalability and MSSP edge device management.

### Directory Structure

```
src/web/
├── manage.py                      # Django CLI management script
├── requirements.txt               # Python dependencies
├── .env.example                   # Environment variables template
├── .gitignore                     # Git ignore patterns
├── README.md                      # Main documentation
├── SETUP_GUIDE.md                 # This file
│
├── hookprobe/                     # Main Django project
│   ├── __init__.py
│   ├── settings/                  # Split settings configuration
│   │   ├── __init__.py           # Auto-detect environment
│   │   ├── base.py               # Base settings
│   │   ├── development.py        # Development settings
│   │   └── production.py         # Production settings
│   ├── urls.py                    # Main URL routing
│   ├── wsgi.py                    # WSGI application
│   └── asgi.py                    # ASGI application (async)
│
├── apps/                          # Django applications
│   ├── __init__.py
│   │
│   ├── cms/                       # Public-facing CMS
│   │   ├── __init__.py
│   │   ├── apps.py
│   │   ├── models.py             # Page, BlogPost, BlogCategory, ContactSubmission
│   │   ├── views.py              # Public views
│   │   ├── urls.py
│   │   ├── forms.py              # Contact form
│   │   ├── admin.py              # Django admin config
│   │   └── migrations/
│   │
│   ├── dashboard/                 # Admin dashboard (AdminLTE)
│   │   ├── __init__.py
│   │   ├── apps.py
│   │   ├── models.py             # No models (aggregates data)
│   │   ├── views.py              # Dashboard views
│   │   ├── urls.py
│   │   ├── admin.py
│   │   └── migrations/
│   │
│   ├── devices/                   # MSSP device management
│   │   ├── __init__.py
│   │   ├── apps.py
│   │   ├── models.py             # Customer, Device, DeviceLog, DeviceMetric
│   │   ├── views.py              # Device views
│   │   ├── urls.py
│   │   ├── admin.py
│   │   ├── api/                  # REST API
│   │   │   ├── __init__.py
│   │   │   ├── serializers.py   # DRF serializers
│   │   │   ├── views.py         # API viewsets
│   │   │   └── urls.py          # API routes
│   │   └── migrations/
│   │
│   ├── monitoring/                # Monitoring integration
│   │   ├── __init__.py
│   │   ├── apps.py
│   │   ├── models.py             # No models (external data)
│   │   ├── views.py              # Monitoring views
│   │   ├── urls.py
│   │   ├── admin.py
│   │   └── migrations/
│   │
│   └── security/                  # Security & Qsecbit
│       ├── __init__.py
│       ├── apps.py
│       ├── models.py             # SecurityEvent, QsecbitScore, KaliResponse, ThreatIntelligence
│       ├── views.py              # Security views
│       ├── urls.py
│       ├── admin.py
│       ├── api/                  # REST API
│       │   ├── __init__.py
│       │   ├── serializers.py
│       │   ├── views.py
│       │   └── urls.py
│       └── migrations/
│
├── templates/                     # Django templates
│   ├── base/                     # Base templates
│   │   ├── base.html             # Master template
│   │   └── errors/               # Error pages
│   │       ├── 404.html
│   │       ├── 500.html
│   │       └── 403.html
│   │
│   ├── public/                   # Forty theme templates (public site)
│   │   ├── base_public.html     # Public base template
│   │   ├── home.html            # Homepage
│   │   ├── about.html           # About page
│   │   ├── contact.html         # Contact page
│   │   └── blog/                # Blog templates
│   │       ├── list.html        # Blog list
│   │       └── detail.html      # Blog post detail
│   │
│   ├── admin/                    # AdminLTE templates (admin interface)
│   │   ├── base_admin.html      # Admin base template
│   │   ├── dashboard.html       # Main dashboard
│   │   ├── devices/             # Device templates
│   │   │   ├── list.html
│   │   │   ├── detail.html
│   │   │   └── add.html
│   │   ├── monitoring/          # Monitoring templates
│   │   │   └── overview.html
│   │   └── security/            # Security templates
│   │       ├── events.html
│   │       └── qsecbit.html
│   │
│   └── emails/                   # Email templates
│       └── base_email.html
│
├── static/                        # Static files (CSS, JS, images)
│   ├── public/                   # Forty theme assets
│   │   ├── css/
│   │   ├── js/
│   │   ├── images/
│   │   └── fonts/
│   │
│   ├── admin/                    # AdminLTE assets
│   │   ├── css/
│   │   ├── js/
│   │   ├── images/
│   │   └── plugins/
│   │
│   └── common/                   # Shared assets
│       ├── css/
│       ├── js/
│       └── images/
│
└── media/                         # User-uploaded files
    ├── uploads/
    └── cache/
```

## Key Features

### 1. **Public CMS (Forty Theme)**
   - Blog posts with categories
   - Static pages (About, Contact, etc.)
   - Contact form submissions
   - SEO-friendly URLs

### 2. **Admin Dashboard (AdminLTE)**
   - System overview
   - POD status monitoring
   - Device management interface
   - Security events dashboard
   - Qsecbit score visualization

### 3. **MSSP Device Management**
   - Multi-tenant customer management
   - Edge device tracking
   - Device heartbeat API
   - Metrics collection (CPU, RAM, disk, network)
   - Device logs aggregation
   - REST API for device operations

### 4. **Security Integration**
   - Security event aggregation (IDS/IPS/WAF)
   - Qsecbit score tracking
   - Kali Linux response automation
   - Threat intelligence database
   - REST API for security data

### 5. **Monitoring Integration**
   - Grafana dashboard embeds
   - ClickHouse query interface
   - VictoriaMetrics integration

## Next Steps

### 1. Download Frontend Themes

**Forty Theme (Public Site):**
```bash
cd src/web/static/public/
wget https://html5up.net/forty/download -O forty.zip
unzip forty.zip
mv forty/* .
rm -rf forty forty.zip
```

**AdminLTE Theme (Admin Dashboard):**
```bash
cd src/web/static/admin/
wget https://github.com/ColorlibHQ/AdminLTE/releases/download/v3.2.0/AdminLTE-3.2.0.zip
unzip AdminLTE-3.2.0.zip
mv AdminLTE-3.2.0/* .
rm -rf AdminLTE-3.2.0 AdminLTE-3.2.0.zip
```

### 2. Set Up Virtual Environment

```bash
cd src/web/
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows
```

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure Environment

```bash
cp .env.example .env
nano .env
```

Update these critical settings:
- `DJANGO_SECRET_KEY` - Generate a new secret key
- `POSTGRES_PASSWORD` - Match POD-003 password
- `QSECBIT_API_URL` - Verify Qsecbit API endpoint

### 5. Initialize Database

```bash
# Create migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser
```

### 6. Collect Static Files

```bash
python manage.py collectstatic --noinput
```

### 7. Run Development Server

```bash
python manage.py runserver 0.0.0.0:8000
```

Access the application:
- Public site: http://localhost:8000/
- Admin interface: http://localhost:8000/admin/
- Dashboard: http://localhost:8000/dashboard/
- API documentation: http://localhost:8000/api/v1/

### 8. Create Base Templates

You'll need to create actual HTML templates using the Forty and AdminLTE themes. Start with:

1. **Base public template** (`templates/public/base_public.html`)
   - Integrate Forty theme HTML structure
   - Include CSS/JS from `static/public/`

2. **Base admin template** (`templates/admin/base_admin.html`)
   - Integrate AdminLTE layout
   - Include CSS/JS from `static/admin/`

3. **Homepage** (`templates/public/home.html`)
   - Extend base_public.html
   - Display featured blog posts

4. **Dashboard** (`templates/admin/dashboard.html`)
   - Extend base_admin.html
   - Display system metrics and Qsecbit status

### 9. Configure Nginx (Production)

Create `/etc/nginx/sites-available/hookprobe-web`:

```nginx
server {
    listen 80;
    server_name hookprobe.local 10.200.1.12;

    client_max_body_size 100M;

    location /static/ {
        alias /opt/hookprobe/src/web/staticfiles/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    location /media/ {
        alias /opt/hookprobe/src/web/media/;
        expires 30d;
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

Enable site:
```bash
sudo ln -s /etc/nginx/sites-available/hookprobe-web /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 10. Set Up Systemd Service (Production)

Create `/etc/systemd/system/hookprobe-web.service`:

```ini
[Unit]
Description=HookProbe Django Web Application
After=network.target postgresql.service redis.service

[Service]
Type=notify
User=hookprobe
Group=hookprobe
WorkingDirectory=/opt/hookprobe/src/web
Environment="PATH=/opt/hookprobe/src/web/venv/bin"
Environment="DJANGO_ENV=production"
EnvironmentFile=/opt/hookprobe/src/web/.env
ExecStart=/opt/hookprobe/src/web/venv/bin/gunicorn \
    --bind 127.0.0.1:8000 \
    --workers 4 \
    --worker-class sync \
    --timeout 120 \
    --access-logfile /var/log/hookprobe/gunicorn-access.log \
    --error-logfile /var/log/hookprobe/gunicorn-error.log \
    --log-level info \
    hookprobe.wsgi:application
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo mkdir -p /var/log/hookprobe
sudo chown hookprobe:hookprobe /var/log/hookprobe
sudo systemctl daemon-reload
sudo systemctl enable hookprobe-web
sudo systemctl start hookprobe-web
sudo systemctl status hookprobe-web
```

## Testing the API

### Device Heartbeat

```bash
curl -X POST http://localhost:8000/api/v1/devices/devices/device-001/heartbeat/ \
  -H "Content-Type: application/json" \
  -u admin:password \
  -d '{
    "device_id": "device-001",
    "status": "online",
    "cpu_usage": 45.2,
    "ram_usage": 62.1,
    "disk_usage": 38.5,
    "uptime_seconds": 86400,
    "qsecbit_score": 0.25,
    "threat_events_count": 3
  }'
```

### Get Device Metrics

```bash
curl http://localhost:8000/api/v1/devices/devices/device-001/metrics/?hours=24 \
  -u admin:password
```

### Get Security Events

```bash
curl http://localhost:8000/api/v1/security/events/?severity=critical \
  -u admin:password
```

## Development Tips

### Django Management Commands

```bash
# Create new app
python manage.py startapp newapp

# Create superuser
python manage.py createsuperuser

# Shell with Django ORM
python manage.py shell

# Database shell
python manage.py dbshell

# Check for issues
python manage.py check

# Run tests
python manage.py test
```

### Database Management

```bash
# Create migrations for all apps
python manage.py makemigrations

# Create migrations for specific app
python manage.py makemigrations cms

# Show migration SQL
python manage.py sqlmigrate cms 0001

# Rollback migration
python manage.py migrate cms 0001

# Reset migrations (CAUTION!)
find . -path "*/migrations/*.py" -not -name "__init__.py" -delete
find . -path "*/migrations/*.pyc" -delete
```

### Testing API with Python

```python
import requests

# Authenticate
session = requests.Session()
session.auth = ('admin', 'password')

# Get devices
response = session.get('http://localhost:8000/api/v1/devices/devices/')
print(response.json())

# Send heartbeat
heartbeat_data = {
    'device_id': 'device-001',
    'status': 'online',
    'cpu_usage': 45.2,
    'ram_usage': 62.1,
    'disk_usage': 38.5,
    'uptime_seconds': 86400
}
response = session.post(
    'http://localhost:8000/api/v1/devices/devices/device-001/heartbeat/',
    json=heartbeat_data
)
print(response.json())
```

## Integration with HookProbe PODs

### POD-001 (Web DMZ)
- Django runs here at `10.200.1.12:8000`
- Nginx serves as reverse proxy
- Static files served by Nginx

### POD-003 (Database)
- PostgreSQL at `10.200.3.12:5432`
- Store all Django models

### POD-004 (Cache)
- Redis at `10.200.4.12:6379`
- Session storage
- Caching layer

### POD-005 (Monitoring)
- ClickHouse at `10.200.5.12:8123`
- Read security analytics
- Grafana at `10.200.5.12:3000`

### POD-006 (Security)
- Qsecbit API at `10.200.6.12:8888`
- Fetch threat scores
- Security event aggregation

## Troubleshooting

### Issue: Cannot connect to PostgreSQL

```bash
# Test connection
psql -h 10.200.3.12 -U hookprobe -d hookprobe

# Check POD status
podman ps | grep pod-003

# Check Django settings
python manage.py shell
>>> from django.conf import settings
>>> settings.DATABASES
```

### Issue: Static files not loading

```bash
# Collect static files
python manage.py collectstatic --noinput

# Check STATIC_ROOT
python manage.py shell
>>> from django.conf import settings
>>> settings.STATIC_ROOT

# Verify Nginx config
sudo nginx -t
```

### Issue: API returns 401 Unauthorized

- Check authentication credentials
- Verify REST_FRAMEWORK settings in `settings/base.py`
- Test with basic auth: `curl -u admin:password`

## Contributing

When adding new features:
1. Create migrations: `python manage.py makemigrations`
2. Apply migrations: `python manage.py migrate`
3. Update admin.py for new models
4. Create serializers for API endpoints
5. Add tests
6. Update documentation

## Resources

- Django Documentation: https://docs.djangoproject.com/
- Django REST Framework: https://www.django-rest-framework.org/
- Forty Theme: https://html5up.net/forty
- AdminLTE: https://adminlte.io/
- HookProbe: https://github.com/hookprobe/hookprobe

---

**Happy coding! 🚀**
