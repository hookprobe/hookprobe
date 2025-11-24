# HookProbe Web Application

Django-based CMS and Management Dashboard for HookProbe v5.0

## Overview

This web application provides:
- **Public-facing CMS** using HTML5 UP Forty theme
- **Admin Dashboard** using AdminLTE for system management
- **MSSP Device Management** for edge device monitoring
- **Security Events** dashboard with Qsecbit integration
- **Monitoring Integration** with Grafana and ClickHouse

## Architecture

### Applications

1. **CMS** (`apps/cms/`) - Public website
   - Blog posts, pages, contact forms
   - Forty HTML5 theme integration

2. **Dashboard** (`apps/dashboard/`) - Admin interface
   - System overview
   - AdminLTE theme integration
   - POD status monitoring

3. **Devices** (`apps/devices/`) - MSSP management
   - Customer/tenant management
   - Edge device monitoring
   - Device metrics and logs
   - REST API for device heartbeats

4. **Security** (`apps/security/`) - Security events
   - IDS/IPS/WAF event aggregation
   - Qsecbit score tracking
   - Kali Linux response automation
   - Threat intelligence

5. **Monitoring** (`apps/monitoring/`) - System monitoring
   - Grafana dashboard integration
   - ClickHouse query interface

## Installation

### Prerequisites

- Python 3.11+
- PostgreSQL 14+ (POD-003)
- Redis 7+ (POD-004)
- HookProbe v5.0 infrastructure deployed

### Quick Start

1. **Create virtual environment**
   ```bash
   cd /home/user/hookprobe/src/web
   python3 -m venv venv
   source venv/bin/activate
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   nano .env
   # Update database credentials, API URLs, etc.
   ```

4. **Initialize database**
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

5. **Create superuser**
   ```bash
   python manage.py createsuperuser
   ```

6. **Collect static files**
   ```bash
   python manage.py collectstatic --noinput
   ```

7. **Run development server**
   ```bash
   python manage.py runserver 0.0.0.0:8000
   ```

## Configuration

### Environment Variables

See `.env.example` for all available configuration options.

Key variables:
- `DJANGO_ENV`: `development` or `production`
- `DJANGO_SECRET_KEY`: Secret key for Django (change in production!)
- `POSTGRES_*`: Database connection settings
- `QSECBIT_API_URL`: Qsecbit API endpoint

### Database Configuration

The application connects to HookProbe's PostgreSQL database in POD-003:
- Host: `10.200.3.12`
- Port: `5432`
- Database: `hookprobe`

### Caching

Redis cache is configured in POD-004:
- Host: `10.200.4.12`
- Port: `6379`

## Production Deployment

### Using Gunicorn

```bash
# Install gunicorn
pip install gunicorn

# Run gunicorn
gunicorn hookprobe.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 4 \
    --timeout 120 \
    --access-logfile /var/log/hookprobe/gunicorn-access.log \
    --error-logfile /var/log/hookprobe/gunicorn-error.log
```

### Using Systemd

Create `/etc/systemd/system/hookprobe-web.service`:

```ini
[Unit]
Description=HookProbe Django Web Application
After=network.target

[Service]
Type=notify
User=hookprobe
Group=hookprobe
WorkingDirectory=/opt/hookprobe/src/web
Environment="PATH=/opt/hookprobe/src/web/venv/bin"
Environment="DJANGO_ENV=production"
ExecStart=/opt/hookprobe/src/web/venv/bin/gunicorn \
    --bind 0.0.0.0:8000 \
    --workers 4 \
    hookprobe.wsgi:application

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable hookprobe-web
sudo systemctl start hookprobe-web
```

### Nginx Configuration

```nginx
server {
    listen 80;
    server_name hookprobe.local;

    location /static/ {
        alias /opt/hookprobe/src/web/staticfiles/;
    }

    location /media/ {
        alias /opt/hookprobe/src/web/media/;
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## API Endpoints

### Device Management API

- `GET /api/v1/devices/customers/` - List customers
- `GET /api/v1/devices/devices/` - List devices
- `POST /api/v1/devices/devices/{device_id}/heartbeat/` - Device heartbeat
- `GET /api/v1/devices/devices/{device_id}/metrics/` - Device metrics
- `GET /api/v1/devices/devices/{device_id}/logs/` - Device logs

### Security API

- `GET /api/v1/security/events/` - Security events
- `GET /api/v1/security/qsecbit/` - Qsecbit scores
- `GET /api/v1/security/kali/` - Kali responses

### Authentication

API endpoints require authentication. Use session authentication or basic auth.

Example:
```bash
curl -u admin:password http://10.200.1.12/api/v1/devices/devices/
```

## Frontend Themes

### Forty Theme (Public Site)

Download and extract to `static/public/`:
```bash
cd static/public/
wget https://html5up.net/forty/download
unzip forty.zip
```

### AdminLTE Theme (Admin Dashboard)

Download and extract to `static/admin/`:
```bash
cd static/admin/
wget https://github.com/ColorlibHQ/AdminLTE/releases/download/v3.2.0/AdminLTE-3.2.0.zip
unzip AdminLTE-3.2.0.zip
```

## Development

### Running Tests

```bash
python manage.py test
```

### Creating Migrations

```bash
python manage.py makemigrations
python manage.py migrate
```

### Django Shell

```bash
python manage.py shell
```

### Database Shell

```bash
python manage.py dbshell
```

## Folder Structure

```
src/web/
├── manage.py                 # Django management script
├── requirements.txt          # Python dependencies
├── .env.example             # Environment variables template
├── .gitignore               # Git ignore rules
├── README.md                # This file
│
├── hookprobe/               # Main Django project
│   ├── __init__.py
│   ├── settings/           # Settings (base, dev, production)
│   ├── urls.py             # URL routing
│   ├── wsgi.py             # WSGI entry point
│   └── asgi.py             # ASGI entry point
│
├── apps/                    # Django applications
│   ├── cms/                # Public CMS (Forty theme)
│   ├── dashboard/          # Admin dashboard (AdminLTE)
│   ├── devices/            # MSSP device management
│   ├── monitoring/         # Monitoring integration
│   └── security/           # Security & Qsecbit
│
├── templates/              # Django templates
│   ├── base/              # Base templates
│   ├── public/            # Forty theme templates
│   ├── admin/             # AdminLTE templates
│   └── emails/            # Email templates
│
├── static/                 # Static files
│   ├── public/            # Forty theme assets
│   ├── admin/             # AdminLTE assets
│   └── common/            # Shared assets
│
└── media/                  # User uploads
    ├── uploads/
    └── cache/
```

## Troubleshooting

### Database Connection Issues

```bash
# Test PostgreSQL connection
psql -h 10.200.3.12 -U hookprobe -d hookprobe

# Check if POD-003 is running
podman ps | grep pod-003
```

### Redis Connection Issues

```bash
# Test Redis connection
redis-cli -h 10.200.4.12 ping

# Check if POD-004 is running
podman ps | grep pod-004
```

### Static Files Not Loading

```bash
# Collect static files
python manage.py collectstatic --noinput

# Check STATIC_ROOT permissions
ls -la staticfiles/
```

## Contributing

See main [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

## License

MIT License - See [LICENSE](../../LICENSE)

## Support

- Documentation: https://github.com/hookprobe/hookprobe
- Issues: https://github.com/hookprobe/hookprobe/issues
- Email: qsecbit@hookprobe.com
