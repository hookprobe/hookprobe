#!/bin/bash
#
# HookProbe Web Server - Post-Installation Setup
#
# This script installs the Django web application as an optional addon
# after the main HookProbe infrastructure has been deployed.
#
# Usage:
#   sudo ./setup-webserver.sh [edge|cloud|standalone]
#
# Requirements:
#   - HookProbe PODs 001-007 must be running
#   - PostgreSQL (POD-003) must be accessible
#   - Redis (POD-004) must be accessible
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config/webserver-config.sh"

# ============================================================================
# Helper Functions
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if Python 3.11+ is available
    if ! command -v python3 &>/dev/null; then
        log_error "Python 3 is not installed"
        exit 1
    fi

    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
    if (( $(echo "$PYTHON_VERSION < 3.11" | bc -l) )); then
        log_error "Python 3.11 or higher is required (found $PYTHON_VERSION)"
        exit 1
    fi

    # Check if pip is available
    if ! command -v pip3 &>/dev/null; then
        log_error "pip3 is not installed"
        exit 1
    fi

    # Check if git is available
    if ! command -v git &>/dev/null; then
        log_error "git is not installed"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

# ============================================================================
# Installation Functions
# ============================================================================

install_system_dependencies() {
    log_info "Installing system dependencies..."

    if command -v dnf &>/dev/null; then
        # Fedora/RHEL/Rocky/Alma
        dnf install -y \
            python3.11 \
            python3.11-devel \
            python3-pip \
            postgresql-devel \
            gcc \
            nginx \
            || true
    elif command -v apt-get &>/dev/null; then
        # Debian/Ubuntu
        apt-get update
        apt-get install -y \
            python3.11 \
            python3.11-dev \
            python3-pip \
            libpq-dev \
            gcc \
            nginx \
            || true
    fi

    log_success "System dependencies installed"
}

create_directories() {
    log_info "Creating directories..."

    mkdir -p "${INSTALL_DIR}"
    mkdir -p "${WEB_DIR}"
    mkdir -p "${LOG_DIR}"
    mkdir -p "${STATIC_DIR}"
    mkdir -p "${MEDIA_DIR}"

    log_success "Directories created"
}

copy_web_application() {
    log_info "Copying web application files..."

    # Copy web application from repo to install directory
    if [ -d "${REPO_ROOT}/products/mssp/web" ]; then
        cp -r "${REPO_ROOT}/products/mssp/web/"* "${WEB_DIR}/"
        log_success "Web application files copied"
    else
        log_error "Web application source not found at ${REPO_ROOT}/products/mssp/web"
        exit 1
    fi
}

create_virtualenv() {
    log_info "Creating Python virtual environment..."

    python3 -m venv "${VENV_DIR}"
    source "${VENV_DIR}/bin/activate"

    # Upgrade pip
    pip install --upgrade pip

    log_success "Virtual environment created"
}

install_python_dependencies() {
    log_info "Installing Python dependencies..."

    source "${VENV_DIR}/bin/activate"

    pip install -r "${WEB_DIR}/requirements.txt"

    log_success "Python dependencies installed"
}

create_env_file() {
    log_info "Creating environment configuration..."

    cat > "${WEB_DIR}/.env" <<EOF
# Django Configuration
DJANGO_ENV=${DJANGO_ENV}
DJANGO_SECRET_KEY=${DJANGO_SECRET_KEY}
DJANGO_ALLOWED_HOST=${DJANGO_ALLOWED_HOST}
DEBUG=${DJANGO_DEBUG}

# Database Configuration (POD-003)
POSTGRES_DB=${POSTGRES_DB}
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_HOST=${POSTGRES_HOST}
POSTGRES_PORT=${POSTGRES_PORT}

# Redis Configuration (POD-004)
REDIS_HOST=${REDIS_HOST}
REDIS_PORT=${REDIS_PORT}

# ClickHouse Configuration (POD-005)
CLICKHOUSE_HOST=${CLICKHOUSE_HOST}
CLICKHOUSE_PORT=${CLICKHOUSE_PORT}
CLICKHOUSE_DATABASE=${CLICKHOUSE_DATABASE}

# Qsecbit API Configuration (POD-006)
QSECBIT_API_URL=${QSECBIT_API_URL}

# Grafana Configuration
GRAFANA_URL=${GRAFANA_URL}
GRAFANA_API_KEY=${GRAFANA_API_KEY}

# Email Configuration
EMAIL_HOST=${EMAIL_HOST}
EMAIL_PORT=${EMAIL_PORT}
EMAIL_HOST_USER=${EMAIL_HOST_USER}
EMAIL_HOST_PASSWORD=${EMAIL_HOST_PASSWORD}
DEFAULT_FROM_EMAIL=${DEFAULT_FROM_EMAIL}

# Multi-Tenant Configuration
MULTITENANT_ENABLED=${MULTITENANT_ENABLED}
TENANT_ID=${TENANT_ID}
EOF

    chmod 600 "${WEB_DIR}/.env"

    log_success "Environment configuration created"
}

initialize_database() {
    log_info "Initializing database..."

    source "${VENV_DIR}/bin/activate"
    cd "${WEB_DIR}"

    # Wait for PostgreSQL to be ready
    log_info "Waiting for PostgreSQL..."
    for i in {1..30}; do
        if nc -z -w5 "$POSTGRES_HOST" "$POSTGRES_PORT" 2>/dev/null; then
            log_success "PostgreSQL is ready"
            break
        fi
        if [ $i -eq 30 ]; then
            log_error "PostgreSQL is not available after 30 attempts"
            exit 1
        fi
        sleep 2
    done

    # Test database connection
    log_info "Testing database connection..."
    if ! python manage.py check --database default 2>/dev/null; then
        log_error "Database connection failed. Please verify PostgreSQL configuration."
        exit 1
    fi
    log_success "Database connection successful"

    # Run migrations
    log_info "Running database migrations..."

    # Create migrations if needed (development mode only)
    if [ "$DJANGO_DEBUG" = "true" ] || [ "$DJANGO_DEBUG" = "True" ]; then
        log_info "Checking for new migrations..."
        python manage.py makemigrations --noinput || log_warning "No new migrations to create"
    fi

    # Apply migrations
    if ! python manage.py migrate --noinput; then
        log_error "Database migration failed"
        exit 1
    fi
    log_success "Database migrations applied successfully"

    # Verify migrations
    log_info "Verifying migrations..."
    if python manage.py showmigrations 2>/dev/null | grep -q '\[ \]'; then
        log_warning "Some migrations may not have been applied"
    else
        log_success "All migrations verified"
    fi

    log_success "Database initialized"
}

load_seed_data() {
    log_info "Loading seed data..."

    source "${VENV_DIR}/bin/activate"
    cd "${WEB_DIR}"

    # Check if seed data command exists
    if python manage.py help seed_demo_data &>/dev/null; then
        log_info "Found seed_demo_data command, loading demo data..."

        # Ask user if they want to load seed data
        echo ""
        read -p "Do you want to load demo/sample data? (yes/no): " -r
        if [[ $REPLY =~ ^[Yy]es$ ]]; then
            if python manage.py seed_demo_data; then
                log_success "Seed data loaded successfully"
            else
                log_warning "Seed data loading encountered issues (non-critical)"
            fi
        else
            log_info "Skipping seed data"
        fi
    else
        log_info "No seed data command found (skipping)"
    fi
}

collect_static_files() {
    log_info "Collecting static files..."

    source "${VENV_DIR}/bin/activate"
    cd "${WEB_DIR}"

    python manage.py collectstatic --noinput

    log_success "Static files collected"
}

download_frontend_themes() {
    if [ "$AUTO_DOWNLOAD_THEMES" = "true" ]; then
        log_info "Downloading frontend themes..."

        # Download Forty theme
        log_info "Downloading Forty theme..."
        mkdir -p "${WEB_DIR}/static/public"
        cd "${WEB_DIR}/static/public"
        wget -q "$FORTY_THEME_URL" -O forty.zip || log_warning "Failed to download Forty theme"
        if [ -f forty.zip ]; then
            unzip -q forty.zip
            rm forty.zip
            log_success "Forty theme downloaded"
        fi

        # Download AdminLTE theme
        log_info "Downloading AdminLTE theme..."
        mkdir -p "${WEB_DIR}/static/admin"
        cd "${WEB_DIR}/static/admin"
        wget -q "$ADMINLTE_THEME_URL" -O adminlte.zip || log_warning "Failed to download AdminLTE theme"
        if [ -f adminlte.zip ]; then
            unzip -q adminlte.zip
            rm adminlte.zip
            log_success "AdminLTE theme downloaded"
        fi
    fi
}

create_systemd_service() {
    if [ "$SYSTEMD_ENABLED" = "true" ]; then
        log_info "Creating systemd service..."

        cat > "/etc/systemd/system/${SYSTEMD_SERVICE_NAME}.service" <<EOF
[Unit]
Description=HookProbe Django Web Application
After=network.target postgresql.service redis.service
Wants=postgresql.service redis.service

[Service]
Type=notify
User=root
Group=root
WorkingDirectory=${WEB_DIR}
Environment="PATH=${VENV_DIR}/bin"
EnvironmentFile=${WEB_DIR}/.env
ExecStart=${VENV_DIR}/bin/gunicorn \\
    --bind ${WEBSERVER_HOST}:${WEBSERVER_PORT} \\
    --workers ${WEBSERVER_WORKERS} \\
    --worker-class sync \\
    --timeout ${WEBSERVER_TIMEOUT} \\
    --access-logfile ${LOG_DIR}/gunicorn-access.log \\
    --error-logfile ${LOG_DIR}/gunicorn-error.log \\
    --log-level info \\
    hookprobe.wsgi:application
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        systemctl enable "${SYSTEMD_SERVICE_NAME}"

        log_success "Systemd service created"
    fi
}

configure_nginx() {
    if [ "$NGINX_ENABLED" = "true" ]; then
        log_info "Configuring Nginx..."

        cat > "/etc/nginx/conf.d/hookprobe-webserver.conf" <<EOF
server {
    listen ${NGINX_PORT};
    server_name _;
    client_max_body_size 100M;

    access_log ${LOG_DIR}/nginx-access.log;
    error_log ${LOG_DIR}/nginx-error.log;

    location /static/ {
        alias ${STATIC_DIR}/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    location /media/ {
        alias ${MEDIA_DIR}/;
        expires 30d;
    }

    location / {
        proxy_pass http://${WEBSERVER_HOST}:${WEBSERVER_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
EOF

        # Test nginx configuration
        nginx -t || log_warning "Nginx configuration test failed"

        systemctl enable nginx
        systemctl restart nginx || log_warning "Failed to restart Nginx"

        log_success "Nginx configured"
    fi
}

create_superuser_prompt() {
    log_info "Creating Django superuser..."

    source "${VENV_DIR}/bin/activate"
    cd "${WEB_DIR}"

    echo ""
    echo "================================================"
    echo "Create Django Admin Superuser"
    echo "================================================"
    echo ""
    python manage.py createsuperuser || log_warning "Superuser creation skipped or failed"
}

start_services() {
    log_info "Starting services..."

    if [ "$SYSTEMD_ENABLED" = "true" ]; then
        systemctl start "${SYSTEMD_SERVICE_NAME}"
        log_success "Web server started"
    fi

    if [ "$NGINX_ENABLED" = "true" ]; then
        systemctl restart nginx
        log_success "Nginx restarted"
    fi
}

show_completion_message() {
    cat <<EOF

${GREEN}========================================
HookProbe Web Server Installation Complete!
========================================${NC}

Deployment Type: ${DEPLOYMENT_TYPE}

${BLUE}Services:${NC}
  - Django Web Server: http://<your-ip>:${WEBSERVER_PORT}
  - Nginx (if enabled): http://<your-ip>:${NGINX_PORT}

${BLUE}Access Points:${NC}
  - Public Site: http://<your-ip>/
  - Admin Interface: http://<your-ip>/admin/
  - Dashboard: http://<your-ip>/dashboard/
  - Device Management: http://<your-ip>/devices/
  - Security: http://<your-ip>/security/
  - API: http://<your-ip>/api/v1/

${BLUE}Service Management:${NC}
  - Start: systemctl start ${SYSTEMD_SERVICE_NAME}
  - Stop: systemctl stop ${SYSTEMD_SERVICE_NAME}
  - Status: systemctl status ${SYSTEMD_SERVICE_NAME}
  - Logs: journalctl -u ${SYSTEMD_SERVICE_NAME} -f

${BLUE}Configuration:${NC}
  - Web Directory: ${WEB_DIR}
  - Environment File: ${WEB_DIR}/.env
  - Log Directory: ${LOG_DIR}

${BLUE}Next Steps:${NC}
  1. Customize frontend templates in ${WEB_DIR}/templates/
  2. Configure email settings in ${WEB_DIR}/.env
  3. Set up SSL certificate (if needed)
  4. Review and customize static content

${YELLOW}Important:${NC}
  - Change the Django secret key in ${WEB_DIR}/.env
  - Update ALLOWED_HOSTS for production
  - Configure firewall rules to allow HTTP/HTTPS traffic

For more information, see: ${WEB_DIR}/README.md

${GREEN}========================================${NC}

EOF
}

# ============================================================================
# Main Installation
# ============================================================================

main() {
    echo ""
    echo "========================================"
    echo "HookProbe Web Server Installation"
    echo "========================================"
    echo ""

    # Check if running as root
    check_root

    # Load configuration
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    else
        log_error "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi

    # Override deployment type from command line if provided
    if [ $# -gt 0 ]; then
        DEPLOYMENT_TYPE="$1"
    fi

    # Validate configuration
    validate_config || exit 1

    # Show configuration
    show_config

    # Confirm installation
    echo ""
    read -p "Do you want to proceed with the installation? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy]es$ ]]; then
        log_info "Installation cancelled"
        exit 0
    fi

    # Run installation steps
    check_prerequisites
    install_system_dependencies
    create_directories
    copy_web_application
    create_virtualenv
    install_python_dependencies
    create_env_file
    download_frontend_themes
    initialize_database
    load_seed_data
    collect_static_files
    create_systemd_service
    configure_nginx
    create_superuser_prompt
    start_services

    # Show completion message
    show_completion_message
}

# Run main function
main "$@"
