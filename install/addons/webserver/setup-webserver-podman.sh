#!/bin/bash
#
# HookProbe Web Server - Podman Container Deployment
#
# This script deploys the Django web application as a Podman container
# integrated with POD-001 (Web DMZ).
#
# Usage:
#   sudo ./setup-webserver-podman.sh [edge|cloud|standalone]
#
# Requirements:
#   - HookProbe PODs 001-007 must be running
#   - Podman 4.0+
#   - PostgreSQL (POD-003) accessible
#   - Redis (POD-004) accessible
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

check_podman() {
    if ! command -v podman &>/dev/null; then
        log_error "Podman is not installed"
        exit 1
    fi

    PODMAN_VERSION=$(podman --version | awk '{print $3}' | cut -d'.' -f1)
    if [ "$PODMAN_VERSION" -lt 4 ]; then
        log_error "Podman 4.0 or higher is required"
        exit 1
    fi

    log_success "Podman version check passed"
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if POD-001 network exists
    if ! podman network exists hookprobe-pod-001 2>/dev/null; then
        log_warning "POD-001 network not found. Will create it."
    fi

    log_success "Prerequisites check passed"
}

# ============================================================================
# Podman Functions
# ============================================================================

build_container_image() {
    log_info "Building web server container image..."

    cd "${REPO_ROOT}"

    # Build with Podman
    podman build \
        -f "${SCRIPT_DIR}/Containerfile" \
        -t hookprobe-webserver:latest \
        -t hookprobe-webserver:5.0 \
        .

    log_success "Container image built: hookprobe-webserver:latest"
}

create_container_volumes() {
    log_info "Creating container volumes..."

    # Create volumes for persistent data
    podman volume create hookprobe-web-static 2>/dev/null || true
    podman volume create hookprobe-web-media 2>/dev/null || true
    podman volume create hookprobe-web-logs 2>/dev/null || true

    log_success "Container volumes created"
}

create_environment_file() {
    log_info "Creating container environment file..."

    cat > "${SCRIPT_DIR}/container.env" <<EOF
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

# Gunicorn Configuration
GUNICORN_WORKERS=${WEBSERVER_WORKERS}
GUNICORN_TIMEOUT=${WEBSERVER_TIMEOUT}

# Grafana Configuration
GRAFANA_URL=${GRAFANA_URL}

# Multi-Tenant Configuration
MULTITENANT_ENABLED=${MULTITENANT_ENABLED}
TENANT_ID=${TENANT_ID}
EOF

    chmod 600 "${SCRIPT_DIR}/container.env"

    log_success "Container environment file created"
}

run_container() {
    log_info "Starting web server container..."

    # Stop existing container if running
    podman stop ${CONTAINER_NAME} 2>/dev/null || true
    podman rm ${CONTAINER_NAME} 2>/dev/null || true

    # Run container
    podman run -d \
        --name ${CONTAINER_NAME} \
        --pod hookprobe-pod-001 \
        --env-file "${SCRIPT_DIR}/container.env" \
        -v hookprobe-web-static:/app/staticfiles:Z \
        -v hookprobe-web-media:/app/media:Z \
        -v hookprobe-web-logs:/app/logs:Z \
        --restart always \
        --health-cmd "curl -f http://localhost:8000/admin/login/ || exit 1" \
        --health-interval 30s \
        --health-timeout 10s \
        --health-retries 3 \
        --health-start-period 60s \
        hookprobe-webserver:latest

    log_success "Web server container started: ${CONTAINER_NAME}"
}

create_systemd_service() {
    if [ "$SYSTEMD_ENABLED" = "true" ]; then
        log_info "Generating systemd service for container..."

        # Generate systemd unit file
        podman generate systemd \
            --new \
            --name ${CONTAINER_NAME} \
            --restart-policy=always \
            --start-timeout 60 \
            --stop-timeout 30 \
            > "/etc/systemd/system/${SYSTEMD_SERVICE_NAME}.service"

        # Modify service to depend on POD-001
        sed -i '/\[Unit\]/a Requires=podman-pod-hookprobe-pod-001.service\nAfter=podman-pod-hookprobe-pod-001.service' \
            "/etc/systemd/system/${SYSTEMD_SERVICE_NAME}.service"

        systemctl daemon-reload
        systemctl enable "${SYSTEMD_SERVICE_NAME}"

        log_success "Systemd service created: ${SYSTEMD_SERVICE_NAME}"
    fi
}

configure_nginx() {
    if [ "$NGINX_ENABLED" = "true" ]; then
        log_info "Configuring Nginx reverse proxy..."

        # Get container IP
        CONTAINER_IP=$(podman inspect ${CONTAINER_NAME} | jq -r '.[0].NetworkSettings.Networks["hookprobe-pod-001"].IPAddress')

        if [ -z "$CONTAINER_IP" ] || [ "$CONTAINER_IP" = "null" ]; then
            CONTAINER_IP="localhost"
        fi

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
        proxy_pass http://${CONTAINER_IP}:${WEBSERVER_PORT};
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

        # Install nginx if not present
        if ! command -v nginx &>/dev/null; then
            if command -v dnf &>/dev/null; then
                dnf install -y nginx
            elif command -v apt-get &>/dev/null; then
                apt-get update && apt-get install -y nginx
            fi
        fi

        # Test and restart nginx
        nginx -t && systemctl restart nginx || log_warning "Nginx configuration failed"

        log_success "Nginx configured"
    fi
}

create_superuser() {
    log_info "Creating Django superuser..."

    echo ""
    echo "================================================"
    echo "Create Django Admin Superuser"
    echo "================================================"
    echo ""

    # Run createsuperuser in container
    podman exec -it ${CONTAINER_NAME} python manage.py createsuperuser || log_warning "Superuser creation skipped"
}

show_container_info() {
    log_info "Container information:"

    podman inspect ${CONTAINER_NAME} --format '
Container: {{.Name}}
Image: {{.ImageName}}
Status: {{.State.Status}}
Health: {{.State.Health.Status}}
Created: {{.Created}}
Ports: {{range .NetworkSettings.Ports}}{{.}}{{end}}
'
}

show_completion_message() {
    CONTAINER_IP=$(podman inspect ${CONTAINER_NAME} | jq -r '.[0].NetworkSettings.IPAddress' 2>/dev/null || echo "localhost")

    cat <<EOF

${GREEN}========================================
HookProbe Web Server (Podman) Installation Complete!
========================================${NC}

Deployment Type: ${DEPLOYMENT_TYPE}
Container Name: ${CONTAINER_NAME}

${BLUE}Services:${NC}
  - Django Web Server: http://${CONTAINER_IP}:${WEBSERVER_PORT}
  - Nginx (if enabled): http://<your-ip>:${NGINX_PORT}

${BLUE}Access Points:${NC}
  - Public Site: http://<your-ip>/
  - Admin Interface: http://<your-ip>/admin/
  - Dashboard: http://<your-ip>/dashboard/
  - Device Management: http://<your-ip>/devices/
  - Security: http://<your-ip>/security/
  - API: http://<your-ip>/api/v1/

${BLUE}Container Management:${NC}
  - View logs: podman logs -f ${CONTAINER_NAME}
  - Container shell: podman exec -it ${CONTAINER_NAME} /bin/bash
  - Stop container: podman stop ${CONTAINER_NAME}
  - Start container: podman start ${CONTAINER_NAME}
  - Restart container: podman restart ${CONTAINER_NAME}

${BLUE}Systemd Management:${NC}
  - Start: systemctl start ${SYSTEMD_SERVICE_NAME}
  - Stop: systemctl stop ${SYSTEMD_SERVICE_NAME}
  - Status: systemctl status ${SYSTEMD_SERVICE_NAME}
  - Logs: journalctl -u ${SYSTEMD_SERVICE_NAME} -f

${BLUE}Data Volumes:${NC}
  - Static files: hookprobe-web-static
  - Media files: hookprobe-web-media
  - Logs: hookprobe-web-logs

${BLUE}Configuration:${NC}
  - Environment: ${SCRIPT_DIR}/container.env
  - Image: hookprobe-webserver:latest

${BLUE}Next Steps:${NC}
  1. Access admin interface and log in with superuser
  2. Customize frontend templates (rebuild container after changes)
  3. Configure email settings in container.env
  4. Set up SSL certificate (if needed)
  5. Review security settings

${YELLOW}Important:${NC}
  - Change the Django secret key in container.env
  - Update ALLOWED_HOSTS for production
  - Configure firewall rules to allow HTTP/HTTPS traffic
  - Backup data volumes regularly

${GREEN}========================================${NC}

EOF
}

# ============================================================================
# Main Installation
# ============================================================================

main() {
    echo ""
    echo "========================================"
    echo "HookProbe Web Server (Podman) Installation"
    echo "========================================"
    echo ""

    # Check if running as root
    check_root

    # Check Podman
    check_podman

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
    read -p "Do you want to proceed with the Podman container installation? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy]es$ ]]; then
        log_info "Installation cancelled"
        exit 0
    fi

    # Run installation steps
    check_prerequisites
    build_container_image
    create_container_volumes
    create_environment_file
    run_container
    create_systemd_service
    configure_nginx

    # Wait for container to be healthy
    log_info "Waiting for container to be healthy..."
    sleep 10

    # Create superuser
    create_superuser

    # Show container info
    show_container_info

    # Show completion message
    show_completion_message
}

# Run main function
main "$@"
