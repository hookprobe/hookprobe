#!/bin/bash
#
# update.sh - HookProbe Auto-Update Script
# Version: 5.0
# License: AGPL-3.0 - see LICENSE file
#
# Pulls latest changes from GitHub and re-provisions safely
#

set -e
set -u

# ============================================================================
# CONSTANTS
# ============================================================================

readonly HOOKPROBE_BASE="/opt/hookprobe"
readonly GIT_REPO="https://github.com/hookprobe/hookprobe.git"
readonly GIT_BRANCH="${GIT_BRANCH:-main}"
readonly LOG_FILE="/var/log/hookprobe/update.log"
readonly BACKUP_DIR="/opt/hookprobe-backups"

# ============================================================================
# LOGGING
# ============================================================================

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $*" | tee -a "$LOG_FILE" >&2
}

# ============================================================================
# PRE-UPDATE CHECKS
# ============================================================================

check_prerequisites() {
    log "Checking prerequisites..."

    # Check if git is installed
    if ! command -v git >/dev/null 2>&1; then
        log_error "git is not installed"
        return 1
    fi

    # Check internet connectivity
    if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        log_error "No internet connectivity"
        return 1
    fi

    log "Prerequisites OK"
}

# ============================================================================
# BACKUP
# ============================================================================

create_backup() {
    log "Creating backup..."

    local backup_name="hookprobe-backup-$(date +%Y%m%d-%H%M%S)"
    local backup_path="$BACKUP_DIR/$backup_name"

    mkdir -p "$BACKUP_DIR"

    # Backup current installation
    if [ -d "$HOOKPROBE_BASE" ]; then
        cp -r "$HOOKPROBE_BASE" "$backup_path"
        log "Backup created: $backup_path"
    else
        log_error "HookProbe base directory not found: $HOOKPROBE_BASE"
        return 1
    fi

    # Backup configuration
    if [ -d "/etc/hookprobe" ]; then
        mkdir -p "$backup_path/etc"
        cp -r "/etc/hookprobe" "$backup_path/etc/"
    fi

    # Keep only last 5 backups
    local backup_count=$(ls -1 "$BACKUP_DIR" | wc -l)
    if [ "$backup_count" -gt 5 ]; then
        log "Removing old backups (keeping last 5)..."
        ls -1t "$BACKUP_DIR" | tail -n +6 | xargs -I {} rm -rf "$BACKUP_DIR/{}"
    fi
}

# ============================================================================
# UPDATE
# ============================================================================

fetch_updates() {
    log "Fetching updates from GitHub..."

    local repo_dir="$HOOKPROBE_BASE/repo"

    # Clone or pull repository
    if [ -d "$repo_dir/.git" ]; then
        log "Pulling latest changes..."
        cd "$repo_dir"
        git fetch origin "$GIT_BRANCH"

        # Check if there are updates
        local local_commit=$(git rev-parse HEAD)
        local remote_commit=$(git rev-parse "origin/$GIT_BRANCH")

        if [ "$local_commit" = "$remote_commit" ]; then
            log "Already up to date"
            return 0
        fi

        log "Updates available: $local_commit -> $remote_commit"
        git pull origin "$GIT_BRANCH"
    else
        log "Cloning repository..."
        mkdir -p "$repo_dir"
        git clone -b "$GIT_BRANCH" "$GIT_REPO" "$repo_dir"
    fi

    log "Updates fetched successfully"
}

apply_updates() {
    log "Applying updates..."

    local repo_dir="$HOOKPROBE_BASE/repo"

    if [ ! -d "$repo_dir" ]; then
        log_error "Repository directory not found"
        return 1
    fi

    # Copy updated files
    log "Copying updated scripts..."
    cp -r "$repo_dir/deploy/edge/"* "$HOOKPROBE_BASE/scripts/" 2>/dev/null || true
    cp -r "$repo_dir/core/qsecbit/"* "$HOOKPROBE_BASE/agent/" 2>/dev/null || true

    # Make scripts executable
    chmod +x "$HOOKPROBE_BASE"/scripts/*.sh 2>/dev/null || true
    chmod +x "$HOOKPROBE_BASE"/agent/*.py 2>/dev/null || true

    # Update systemd units
    log "Updating systemd units..."
    if [ -d "$repo_dir/deploy/edge/systemd" ]; then
        cp "$repo_dir/deploy/edge/systemd/"*.service /etc/systemd/system/
        cp "$repo_dir/deploy/edge/systemd/"*.timer /etc/systemd/system/
        systemctl daemon-reload
    fi

    log "Updates applied successfully"
}

# ============================================================================
# POST-UPDATE
# ============================================================================

restart_services() {
    log "Restarting services..."

    # Re-run provision
    log "Re-provisioning..."
    systemctl start hookprobe-provision.service

    # Wait for provision to complete
    local timeout=300
    local elapsed=0

    while systemctl is-active hookprobe-provision.service >/dev/null 2>&1; do
        if [ $elapsed -ge $timeout ]; then
            log_error "Provision timeout"
            return 1
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done

    # Check if provision succeeded
    if systemctl is-failed hookprobe-provision.service >/dev/null 2>&1; then
        log_error "Provision failed after update"
        return 1
    fi

    # Restart agent
    log "Restarting agent..."
    systemctl restart hookprobe-agent.service

    # Wait for agent to be ready
    sleep 10

    # Health check
    if curl -f http://localhost:8888/health >/dev/null 2>&1; then
        log "Agent health check passed"
    else
        log_error "Agent health check failed"
        return 1
    fi

    log "Services restarted successfully"
}

verify_update() {
    log "Verifying update..."

    local errors=0

    # Check services are running
    local services=(
        "hookprobe-agent.service"
    )

    for service in "${services[@]}"; do
        if ! systemctl is-active "$service" >/dev/null 2>&1; then
            log_error "Service not running: $service"
            ((errors++))
        fi
    done

    if [ $errors -eq 0 ]; then
        log "Update verification passed"
        return 0
    else
        log_error "Update verification failed with $errors error(s)"
        return 1
    fi
}

# ============================================================================
# ROLLBACK
# ============================================================================

rollback() {
    log_error "Update failed, rolling back..."

    # Find latest backup
    local latest_backup=$(ls -1t "$BACKUP_DIR" | head -n1)

    if [ -z "$latest_backup" ]; then
        log_error "No backup found for rollback"
        return 1
    fi

    log "Rolling back to: $latest_backup"

    # Stop services
    systemctl stop hookprobe-agent.service || true

    # Restore backup
    rm -rf "$HOOKPROBE_BASE"
    cp -r "$BACKUP_DIR/$latest_backup" "$HOOKPROBE_BASE"

    # Restart services
    systemctl start hookprobe-provision.service
    systemctl start hookprobe-agent.service

    log "Rollback completed"
}

# ============================================================================
# MAIN UPDATE
# ============================================================================

main() {
    log "========================================="
    log "HookProbe Auto-Update Started"
    log "========================================="

    # Ensure log directory exists
    mkdir -p "$(dirname "$LOG_FILE")"

    # Pre-update
    if ! check_prerequisites; then
        log_error "Pre-update checks failed"
        exit 1
    fi

    if ! create_backup; then
        log_error "Backup failed, aborting update"
        exit 1
    fi

    # Update
    if ! fetch_updates; then
        log_error "Failed to fetch updates"
        exit 1
    fi

    if ! apply_updates; then
        log_error "Failed to apply updates"
        rollback
        exit 1
    fi

    # Post-update
    if ! restart_services; then
        log_error "Failed to restart services"
        rollback
        exit 1
    fi

    if ! verify_update; then
        log_error "Update verification failed"
        rollback
        exit 1
    fi

    log "========================================="
    log "HookProbe Auto-Update Completed Successfully"
    log "========================================="
}

# Run main if executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main
fi
