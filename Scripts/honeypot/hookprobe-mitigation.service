# ============================================================
# hookprobe-mitigation.service
# Systemd service unit for HookProbe Attack Mitigation
# ============================================================

[Unit]
Description=HookProbe Attack Mitigation Service
Documentation=https://github.com/hookprobe/hookprobe
After=network.target podman.service
Requires=podman.service

[Service]
Type=oneshot
User=root
Group=root

# Environment
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Execute mitigation script
ExecStart=/usr/local/bin/attack-mitigation-orchestrator.sh

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hookprobe-mitigation

# Security
PrivateTmp=yes
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false

# Resource limits
TimeoutSec=300
CPUQuota=50%
MemoryLimit=1G

[Install]
WantedBy=multi-user.target

# ============================================================
# hookprobe-mitigation.timer
# Systemd timer unit for periodic attack mitigation
# ============================================================

[Unit]
Description=HookProbe Attack Mitigation Timer
Documentation=https://github.com/hookprobe/hookprobe
Requires=hookprobe-mitigation.service

[Timer]
# Run every 30 seconds (matches Qsecbit check interval)
OnBootSec=1min
OnUnitActiveSec=30s

# Accuracy
AccuracySec=1s

# Persistence
Persistent=true

[Install]
WantedBy=timers.target

# ============================================================
# INSTALLATION INSTRUCTIONS
# ============================================================
#
# 1. Copy files to system directories:
#    sudo cp attack-mitigation-orchestrator.sh /usr/local/bin/
#    sudo chmod +x /usr/local/bin/attack-mitigation-orchestrator.sh
#    sudo cp mitigation-config.conf /etc/hookprobe/
#    sudo chmod 600 /etc/hookprobe/mitigation-config.conf
#
# 2. Install systemd units:
#    sudo cp hookprobe-mitigation.service /etc/systemd/system/
#    sudo cp hookprobe-mitigation.timer /etc/systemd/system/
#
# 3. Reload systemd:
#    sudo systemctl daemon-reload
#
# 4. Enable and start timer:
#    sudo systemctl enable hookprobe-mitigation.timer
#    sudo systemctl start hookprobe-mitigation.timer
#
# 5. Check status:
#    sudo systemctl status hookprobe-mitigation.timer
#    sudo systemctl status hookprobe-mitigation.service
#
# 6. View logs:
#    sudo journalctl -u hookprobe-mitigation.service -f
#
# ============================================================
