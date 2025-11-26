# Podman Configuration for POD-009

## Why Podman?

HookProbe uses **Podman** instead of Docker for enhanced security and flexibility:

### Security Advantages
1. **Rootless Containers**: Run containers without root privileges
2. **Daemonless**: No central daemon with root access
3. **SELinux Integration**: Better security context isolation
4. **User Namespaces**: Improved container isolation
5. **No Socket Exposure**: Eliminates daemon attack surface

### Technical Benefits
1. **OCI Compliant**: Compatible with Docker images
2. **Drop-in Replacement**: Uses same CLI syntax as Docker
3. **Pod Support**: Native Kubernetes-style pods
4. **Systemd Integration**: Native systemd support for containers
5. **No Licensing Concerns**: Fully open-source (Apache 2.0)

## Installation

### RHEL/CentOS/Fedora
```bash
sudo dnf install podman podman-compose
```

### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install podman podman-compose
```

### Verify Installation
```bash
podman --version
podman-compose --version
```

## Rootless Mode (Recommended)

### Enable Rootless Podman
```bash
# Check if rootless mode is available
podman system info | grep -i rootless

# Enable lingering (allows containers to run when logged out)
loginctl enable-linger $USER

# Configure subuid/subgid ranges (if not already set)
sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER

# Reload user session
podman system migrate
```

### Benefits of Rootless Mode
- Containers run as your user (no root required)
- Enhanced security isolation
- Prevents privilege escalation attacks
- Ideal for multi-tenant environments

## Using podman-compose with POD-009

### Deploy POD-009
```bash
cd /home/user/hookprobe/infrastructure/pod-009-email

# Deploy all containers
podman-compose up -d

# Verify deployment
podman-compose ps

# Check logs
podman-compose logs -f
```

### Container Management
```bash
# List running containers
podman ps

# List all containers
podman ps -a

# Stop containers
podman-compose down

# Restart specific container
podman-compose restart dmz-mail-gateway

# Remove containers and volumes
podman-compose down -v
```

### Network Management
```bash
# List networks
podman network ls

# Inspect network
podman network inspect hookprobe-dmz

# Remove network
podman network rm hookprobe-dmz
```

### Volume Management
```bash
# List volumes
podman volume ls

# Inspect volume
podman volume inspect hookprobe-dmz-mail-queue

# Prune unused volumes
podman volume prune
```

## Differences from Docker

### Command Equivalents
| Docker | Podman |
|--------|--------|
| `docker run` | `podman run` |
| `docker ps` | `podman ps` |
| `docker exec` | `podman exec` |
| `docker logs` | `podman logs` |
| `docker-compose up` | `podman-compose up` |
| `docker network ls` | `podman network ls` |
| `docker volume ls` | `podman volume ls` |

### Behavioral Differences
1. **No Daemon**: Podman doesn't use a daemon
2. **Rootless by Default**: Containers run as your user
3. **Pod Support**: Can group containers into pods
4. **Systemd Units**: Can generate systemd service files

## Systemd Integration (Production)

### Generate Systemd Units
```bash
# Generate systemd unit for a container
podman generate systemd --new --name hookprobe-dmz-mail-gateway > /etc/systemd/system/hookprobe-mail-gateway.service

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable hookprobe-mail-gateway
sudo systemctl start hookprobe-mail-gateway

# Check status
sudo systemctl status hookprobe-mail-gateway
```

### Auto-start on Boot
```bash
# Enable lingering (rootless containers survive logout)
loginctl enable-linger $USER

# Containers will auto-restart via systemd
```

## Troubleshooting

### Port Binding Issues (Rootless)
**Problem**: Cannot bind to ports < 1024 as non-root

**Solution 1**: Use higher ports and port forwarding
```bash
# Firewall rule to forward port 25 → 1025
sudo iptables -t nat -A PREROUTING -p tcp --dport 25 -j REDIRECT --to-port 1025
```

**Solution 2**: Enable unprivileged port binding
```bash
# Allow binding to port 25 as non-root
echo "net.ipv4.ip_unprivileged_port_start=25" | sudo tee /etc/sysctl.d/99-podman.conf
sudo sysctl --system
```

**Solution 3**: Use `podman-machine` (macOS/Windows)
```bash
podman machine init
podman machine start
```

### Network Connectivity Issues
**Problem**: Containers can't reach each other

**Solution**: Ensure containers are on same network
```bash
# Check container networks
podman inspect hookprobe-dmz-mail-gateway | grep -A5 Networks

# Reconnect to network if needed
podman network connect hookprobe-dmz hookprobe-dmz-mail-gateway
```

### SELinux Denials
**Problem**: SELinux blocking container operations

**Solution 1**: Check audit logs
```bash
sudo ausearch -m avc -ts recent
```

**Solution 2**: Adjust SELinux context
```bash
# Set correct SELinux context on volumes
chcon -Rt svirt_sandbox_file_t /path/to/volume
```

**Solution 3**: Generate policy (last resort)
```bash
sudo ausearch -m avc -ts recent | audit2allow -M my-podman
sudo semodule -i my-podman.pp
```

### Permission Denied Errors
**Problem**: Cannot access volumes or files

**Solution**: Check file ownership
```bash
# Files should be owned by your user in rootless mode
podman unshare chown -R $(id -u):$(id -g) /path/to/volume
```

## Migration from Docker

### For Existing Docker Users
```bash
# Alias docker to podman (optional)
alias docker=podman
alias docker-compose=podman-compose

# Add to ~/.bashrc or ~/.zshrc for persistence
echo "alias docker=podman" >> ~/.bashrc
echo "alias docker-compose=podman-compose" >> ~/.bashrc
```

### Image Compatibility
Podman uses the same image format as Docker:
```bash
# Pull Docker images
podman pull docker.io/ubuntu/postfix:latest

# Images work identically
```

### Compose File Compatibility
`docker-compose.yml` works with `podman-compose` without changes:
```bash
# Same compose file works for both
podman-compose -f docker-compose.yml up -d
```

## Best Practices for POD-009

### 1. Use Rootless Mode
```bash
# Run as your user (not root)
podman-compose up -d
```

### 2. Enable Auto-restart
```yaml
# In docker-compose.yml
services:
  dmz-mail-gateway:
    restart: unless-stopped  # or always
```

### 3. Resource Limits
```yaml
# Prevent resource exhaustion
services:
  dmz-mail-gateway:
    cpus: '2'
    mem_limit: 2g
    mem_reservation: 1g
```

### 4. Health Checks
```yaml
# Monitor container health
services:
  dmz-mail-gateway:
    healthcheck:
      test: ["CMD", "postfix", "status"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### 5. Logging Configuration
```bash
# Configure log driver
podman run --log-driver=journald \
           --log-opt tag="hookprobe-mail" \
           hookprobe-dmz-mail-gateway

# View logs via journald
journalctl CONTAINER_NAME=hookprobe-dmz-mail-gateway
```

## Monitoring Podman Containers

### Health Checks
```bash
# Check container health
podman healthcheck run hookprobe-dmz-mail-gateway

# View health status
podman inspect hookprobe-dmz-mail-gateway | jq '.[0].State.Health'
```

### Resource Usage
```bash
# Real-time stats
podman stats

# Historical stats
podman stats --no-stream hookprobe-dmz-mail-gateway
```

### Logs
```bash
# Follow logs
podman logs -f hookprobe-dmz-mail-gateway

# Last 100 lines
podman logs --tail 100 hookprobe-dmz-mail-gateway

# Since timestamp
podman logs --since 2025-01-01T00:00:00 hookprobe-dmz-mail-gateway
```

## Security Hardening

### 1. Run as Non-Root User
```yaml
# In docker-compose.yml
services:
  dmz-mail-gateway:
    user: "1000:1000"  # Your UID:GID
```

### 2. Read-Only Root Filesystem
```yaml
services:
  dmz-mail-gateway:
    read_only: true
    tmpfs:
      - /tmp
      - /var/run
```

### 3. Drop Capabilities
```yaml
services:
  dmz-mail-gateway:
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETUID
      - SETGID
```

### 4. Security Options
```yaml
services:
  dmz-mail-gateway:
    security_opt:
      - no-new-privileges:true
      - seccomp=unconfined  # Adjust as needed
```

## Performance Tuning

### 1. Storage Driver
```bash
# Check current driver
podman info | grep graphDriverName

# Recommended: overlay2 or fuse-overlayfs (rootless)
```

### 2. Network Performance
```bash
# Use CNI plugins for better performance
sudo dnf install containernetworking-plugins
```

### 3. Resource Limits
```bash
# Set cgroup limits
podman run --memory=2g --cpus=2 hookprobe-dmz-mail-gateway
```

## References

- [Podman Official Documentation](https://docs.podman.io/)
- [Podman Compose](https://github.com/containers/podman-compose)
- [Rootless Containers](https://rootlesscontaine.rs/)
- [Migrating from Docker to Podman](https://docs.podman.io/en/latest/Tutorials.html)
- [Podman Desktop](https://podman-desktop.io/)
