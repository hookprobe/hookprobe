# Guardian VM Integration Plan

**Version**: 1.0
**Status**: Design Phase
**Target**: Guardian on Raspberry Pi 5 (8GB RAM)

---

## Overview

Enable Guardian users to optionally run lightweight VMs (Home Assistant, OpenMediaVault, TrueNAS) alongside Guardian's security stack, utilizing the spare RAM on RPi 5.

### Resource Budget (8GB RPi 5)

| Component | RAM | Disk |
|-----------|-----|------|
| Guardian Core + Containers | ~512MB | 2GB |
| Home Assistant VM | 2GB | 32GB |
| OpenMediaVault VM | 2GB | 32GB+ |
| System/Buffer | 1.5GB | - |
| **Available for additional VMs** | ~2GB | Variable |

---

## Technical Requirements

### KVM on Raspberry Pi 5

```bash
# Required packages
sudo apt install -y \
    qemu-system-arm \
    qemu-utils \
    libvirt-daemon-system \
    libvirt-clients \
    virtinst \
    bridge-utils \
    cloud-image-utils

# Add user to libvirt group
sudo usermod -aG libvirt,kvm $USER

# Verify KVM support
ls -la /dev/kvm
virsh list --all
```

### Supported VM Images (ARM64)

| Application | Image | Download Size | Notes |
|------------|-------|---------------|-------|
| Home Assistant | HAOS ARM64 | ~300MB | Official .qcow2 available |
| OpenMediaVault | Debian ARM64 | ~500MB | Install OMV on Debian |
| TrueNAS SCALE | ARM64 build | ~1GB | Community builds |
| Ubuntu Server | ARM64 Cloud | ~600MB | cloud-init ready |

---

## Implementation Phases

### Phase 1: Install Script Integration

**Location**: `products/guardian/scripts/setup.sh`

```bash
# Add to installation prompts (around line 4600)
install_vm_support() {
    echo ""
    echo "╔════════════════════════════════════════════════╗"
    echo "║     Optional: VM Support (QEMU/KVM)            ║"
    echo "╠════════════════════════════════════════════════╣"
    echo "║ Run VMs alongside Guardian:                    ║"
    echo "║  • Home Assistant                              ║"
    echo "║  • OpenMediaVault / TrueNAS                   ║"
    echo "║  • Other ARM64 VMs                            ║"
    echo "║                                                ║"
    echo "║ Requirements:                                  ║"
    echo "║  • RPi 5 with 8GB RAM recommended             ║"
    echo "║  • ~500MB additional disk space               ║"
    echo "╚════════════════════════════════════════════════╝"
    echo ""

    read -p "Install VM support? [y/N]: " INSTALL_VMS
    if [[ "$INSTALL_VMS" =~ ^[Yy]$ ]]; then
        echo "[*] Installing QEMU/KVM and libvirt..."
        apt-get install -y \
            qemu-system-arm \
            qemu-utils \
            libvirt-daemon-system \
            libvirt-clients \
            virtinst \
            cloud-image-utils

        # Add hookprobe user to libvirt group
        usermod -aG libvirt,kvm hookprobe 2>/dev/null || true

        # Configure libvirt to use Guardian's bridge
        configure_libvirt_bridge

        # Create VM storage directory
        mkdir -p /var/lib/hookprobe/vms/{images,templates}
        chown -R hookprobe:hookprobe /var/lib/hookprobe/vms

        # Install VM management service
        install_vm_management_service

        VM_SUPPORT_INSTALLED=true
        echo "[✓] VM support installed successfully"
    else
        VM_SUPPORT_INSTALLED=false
    fi
}

configure_libvirt_bridge() {
    # Create libvirt network definition using Guardian's br0
    cat > /tmp/guardian-network.xml << 'NETEOF'
<network>
  <name>guardian</name>
  <forward mode="bridge"/>
  <bridge name="br0"/>
</network>
NETEOF

    virsh net-define /tmp/guardian-network.xml
    virsh net-start guardian
    virsh net-autostart guardian
    rm /tmp/guardian-network.xml
}

install_vm_management_service() {
    # Systemd service for VM auto-start
    cat > /etc/systemd/system/guardian-vms.service << 'SVCEOF'
[Unit]
Description=HookProbe Guardian VM Manager
After=network-online.target libvirtd.service
Wants=libvirtd.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/hookprobe/guardian/scripts/vm-autostart.sh start
ExecStop=/opt/hookprobe/guardian/scripts/vm-autostart.sh stop

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable guardian-vms.service
}
```

### Phase 2: Flask Web Module

**Location**: `products/guardian/web/modules/vms/`

#### `__init__.py`
```python
from flask import Blueprint

vms_bp = Blueprint('vms', __name__, template_folder='../../templates')

from . import views
```

#### `views.py`
```python
"""
VM Management Module - Control VMs from Guardian Dashboard
"""
import subprocess
import json
import xml.etree.ElementTree as ET
from flask import jsonify, request, render_template
from . import vms_bp


def _run_virsh(cmd):
    """Execute virsh command and return output."""
    try:
        result = subprocess.run(
            ['virsh'] + cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout.strip(), result.returncode == 0
    except Exception as e:
        return str(e), False


@vms_bp.route('/api/vms/status')
def vm_status():
    """Check if VM support is installed and libvirtd is running."""
    # Check if libvirtd is running
    output, success = _run_virsh(['list', '--all'])
    return jsonify({
        'installed': success,
        'libvirtd_running': success,
        'error': None if success else output
    })


@vms_bp.route('/api/vms/list')
def list_vms():
    """List all VMs with their status."""
    output, success = _run_virsh(['list', '--all', '--name'])
    if not success:
        return jsonify({'vms': [], 'error': output}), 500

    vms = []
    for name in output.splitlines():
        if name.strip():
            vm_info = get_vm_info(name.strip())
            vms.append(vm_info)

    return jsonify({'vms': vms})


def get_vm_info(name):
    """Get detailed info for a VM."""
    info = {'name': name, 'state': 'unknown', 'memory': 0, 'vcpus': 0, 'ip': None}

    # Get domain state
    output, success = _run_virsh(['domstate', name])
    if success:
        info['state'] = output.strip()

    # Get domain info (memory, vcpus)
    output, success = _run_virsh(['dominfo', name])
    if success:
        for line in output.splitlines():
            if 'Max memory:' in line:
                info['memory'] = int(line.split(':')[1].strip().split()[0]) // 1024  # MB
            elif 'CPU(s):' in line:
                info['vcpus'] = int(line.split(':')[1].strip())

    # Get IP address if running
    if info['state'] == 'running':
        output, success = _run_virsh(['domifaddr', name])
        if success and output:
            for line in output.splitlines():
                if 'ipv4' in line:
                    parts = line.split()
                    for part in parts:
                        if '.' in part and '/' in part:
                            info['ip'] = part.split('/')[0]
                            break

    return info


@vms_bp.route('/api/vms/<name>/start', methods=['POST'])
def start_vm(name):
    """Start a VM."""
    output, success = _run_virsh(['start', name])
    return jsonify({'success': success, 'message': output})


@vms_bp.route('/api/vms/<name>/stop', methods=['POST'])
def stop_vm(name):
    """Gracefully shutdown a VM."""
    output, success = _run_virsh(['shutdown', name])
    return jsonify({'success': success, 'message': output})


@vms_bp.route('/api/vms/<name>/force-stop', methods=['POST'])
def force_stop_vm(name):
    """Force stop a VM."""
    output, success = _run_virsh(['destroy', name])
    return jsonify({'success': success, 'message': output})


@vms_bp.route('/api/vms/<name>/console')
def get_console_info(name):
    """Get VNC/SPICE console connection info."""
    output, success = _run_virsh(['vncdisplay', name])
    if success and output.strip():
        port = int(output.strip().split(':')[1]) + 5900
        return jsonify({
            'type': 'vnc',
            'host': '127.0.0.1',
            'port': port,
            'websocket_url': f'/api/vms/{name}/websocket'
        })

    return jsonify({'type': None, 'error': 'No display configured'})


@vms_bp.route('/api/vms/templates')
def list_templates():
    """List available VM templates for quick deployment."""
    templates = [
        {
            'id': 'homeassistant',
            'name': 'Home Assistant',
            'description': 'Smart home automation platform',
            'icon': 'home',
            'memory': 2048,
            'disk': 32,
            'download_url': 'https://github.com/home-assistant/operating-system/releases',
            'image_type': 'qcow2'
        },
        {
            'id': 'openmediavault',
            'name': 'OpenMediaVault',
            'description': 'Network attached storage (NAS) solution',
            'icon': 'server',
            'memory': 2048,
            'disk': 32,
            'download_url': 'https://www.openmediavault.org/download.html',
            'image_type': 'iso',
            'base': 'debian'
        },
        {
            'id': 'ubuntu',
            'name': 'Ubuntu Server 24.04',
            'description': 'General purpose Linux server',
            'icon': 'terminal',
            'memory': 1024,
            'disk': 20,
            'download_url': 'https://cloud-images.ubuntu.com/noble/current/',
            'image_type': 'qcow2'
        }
    ]
    return jsonify({'templates': templates})


@vms_bp.route('/api/vms/create', methods=['POST'])
def create_vm():
    """Create a new VM from template or custom config."""
    data = request.get_json()

    name = data.get('name')
    template = data.get('template')
    memory = data.get('memory', 2048)  # MB
    vcpus = data.get('vcpus', 2)
    disk_path = data.get('disk_path')

    if not name or not disk_path:
        return jsonify({'success': False, 'error': 'Name and disk_path required'}), 400

    # Create VM with virt-install
    cmd = [
        'virt-install',
        '--name', name,
        '--memory', str(memory),
        '--vcpus', str(vcpus),
        '--disk', f'path={disk_path},format=qcow2',
        '--network', 'network=guardian',
        '--graphics', 'vnc,listen=127.0.0.1',
        '--noautoconsole',
        '--import',
        '--os-variant', 'linux2022'
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        success = result.returncode == 0
        return jsonify({
            'success': success,
            'message': result.stdout if success else result.stderr
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@vms_bp.route('/api/vms/<name>/delete', methods=['DELETE'])
def delete_vm(name):
    """Delete a VM (undefine and optionally remove disk)."""
    remove_disk = request.args.get('remove_disk', 'false').lower() == 'true'

    # First, make sure VM is stopped
    _run_virsh(['destroy', name])

    # Undefine the VM
    if remove_disk:
        output, success = _run_virsh(['undefine', name, '--remove-all-storage'])
    else:
        output, success = _run_virsh(['undefine', name])

    return jsonify({'success': success, 'message': output})
```

### Phase 3: Dashboard Integration

**Location**: `products/guardian/web/templates/core/dashboard.html`

Add VM tiles to the navigation section:

```html
<!-- VM Management Tile (only shown if VM support installed) -->
<div class="nav-tile" id="vm-tile" style="display: none;" onclick="navigateTo('vms')">
    <div class="nav-tile-header">
        <div class="nav-tile-icon" style="background: linear-gradient(135deg, #06b6d4, #0891b2);">
            <svg fill="currentColor" viewBox="0 0 24 24">
                <path d="M21 2H3c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h7v2H8v2h8v-2h-2v-2h7c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H3V4h18v12z"/>
            </svg>
        </div>
        <div class="nav-tile-info">
            <h4>Virtual Machines</h4>
            <p>Home Assistant, NAS, and more</p>
        </div>
    </div>
    <div class="nav-tile-footer">
        <span class="nav-tile-stat" id="vm-status">Loading...</span>
        <span class="nav-tile-arrow">Manage →</span>
    </div>
</div>

<script>
// Check if VM support is installed
async function checkVMSupport() {
    try {
        const response = await fetch('/api/vms/status');
        const data = await response.json();

        if (data.installed) {
            document.getElementById('vm-tile').style.display = 'block';

            // Get VM count
            const listResponse = await fetch('/api/vms/list');
            const listData = await listResponse.json();
            const running = listData.vms.filter(vm => vm.state === 'running').length;
            const total = listData.vms.length;

            document.getElementById('vm-status').innerHTML =
                `<strong>${running}</strong>/${total} running`;
        }
    } catch (e) {
        // VM support not installed, tile stays hidden
    }
}

// Check on page load
checkVMSupport();
</script>
```

### Phase 4: VM Management Page

**Location**: `products/guardian/web/templates/vms/index.html`

```html
<style>
.vm-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: var(--spacing-lg);
    margin-bottom: var(--spacing-xl);
}

.vm-card {
    background: var(--bg-card);
    border-radius: var(--radius-xl);
    padding: var(--spacing-lg);
    box-shadow: var(--shadow-md);
}

.vm-card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: var(--spacing-md);
}

.vm-status {
    display: inline-flex;
    align-items: center;
    gap: var(--spacing-xs);
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
}

.vm-status.running {
    background: rgba(16, 185, 129, 0.15);
    color: var(--hp-green);
}

.vm-status.stopped {
    background: rgba(107, 114, 128, 0.15);
    color: var(--text-secondary);
}

.vm-stats {
    display: flex;
    gap: var(--spacing-lg);
    margin: var(--spacing-md) 0;
}

.vm-stat {
    text-align: center;
}

.vm-stat-value {
    font-size: 1.25rem;
    font-weight: 700;
}

.vm-stat-label {
    font-size: 0.75rem;
    color: var(--text-secondary);
}

.vm-actions {
    display: flex;
    gap: var(--spacing-sm);
    margin-top: var(--spacing-md);
}

.vm-ip {
    font-family: monospace;
    background: var(--bg-light);
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 0.875rem;
}

/* Template cards */
.template-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    gap: var(--spacing-md);
}

.template-card {
    background: var(--bg-card);
    border: 2px solid var(--border-color);
    border-radius: var(--radius-lg);
    padding: var(--spacing-lg);
    cursor: pointer;
    transition: all var(--transition-fast);
}

.template-card:hover {
    border-color: var(--hp-primary);
    transform: translateY(-2px);
}
</style>

<div class="content-section">
    <div class="section-header">
        <h2>
            <svg width="24" height="24" fill="currentColor" viewBox="0 0 24 24">
                <path d="M21 2H3c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h7v2H8v2h8v-2h-2v-2h7c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H3V4h18v12z"/>
            </svg>
            Virtual Machines
        </h2>
        <button class="btn btn-primary" onclick="showCreateVMModal()">
            <svg width="16" height="16" fill="currentColor" viewBox="0 0 24 24">
                <path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/>
            </svg>
            Create VM
        </button>
    </div>

    <!-- Running VMs -->
    <div class="vm-grid" id="vm-list">
        <div class="loading-placeholder">Loading VMs...</div>
    </div>

    <!-- Quick Deploy Templates -->
    <h3 style="margin-top: var(--spacing-xl);">Quick Deploy Templates</h3>
    <div class="template-grid" id="template-list">
        <!-- Populated by JavaScript -->
    </div>
</div>

<script>
async function loadVMs() {
    const container = document.getElementById('vm-list');

    try {
        const response = await fetch('/api/vms/list');
        const data = await response.json();

        if (data.vms.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <p>No virtual machines configured.</p>
                    <p>Create one using the templates below or click "Create VM".</p>
                </div>
            `;
            return;
        }

        container.innerHTML = data.vms.map(vm => `
            <div class="vm-card">
                <div class="vm-card-header">
                    <h4>${vm.name}</h4>
                    <span class="vm-status ${vm.state === 'running' ? 'running' : 'stopped'}">
                        ${vm.state}
                    </span>
                </div>

                <div class="vm-stats">
                    <div class="vm-stat">
                        <div class="vm-stat-value">${vm.memory} MB</div>
                        <div class="vm-stat-label">Memory</div>
                    </div>
                    <div class="vm-stat">
                        <div class="vm-stat-value">${vm.vcpus}</div>
                        <div class="vm-stat-label">vCPUs</div>
                    </div>
                    ${vm.ip ? `
                    <div class="vm-stat">
                        <div class="vm-stat-value vm-ip">${vm.ip}</div>
                        <div class="vm-stat-label">IP Address</div>
                    </div>
                    ` : ''}
                </div>

                <div class="vm-actions">
                    ${vm.state === 'running' ? `
                        <button class="btn btn-sm btn-secondary" onclick="stopVM('${vm.name}')">Stop</button>
                        <button class="btn btn-sm btn-primary" onclick="openConsole('${vm.name}')">Console</button>
                        ${vm.ip ? `<a class="btn btn-sm btn-success" href="http://${vm.ip}" target="_blank">Open Web UI</a>` : ''}
                    ` : `
                        <button class="btn btn-sm btn-success" onclick="startVM('${vm.name}')">Start</button>
                        <button class="btn btn-sm btn-danger" onclick="deleteVM('${vm.name}')">Delete</button>
                    `}
                </div>
            </div>
        `).join('');
    } catch (e) {
        container.innerHTML = `<div class="error">Failed to load VMs: ${e.message}</div>`;
    }
}

async function loadTemplates() {
    const container = document.getElementById('template-list');

    try {
        const response = await fetch('/api/vms/templates');
        const data = await response.json();

        container.innerHTML = data.templates.map(t => `
            <div class="template-card" onclick="deployTemplate('${t.id}')">
                <h4>${t.name}</h4>
                <p>${t.description}</p>
                <small>RAM: ${t.memory}MB | Disk: ${t.disk}GB</small>
            </div>
        `).join('');
    } catch (e) {
        container.innerHTML = '<div class="error">Failed to load templates</div>';
    }
}

async function startVM(name) {
    const response = await fetch(`/api/vms/${name}/start`, { method: 'POST' });
    const data = await response.json();
    if (data.success) {
        loadVMs();
    } else {
        alert('Failed to start VM: ' + data.message);
    }
}

async function stopVM(name) {
    const response = await fetch(`/api/vms/${name}/stop`, { method: 'POST' });
    const data = await response.json();
    loadVMs();
}

async function deleteVM(name) {
    if (!confirm(`Delete VM "${name}"? This cannot be undone.`)) return;

    const response = await fetch(`/api/vms/${name}/delete?remove_disk=true`, { method: 'DELETE' });
    const data = await response.json();
    loadVMs();
}

function openConsole(name) {
    // Open noVNC console in new window
    window.open(`/vms/${name}/console`, '_blank', 'width=1024,height=768');
}

// Initialize
loadVMs();
loadTemplates();
setInterval(loadVMs, 10000); // Refresh every 10s
</script>
```

---

## Network Integration

### Bridge Configuration

VMs connect to Guardian's existing `br0` bridge:

```xml
<!-- /etc/libvirt/qemu/networks/guardian.xml -->
<network>
  <name>guardian</name>
  <forward mode="bridge"/>
  <bridge name="br0"/>
</network>
```

### IP Allocation

| Device | IP Address | Notes |
|--------|------------|-------|
| Guardian | 192.168.4.1 | Gateway, DHCP server |
| DHCP Pool | 192.168.4.2-30 | WiFi clients |
| Home Assistant | 192.168.4.50 | Static, reserved |
| OpenMediaVault | 192.168.4.51 | Static, reserved |
| TrueNAS | 192.168.4.52 | Static, reserved |
| Reserved VMs | 192.168.4.53-60 | Future VMs |

### dnsmasq Integration

Add to `/etc/dnsmasq.conf`:

```
# VM static reservations (added by setup.sh if VM support installed)
dhcp-host=52:54:00:00:04:50,homeassistant,192.168.4.50
dhcp-host=52:54:00:00:04:51,openmediavault,192.168.4.51
dhcp-host=52:54:00:00:04:52,truenas,192.168.4.52

# Local DNS for VMs
address=/homeassistant.guardian.local/192.168.4.50
address=/nas.guardian.local/192.168.4.51
```

---

## Security Considerations

### VM Isolation

1. **Network Segmentation**: VMs are on same bridge as clients but can be firewall-isolated
2. **Resource Limits**: Set CPU/memory cgroups to prevent VM from starving Guardian
3. **Storage Isolation**: VM disks in `/var/lib/hookprobe/vms/` with proper permissions

### iptables Rules

```bash
# Allow VM traffic to/from br0
iptables -A FORWARD -i br0 -o br0 -j ACCEPT

# Block VM access to Guardian management port (optional)
iptables -A INPUT -s 192.168.4.50/29 -p tcp --dport 8443 -j DROP
```

---

## User Experience Flow

### Installation

```
$ sudo ./install.sh --tier guardian

[Step 6/8] Optional Features
╔════════════════════════════════════════════════╗
║     Optional: VM Support (QEMU/KVM)            ║
╠════════════════════════════════════════════════╣
║ Run VMs alongside Guardian:                    ║
║  • Home Assistant (smart home)                 ║
║  • OpenMediaVault (NAS)                        ║
║  • Custom ARM64 VMs                            ║
╚════════════════════════════════════════════════╝

Install VM support? [y/N]: y

[*] Installing QEMU/KVM packages...
[*] Configuring libvirt bridge...
[*] Creating VM storage directory...
[✓] VM support installed

Would you like to deploy Home Assistant now? [y/N]: y
[*] Downloading Home Assistant OS (ARM64)...
[*] Creating VM 'homeassistant'...
[✓] Home Assistant deployed at http://192.168.4.50:8123
```

### Dashboard Access

1. User sees "Virtual Machines" tile on Guardian dashboard
2. Clicking shows running VMs with start/stop controls
3. "Open Web UI" button launches VM's web interface
4. Quick deploy templates for common appliances

---

## Implementation Checklist

- [ ] Phase 1: Install script integration
  - [ ] `install_vm_support()` function
  - [ ] `configure_libvirt_bridge()` function
  - [ ] Package installation
  - [ ] User prompts

- [ ] Phase 2: Flask module
  - [ ] `modules/vms/__init__.py`
  - [ ] `modules/vms/views.py`
  - [ ] Blueprint registration

- [ ] Phase 3: Dashboard integration
  - [ ] VM tile in navigation
  - [ ] Status indicator
  - [ ] VM management page template

- [ ] Phase 4: Templates & automation
  - [ ] Home Assistant template
  - [ ] OpenMediaVault template
  - [ ] Auto-download images
  - [ ] cloud-init integration

- [ ] Phase 5: Testing
  - [ ] Test on RPi 5 8GB
  - [ ] Resource usage monitoring
  - [ ] Network connectivity
  - [ ] Performance impact on Guardian

---

## References

- [KVM on Raspberry Pi 5](https://ostrich.kyiv.ua/en/2025/05/08/raspberry-pi-as-a-kvm-hypervisor/)
- [libvirt Documentation](https://libvirt.org/docs.html)
- [Home Assistant OS ARM64](https://www.home-assistant.io/installation/linux)
- [OpenMediaVault Installation](https://www.openmediavault.org/)
