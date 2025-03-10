## Self-building < - > self-healing hookprobe pods for SOC-SIEM nerds

Below is an **example** Bash script that automates installation and configuration of a **HOOKPROBE xSOC** environment on Ubuntu, including:

- **Podman** for container management  
- **Open vSwitch (OVS)** for virtual switching  
- **Free Range Routing (FRR)** for dynamic routing (including VRFs)  
- **VXLAN** interfaces for overlay networking  
- **Basic VRF setup** for network segmentation  
- **Syslog** configuration/monitoring hooks  

> **Note**:  
> 1. This script is a starting template—adapt paths, IP addresses, interface names, and other details as needed for your environment.  
> 2. This example focuses on installing and enabling each component. You will likely need to fine-tune configurations (e.g., FRR daemons, OVS bridging, VRF routing tables, syslog destinations, firewall rules, container networking, etc.) based on your specific use case and the architecture shown in your diagram.  
> 3. If you are running Ubuntu older than 22.04 or a different derivative, some package names/repositories may differ.

---

## Installation & Configuration Script

```bash
#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# xSOC AI Router - Example Automated Setup
# Includes: Podman, Open vSwitch, FRR, VXLAN, VRFs, Syslog hooks
# ------------------------------------------------------------------------------

set -e

# ------------------------------------------------------------------------------
# 0. Pre-Checks
# ------------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root or with sudo."
  exit 1
fi

# ------------------------------------------------------------------------------
# 1. System Update & Basic Tools
# ------------------------------------------------------------------------------
echo "[TASK] Updating system packages..."
apt-get update -y
apt-get upgrade -y

echo "[TASK] Installing base dependencies..."
apt-get install -y \
    curl wget git vim nano lsb-release ca-certificates \
    net-tools iputils-ping software-properties-common \
    apt-transport-https gnupg2

# ------------------------------------------------------------------------------
# 2. Install Podman
#    (On Ubuntu 22.04+, Podman is in default repos; otherwise, add official repo.)
# ------------------------------------------------------------------------------
echo "[TASK] Installing Podman..."
apt-get install -y podman

# Optionally verify Podman:
echo "[INFO] Podman version:"
podman --version

# ------------------------------------------------------------------------------
# 3. Install Open vSwitch
# ------------------------------------------------------------------------------
echo "[TASK] Installing Open vSwitch..."
apt-get install -y openvswitch-switch

# Enable and start OVS:
systemctl enable openvswitch-switch
systemctl start openvswitch-switch

# Optionally show OVS version:
echo "[INFO] OVS version:"
ovs-vsctl --version

# ------------------------------------------------------------------------------
# 4. Install and Configure FRR (Free Range Routing)
# ------------------------------------------------------------------------------
echo "[TASK] Installing FRR..."

# On Ubuntu 22.04, FRR packages are available in main repos:
apt-get install -y frr frr-pythontools

# Alternatively, for the latest FRR version, you could do:
# add-apt-repository ppa:frr/frr -y
# apt-get update -y
# apt-get install -y frr frr-pythontools

# Enable desired FRR daemons (zebra, bgpd, ospfd, etc.) in /etc/frr/daemons
# For VRF and advanced routing, you need at least 'zebra' running:
sed -i 's/^zebra=no/zebra=yes/' /etc/frr/daemons
sed -i 's/^bgpd=no/bgpd=yes/' /etc/frr/daemons
sed -i 's/^ospfd=no/ospfd=yes/' /etc/frr/daemons
# etc. for other daemons as needed

# Enable FRR at boot and start services:
systemctl enable frr
systemctl start frr

# ------------------------------------------------------------------------------
# 5. Basic VRF Setup
#    VRFs allow for separate routing tables per interface or container network
# ------------------------------------------------------------------------------
echo "[TASK] Setting up basic VRF..."

# Example: create two VRFs: vrf-blue and vrf-red
# Adjust to your own naming and environment needs
ip link add vrf-blue type vrf table 10
ip link add vrf-red type vrf table 20

# Bring them up
ip link set dev vrf-blue up
ip link set dev vrf-red up

# Bind an interface to vrf-blue (example: ens33). Change to your real interface!
# ip link set dev ens33 master vrf-blue

# ------------------------------------------------------------------------------
# 6. VXLAN Configuration (example)
#    Create a VXLAN interface for overlay networks
# ------------------------------------------------------------------------------
echo "[TASK] Creating VXLAN interface..."

# Example: create vxlan100 with a destination port 4789
ip link add vxlan100 type vxlan id 100 dev ens33 dstport 4789

# Move vxlan100 into vrf-blue (optional):
# ip link set vxlan100 master vrf-blue

# Bring it up:
ip link set vxlan100 up

# ------------------------------------------------------------------------------
# 7. Open vSwitch Bridge Configuration (example)
# ------------------------------------------------------------------------------
echo "[TASK] Configuring OVS bridge..."

# Create a new OVS bridge (e.g., br-external)
ovs-vsctl add-br br-external

# Attach a physical NIC (ens33) to br-external. Change to your real NIC.
ovs-vsctl add-port br-external ens33

# If you want a VXLAN port in OVS (instead of kernel ip link):
# ovs-vsctl add-port br-external vxlan100 -- set interface vxlan100 type=vxlan options:key=100 options:remote_ip=10.0.0.2

# ------------------------------------------------------------------------------
# 8. Basic Syslog Configuration
# ------------------------------------------------------------------------------
# FRR typically logs to syslog. You can also configure containers to log to syslog.
# We'll just ensure rsyslog is installed and running.
# ------------------------------------------------------------------------------
echo "[TASK] Installing rsyslog for central logging..."
apt-get install -y rsyslog

# Optionally configure FRR logging to syslog by editing /etc/frr/frr.conf
# e.g., adding lines like:
#   log syslog
#   log facility local0
#   service integrated-vtysh-config
#
# Then ensure your /etc/rsyslog.d/ setup can capture local0.* logs to a file
# or forward them to a remote syslog server.

systemctl enable rsyslog
systemctl restart rsyslog

# ------------------------------------------------------------------------------
# 9. (Optional) Podman Networking Example
# ------------------------------------------------------------------------------
# This shows how you might create a Podman network that uses OVS or a VRF.
# This is just a placeholder example—adjust for your environment.
# ------------------------------------------------------------------------------
echo "[TASK] Creating a sample Podman network..."

# By default, Podman can create CNI-based networks. For advanced OVS bridging,
# you can create a custom CNI config. For a simple example:
podman network create --driver bridge --subnet 10.88.0.0/16 xsoc-net

# Optionally run a test container:
# podman run -d --name test-ctr --network xsoc-net nginx:alpine

# ------------------------------------------------------------------------------
# 10. (Optional) IDS/IPS, Firewall, Additional Tools
# ------------------------------------------------------------------------------
# For an IDS/IPS like Suricata or Snort, you would install them similarly:
# apt-get install -y suricata
# systemctl enable suricata
# systemctl start suricata
#
# For a firewall, you might configure ufw, iptables, or nftables here.
# For example:
# ufw allow ssh
# ufw enable
#
# Adjust as needed for your xSOC environment.
# ------------------------------------------------------------------------------

echo "---------------------------------------------------------"
echo "[INFO] Base setup complete."
echo "Please review configurations for FRR (/etc/frr/), OVS, VRFs, and Podman."
echo "Adjust interface names, IP addresses, and routing per your network plan."
echo "---------------------------------------------------------"
```

---

### Usage

1. Make the script executable:
   ```bash
   chmod +x xsoc_install.sh
   ```

2. Run it as `root` or with `sudo`:
   ```bash
   sudo ./xsoc_install.sh
   ```

3. Adjust configurations:
   - **FRR**: `/etc/frr/daemons` and `/etc/frr/frr.conf`  
   - **OVS**: Use `ovs-vsctl` commands to adjust bridging, VLANs, VXLANs.  
   - **VRF**: Adapt VRF names, routing tables, and interface bindings to your environment.  
   - **Syslog**: Edit `/etc/rsyslog.d/` or `/etc/rsyslog.conf` to send logs to a central location or to store them in a dedicated log file.  
   - **Podman**: Add containers, networks, or volumes as needed.  

4. Reboot if necessary, or restart services individually:
   ```bash
   systemctl restart openvswitch-switch
   systemctl restart frr
   systemctl restart rsyslog
   ```
   and so on.

---

## Next Steps / Customization

- **FRR**: Depending on your routing needs (e.g., BGP, OSPF, OSPFv3, etc.), enable/disable additional daemons in `/etc/frr/daemons` and configure them in `/etc/frr/frr.conf`.  
- **Multiple VRFs**: If you need multiple VRFs (for multiple segments), replicate the VRF creation lines, assign them to different routing tables, and map your interfaces accordingly.  
- **VXLAN Tunnels**: For multi-host overlays, set up remote IP addresses or multi-point VXLAN with a controller.  
- **Containers**: Create container images or pull them from a registry. Each “Pod” or “App” from your xSOC architecture can be a container or set of containers.  
- **Monitoring**: Integrate a monitoring stack (e.g., Prometheus, Grafana) or a SIEM solution if your architecture calls for it.  
- **Firewall/IDS**: Insert firewall rules via `iptables`/`nftables` or install Suricata/Snort to create an IDS/IPS pipeline.  

This skeleton script should help you **automate** the initial deployment of the key components (Podman, OVS, FRR, VRFs, VXLAN, and syslog). Tailor it further to match all the pods and services shown in your diagram (AI modules, advanced logging, additional container pods, etc.).

## Next Steps / Low Level Design

Please come back and check the updates, here for the long run.

[![hookprobe budget](images/xSOC-HLD-v1.2.png)](/Documents/SecurityMitigationPlan.md)
