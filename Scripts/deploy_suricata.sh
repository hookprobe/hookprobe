#!/bin/bash
#
# deploy_suricata.sh (v1.01)
#
# Deploys the Suricata Intrusion Detection System (IDS) to monitor the 
# Open vSwitch bridge (ovs-br0), inspecting the clear-text VXLAN traffic
# after it has been decrypted by the OVS IPsec tunnel.
#
# --- !! Configuration Required !! ---

# Safely exit if any command fails
set -e

# Suricata Settings
SURICATA_POD_NAME="suricata-ids-pod"
SURICATA_CONTAINER_NAME="suricata-ids"
SURICATA_MONITOR_INTERFACE="ovs-br0"
SURICATA_IMAGE="jasonish/suricata:latest"
SURICATA_NETWORK_NAME="autonomous-ovs-net" # Connects to the main app network
SURICATA_VOLUME="suricata-rules-volume"

echo "========================================================"
echo "    SURICATA IDS DEPLOYMENT STARTING                    "
echo "========================================================"

# --- 1. PRE-CHECKS ---
if ! command -v podman &> /dev/null; then
    echo "ERROR: Podman is not installed. Please run setup.sh first."
    exit 1
fi

# --- 2. SETUP DIRECTORIES AND VOLUMES ---
echo "1. Creating necessary volumes and directories..."
podman volume inspect "$SURICATA_VOLUME" &> /dev/null || podman volume create "$SURICATA_VOLUME"

# Create a minimal Suricata YAML config file for monitoring ovs-br0
SURICATA_CONFIG_PATH="/tmp/suricata_config.yaml"

cat << EOF > "$SURICATA_CONFIG_PATH"
# Minimal Suricata configuration focusing on interface and logging
default-log-dir: /var/log/suricata
pcap-log:
  enabled: yes

# Configure interface to monitor
af-packet:
  - interface: ${SURICATA_MONITOR_INTERFACE}
    threads: 1
    defrag: yes
    cluster-type: cluster_flow
    cluster-id: 99
    copy-mode: ips
    bpf-filter: ""

# Use bundled rules (can be customized later)
rule-files:
  - suricata.yaml
  - rules/local.rules
EOF

# --- 3. DEPLOY SURICATA POD ---
echo "2. Deploying Suricata Pod and Container..."

# Stop and remove existing pod/container for a clean start
podman pod exists "$SURICATA_POD_NAME" && podman pod rm -f "$SURICATA_POD_NAME"

# Create the pod, attaching it to the OVS network
podman pod create \
    --name "$SURICATA_POD_NAME" \
    --network "$SURICATA_NETWORK_NAME"

# Run the Suricata container
# We must use --privileged or NET_ADMIN/NET_RAW capabilities to allow sniffing on ovs-br0
podman run -d --restart always \
    --pod "$SURICATA_POD_NAME" \
    --name "$SURICATA_CONTAINER_NAME" \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --cap-add=SYS_NICE \
    --privileged \
    -v "$SURICATA_VOLUME:/var/lib/suricata" \
    -v "$SURICATA_CONFIG_PATH:/etc/suricata/suricata.yaml:ro" \
    "$SURICATA_IMAGE" \
    -i "$SURICATA_MONITOR_INTERFACE" \
    -c /etc/suricata/suricata.yaml
    
echo "--------------------------------------------------------"
echo "Suricata deployed successfully!"
echo "To check its status and logs:"
echo "podman logs -f $SURICATA_CONTAINER_NAME"
echo "--------------------------------------------------------"
