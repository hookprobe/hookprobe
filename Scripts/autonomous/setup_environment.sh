#!/bin/bash
#
# Environment Setup Script for 'autonomous autonomous' ecosystem
# Target OS: RHEL/RedHat 10 (or compatible Fedora/CentOS Stream)
# Target Arch: x86_64
#
# This script prepares the host for containerized deployment:
# 1. Installs Podman, Python, Terraform, and Cloudflared.
# 2. Ensures VXLAN kernel module is loaded.
# 3. Creates a dedicated Podman network attached to the VXLAN gateway.
#
# --- Configuration ---

# Safely exit if any command fails
set -e

# Define required system packages for RHEL/Fedora
REQUIRED_PACKAGES=(
    git
    curl
    wget
    unzip
    podman
    python3
    python3-pip
    net-tools           # For 'ip' commands
    kernel-modules-extra # Ensure network/vxlan modules are available
)

# Define Terraform version
TERRAFORM_VERSION="1.8.5" # Using a recent, stable version

# Define Podman Network Parameters
PODMAN_NETWORK_NAME="autonomous-vxlan-net"
# NOTE: Replace 'vxlan0' with the actual VXLAN interface name on your host.
# We assume the VXLAN is already set up and functioning as 'vxlan0'.
VXLAN_HOST_INTERFACE="vxlan0"
VXLAN_SUBNET="172.25.0.0/24"
VXLAN_GATEWAY="172.25.0.1"


echo "========================================================"
echo "    AUTONOMOUS AUTONOMOUS ENVIRONMENT SETUP STARTING    "
echo "========================================================"

# 1. ARCHITECTURE AND OS CHECK
echo "1. Performing Architecture and OS checks..."
if [[ $(uname -m) != "x86_64" ]]; then
    echo "WARNING: Detected architecture is not x86_64. Script is optimized for x86_64."
    read -p "Continue anyway? (y/N): " continue_install
    if [[ "$continue_install" != "y" ]]; then
        echo "Aborting."
        exit 1
    fi
fi

if ! command -v dnf &> /dev/null; then
    echo "ERROR: 'dnf' command not found. This script requires a RHEL/Fedora-based system."
    exit 1
fi
echo "System check passed (RHEL/dnf detected)."

# 2. INSTALL SYSTEM PACKAGES
echo "2. Installing core system dependencies: ${REQUIRED_PACKAGES[*]}"
sudo dnf update -y
sudo dnf install -y "${REQUIRED_PACKAGES[@]}"

# 3. CONFIGURE PODMAN
echo "3. Configuring Podman for rootless usage..."
# Ensure Podman is ready and configured
podman system migrate --new-storage vfs &> /dev/null || true
echo "Podman is installed and ready. Use 'podman info' to verify."

# 4. VXLAN NETWORK PREPARATION (Ensuring module and interface are available)
echo "4. Preparing for VXLAN networking..."
# Load the kernel module needed for VXLAN
if ! lsmod | grep -q vxlan; then
    echo "Loading vxlan kernel module..."
    sudo modprobe vxlan
fi
# Check if the assumed VXLAN interface exists
if ! ip link show "$VXLAN_HOST_INTERFACE" &> /dev/null; then
    echo "WARNING: VXLAN interface '$VXLAN_HOST_INTERFACE' not found. Assuming it will be created later."
    echo "The full deployment script must ensure the VXLAN interface is created."
else
    echo "VXLAN interface '$VXLAN_HOST_INTERFACE' found."
fi

# 5. CONFIGURE PODMAN NETWORK ATTACHMENT
echo "5. Setting up Podman network '$PODMAN_NETWORK_NAME'..."

# First, attempt to remove the network if it exists to ensure a clean setup
podman network inspect "$PODMAN_NETWORK_NAME" &> /dev/null && podman network rm "$PODMAN_NETWORK_NAME"

# Create the new Podman network using bridge driver.
# The container traffic will use this bridge, and we route it to the VXLAN.
podman network create \
    --driver bridge \
    --subnet="$VXLAN_SUBNET" \
    --gateway="$VXLAN_GATEWAY" \
    "$PODMAN_NETWORK_NAME"

echo "Podman network '$PODMAN_NETWORK_NAME' created with subnet $VXLAN_SUBNET."
echo "Containers attached to this network will communicate over the host's VXLAN."

# 6. INSTALL TERRAFORM (IaC for Cloudflare/external services)
echo "6. Installing Terraform v${TERRAFORM_VERSION}..."
TERRAFORM_URL="https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip"
wget -q "$TERRAFORM_URL"
unzip -q "terraform_${TERRAFORM_VERSION}_linux_amd64.zip"
sudo mv terraform /usr/local/bin/
rm "terraform_${TERRAFORM_VERSION}_linux_amd64.zip"
terraform version
echo "Terraform installed to /usr/local/bin."

# 7. CLOUDFLARE CLI (cloudflared)
echo "7. Installing Cloudflare Tunnel client (cloudflared)..."
CLOUDFLARED_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
sudo wget -q -O /usr/local/bin/cloudflared "$CLOUDFLARED_URL"
sudo chmod +x /usr/local/bin/cloudflared
cloudflared --version
echo "Cloudflared installed for potential secure tunnel/proxying."

echo "========================================================"
echo "         SETUP COMPLETE: NEXT STEPS REQUIRED            "
echo "========================================================"
echo "Environment installation successful. The host is ready to run your Podman containers."
echo "NEXT STEPS (For the main deploy script):"
echo "1. Pull container images (e.g., postgres, nginx, your custom Django image)."
echo "2. Run containers, ensuring they attach to the '$PODMAN_NETWORK_NAME' network."
echo "3. Use Terraform to provision Cloudflare resources."
echo "4. Ensure a mechanism (like iptables/firewalld) routes traffic from '$PODMAN_NETWORK_NAME' to the host's '$VXLAN_HOST_INTERFACE'."
echo "5. The main deployment script should handle Django environment setup (e.g., database migration, collecting static files)."
