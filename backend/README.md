# HookProbe Backend: Mini Data Center Research & Kubernetes Implementation Plan

**Version**: 1.0  
**Date**: November 2025  
**Author**: HookProbe Team  
**Purpose**: Comprehensive research and implementation plan for centralized backend infrastructure

---

![Hookprobe Cloud Orchestrator](../images/hookprobe-cloud-orchestrator.png)

---

## Executive Summary

This document provides research on mini data center platforms and a detailed Kubernetes implementation plan for HookProbe's centralized backend. The goal is to create a one-stop control panel for complex AI/ML tasks, GPU-accelerated workloads, and scalable autonomous operations that complement the edge SBC deployments.

**Key Findings:**
- **Proxmox VE** is the optimal choice for cost-effective, flexible mini data center deployment
- **Kubernetes on VMs** provides best stability for production workloads
- **Hybrid approach** (Proxmox + K8s) maximizes resource efficiency while maintaining isolation

---

## 1. Mini Data Center Platform Research

### 1.1 Market Overview (2025)

| Platform | Market Share | Primary Use Case | Cost Model |
|----------|--------------|------------------|------------|
| VMware vSphere | 41.29% | Enterprise | Commercial (expensive post-Broadcom) |
| Proxmox VE | 1.44% (rapid growth) | SMB/Homelab/Edge | Open-source + optional support |
| Microsoft Hyper-V | ~15% | Windows-centric | Included with Windows Server |
| Citrix | 14.43% | VDI/Remote desktop | Commercial |
| Nutanix AHV | Growing | HCI appliances | Commercial (appliance-based) |

### 1.2 Platform Deep Dive

#### A. **Proxmox VE** ⭐ RECOMMENDED

**Architecture:**
- Debian-based (stable, well-supported)
- KVM hypervisor for VMs (full virtualization)
- LXC for containers (lightweight)
- Built-in Ceph/ZFS for distributed storage
- Web UI + REST API + CLI management
- Native clustering (HA, live migration)

**Strengths:**

✅ **Zero licensing cost** - No per-core or per-VM fees  
✅ **Full-featured** - HA, clustering, backup, snapshots included  
✅ **Kubernetes-friendly** - Excellent VM provisioning for K8s nodes  
✅ **Storage flexibility** - Local, ZFS, Ceph, NFS, iSCSI  
✅ **Open source** - No vendor lock-in, full control  
✅ **REST API** - Full automation via Terraform/Ansible  
✅ **Hardware compatibility** - Runs on commodity x86 servers  
✅ **Active community** - Rapid growth, 5,339+ companies using it

**Weaknesses:**

⚠️ **Less polished UI** - More manual configuration than VMware  
⚠️ **Storage setup complexity** - Ceph/ZFS requires planning  
⚠️ **Learning curve** - Less "wizardized" than VMware  
⚠️ **Fewer integrations** - Not as many third-party tools

**Best For:**

- Cost-sensitive deployments
- Homelab to production scaling
- Organizations valuing open source
- **HookProbe backend** (perfect fit!)

**Cost Analysis:**

- Base software: **$0**
- Optional enterprise repo: ~€90/year per node (updates, support)
- Total 3-node cluster: ~€270/year vs. VMware's $15,000-$50,000+

---

#### B. **VMware vSphere/ESXi**

**Architecture:**

- Type-1 bare-metal hypervisor (ESXi)
- vCenter for management
- vSAN for storage (optional)
- NSX for networking (optional)

**Strengths:**

✅ Mature, enterprise-grade  
✅ Best-in-class ecosystem  
✅ Excellent third-party integrations  
✅ Very polished UI/UX  
✅ Strong certification/compliance support

**Weaknesses:**

❌ **Extreme cost increase** - 2x to 5x post-Broadcom acquisition  
❌ **72-core minimum licensing** - Excessive for small deployments  
❌ **No free version** - ESXi Free discontinued  
❌ **Vendor lock-in** - Proprietary stack

**Best For:**

- Large enterprises with existing VMware investments
- Regulated industries requiring vendor support
- **NOT recommended for HookProbe** due to cost

---

#### C. **Microsoft Hyper-V**

**Architecture:**

- Type-1 hypervisor on Windows Server
- System Center for management
- Failover clustering built-in

**Strengths:**

✅ Included with Windows Server licenses  
✅ Excellent Windows VM performance  
✅ Good integration with Microsoft stack  
✅ Familiar to Windows admins

**Weaknesses:**

⚠️ Windows Server licensing required  
⚠️ Less flexible than Proxmox for Linux workloads  
⚠️ Limited storage options vs. Proxmox

**Best For:**

- Windows-heavy environments
- Organizations with existing Microsoft EAs

---

#### D. **Nutanix AHV**

**Strengths:**

✅ Hyper-converged infrastructure (HCI)  
✅ Excellent management (Prism)  
✅ Good performance

**Weaknesses:**
❌ Requires certified hardware (expensive)  
❌ Not suitable for DIY/commodity hardware

---

### 1.3 Recommendation Matrix

| Criteria | Proxmox | VMware | Hyper-V | Nutanix |
|----------|---------|--------|---------|---------|
| **Cost** | ⭐⭐⭐⭐⭐ | ⭐ | ⭐⭐⭐ | ⭐⭐ |
| **Flexibility** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **K8s Support** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Ease of Use** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **GPU Support** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **API/Automation** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **HookProbe Fit** | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐⭐ |

**Verdict: Proxmox VE** is the clear winner for HookProbe backend.

---

## 2. Kubernetes Deployment Strategy

### 2.1 Kubernetes on Proxmox: Deployment Models

#### **Model 1: VMs (RECOMMENDED) ✅**

```
┌─────────────────────────────────────────┐
│         Proxmox Host (Physical)         │
├─────────────────────────────────────────┤
│  VM 1         VM 2         VM 3         │
│  ┌─────┐     ┌─────┐     ┌─────┐       │
│  │ K8s │     │ K8s │     │ K8s │       │
│  │Ctrl │     │Work │     │Work │       │
│  │Plane│     │ er  │     │ er  │       │
│  └─────┘     └─────┘     └─────┘       │
│  Ubuntu      Ubuntu      Ubuntu         │
└─────────────────────────────────────────┘
```

**Advantages:**
- ✅ Full isolation (safest)
- ✅ Snapshots for rollback
- ✅ Live migration between hosts
- ✅ GPU passthrough works well
- ✅ Standard Kubernetes installation
- ✅ Production-ready

**Disadvantages:**
- ⚠️ Slightly more resource overhead (~5-10%)
- ⚠️ Requires more disk space

**Best For:** Production, HookProbe backend ⭐

---

#### **Model 2: LXC Containers**

```
┌─────────────────────────────────────────┐
│         Proxmox Host (Physical)         │
├─────────────────────────────────────────┤
│  LXC 1        LXC 2        LXC 3        │
│  ┌─────┐     ┌─────┐     ┌─────┐       │
│  │ K8s │     │ K8s │     │ K8s │       │
│  │Ctrl │     │Work │     │Work │       │
│  └─────┘     └─────┘     └─────┘       │
└─────────────────────────────────────────┘
```

**Advantages:**

- ✅ Lower resource overhead
- ✅ Faster startup

**Disadvantages:**

- ❌ Fragile (kernel module issues)
- ❌ Persistent storage problems (Longhorn, Rook don't work well)
- ❌ Requires manual configuration (AppArmor, mounts)
- ❌ Not recommended for production

**Best For:** Experimentation only

---

#### **Model 3: Bare Metal K8s + Proxmox (Advanced)**

Kubernetes installed directly on Proxmox hosts (running alongside Proxmox).

**Advantages:**

- ✅ Maximum performance (no VM overhead)
- ✅ Direct hardware access

**Disadvantages:**

- ❌ Complex etcd quorum management
- ❌ Risk to Proxmox if K8s fails
- ❌ Harder to manage
- ❌ Can't snapshot/migrate nodes

**Best For:** Advanced users only, not recommended for HookProbe

---

### 2.2 HookProbe Backend Architecture

**Recommended: Kubernetes on Proxmox VMs**

```
┌──────────────────────────────────────────────────────────────┐
│                    PROXMOX CLUSTER (3 Nodes)                 │
│                                                               │
│  Node 1              Node 2              Node 3              │
│  ┌──────────┐       ┌──────────┐       ┌──────────┐        │
│  │ K8s      │       │ K8s      │       │ K8s      │        │
│  │ Control  │◄─────►│ Control  │◄─────►│ Control  │        │
│  │ Plane VM │       │ Plane VM │       │ Plane VM │        │
│  │ (etcd)   │       │ (etcd)   │       │ (etcd)   │        │
│  └──────────┘       └──────────┘       └──────────┘        │
│                                                               │
│  ┌──────────┐       ┌──────────┐       ┌──────────┐        │
│  │ K8s      │       │ K8s      │       │ K8s      │        │
│  │ Worker   │       │ Worker   │       │ Worker   │        │
│  │ VM       │       │ VM + GPU │       │ VM       │        │
│  │          │       │ (AI/ML)  │       │          │        │
│  └──────────┘       └──────────┘       └──────────┘        │
│                                                               │
│  ┌────────────────────────────────────────────────┐         │
│  │        Ceph Distributed Storage (OSDs)         │         │
│  │  (Provides PVs for K8s Persistent Storage)     │         │
│  └────────────────────────────────────────────────┘         │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  Edge SBCs       │
                    │  (Intel N100s)   │
                    │  Running         │
                    │  HookProbe v5.0  │
                    └──────────────────┘
```

---

## 3. Detailed Implementation Plan

### 3.1 Hardware Requirements

**Minimum Configuration (3-node cluster):**

| Component | Specification | Purpose |
|-----------|--------------|---------|
| **CPU** | Intel Xeon/AMD EPYC, 8+ cores | K8s scheduling, ML workloads |
| **RAM** | 64GB per node (192GB total) | VMs, containers, Ceph |
| **Storage** | 1TB NVMe SSD per node | etcd, VM images, Ceph OSDs |
| **Network** | 10GbE recommended | Ceph replication, K8s traffic |
| **GPU** | NVIDIA (optional, 1-2 nodes) | AI/ML inference/training |

**Recommended Configuration:**
- 3x servers with 128GB RAM each
- 2x 1TB NVMe per node (OS + Ceph)
- 10GbE networking
- 1x NVIDIA A100/H100 for AI workloads

---

### 3.2 Software Stack

```
┌─────────────────────────────────────────┐
│         Application Layer               │
│  - Django (from edge SBCs)              │
│  - AI Models (TensorFlow, PyTorch)      │
│  - Qsecbit Analysis (centralized)       │
│  - Content Generation AI                │
└─────────────────────────────────────────┘
                  │
┌─────────────────────────────────────────┐
│      Kubernetes Orchestration           │
│  - Control Plane (kubeadm/RKE2)         │
│  - CNI: Cilium (recommended)            │
│  - CSI: Rook-Ceph                       │
│  - Ingress: Nginx/Traefik               │
│  - Service Mesh: Istio (optional)       │
└─────────────────────────────────────────┘
                  │
┌─────────────────────────────────────────┐
│       Virtualization Layer              │
│  - Proxmox VE 8.2+                      │
│  - VMs: Ubuntu 24.04 LTS                │
│  - GPU Passthrough (PCIe)               │
└─────────────────────────────────────────┘
                  │
┌─────────────────────────────────────────┐
│       Storage & Networking              │
│  - Ceph (distributed storage)           │
│  - OVS (virtual networking)             │
│  - VLANs for isolation                  │
└─────────────────────────────────────────┘
                  │
┌─────────────────────────────────────────┐
│          Physical Hardware              │
│  - 3x Servers (CPU, RAM, NVMe, GPU)     │
│  - 10GbE Switch                         │
│  - UPS (recommended)                    │
└─────────────────────────────────────────┘
```

---

### 3.3 Step-by-Step Deployment

#### **Phase 1: Proxmox Cluster Setup (Week 1)**

**Step 1.1: Install Proxmox VE**

```bash
# Download Proxmox VE ISO
wget https://www.proxmox.com/en/downloads

# Install on all 3 nodes via USB/iPXE
# Use ZFS RAID1 for OS disks during installation
```

**Step 1.2: Configure Networking**

```bash
# /etc/network/interfaces on each node

auto lo
iface lo inet loopback

# Management Network (for Proxmox UI/SSH)
auto eno1
iface eno1 inet static
    address 192.168.1.10/24
    gateway 192.168.1.1

# Ceph Public Network (10GbE)
auto eno2
iface eno2 inet static
    address 10.0.1.10/24

# Ceph Cluster Network (10GbE)
auto eno3
iface eno3 inet static
    address 10.0.2.10/24

# Bridge for VM networking
auto vmbr0
iface vmbr0 inet static
    address 10.100.0.1/24
    bridge-ports none
    bridge-stp off
    bridge-fd 0
```

**Step 1.3: Create Proxmox Cluster**

```bash
# On Node 1 (master)
pvecm create hookprobe-cluster

# On Node 2 and 3
pvecm add 192.168.1.10
```

**Step 1.4: Configure Ceph Storage**

```bash
# Install Ceph packages on all nodes
pveceph install

# Initialize Ceph
pveceph init --network 10.0.1.0/24

# Create monitors (on all 3 nodes)
pveceph mon create

# Create OSDs (use NVMe SSDs)
pveceph osd create /dev/nvme0n1

# Create Ceph pools
pveceph pool create k8s-storage --size 3 --min_size 2
pveceph pool create k8s-rbd --size 3 --min_size 2
```

---

#### **Phase 2: Kubernetes VM Provisioning (Week 2)**

**Step 2.1: Create Ubuntu VM Template**

```bash
# Download Ubuntu Cloud Image
cd /var/lib/vz/template/iso
wget https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img

# Create VM template
qm create 9000 --name ubuntu-k8s-template --memory 4096 --cores 2 --net0 virtio,bridge=vmbr0
qm importdisk 9000 ubuntu-24.04-server-cloudimg-amd64.img local-lvm
qm set 9000 --scsihw virtio-scsi-pci --scsi0 local-lvm:vm-9000-disk-0
qm set 9000 --boot c --bootdisk scsi0
qm set 9000 --ide2 local-lvm:cloudinit
qm set 9000 --serial0 socket --vga serial0
qm set 9000 --agent enabled=1

# Convert to template
qm template 9000
```

**Step 2.2: Deploy K8s VMs with Terraform**

Create `main.tf`:

```hcl
terraform {
  required_providers {
    proxmox = {
      source  = "Telmate/proxmox"
      version = "3.0.1-rc4"
    }
  }
}

provider "proxmox" {
  pm_api_url      = "https://192.168.1.10:8006/api2/json"
  pm_api_token_id = "terraform@pam!terraform_token"
  pm_api_token_secret = "your-secret-here"
  pm_tls_insecure = true
}

# Control Plane VMs
resource "proxmox_vm_qemu" "k8s_control_plane" {
  count       = 3
  name        = "k8s-control-${count.index + 1}"
  target_node = "pve-node-${count.index + 1}"
  clone       = "ubuntu-k8s-template"
  
  cores   = 4
  memory  = 8192
  sockets = 1
  
  disk {
    size    = "50G"
    storage = "ceph-storage"
    type    = "scsi"
  }
  
  network {
    model  = "virtio"
    bridge = "vmbr0"
  }
  
  ipconfig0 = "ip=10.100.0.${10 + count.index}/24,gw=10.100.0.1"
  
  ciuser     = "ubuntu"
  cipassword = "your-secure-password"
  sshkeys    = file("~/.ssh/id_rsa.pub")
}

# Worker VMs
resource "proxmox_vm_qemu" "k8s_worker" {
  count       = 3
  name        = "k8s-worker-${count.index + 1}"
  target_node = "pve-node-${(count.index % 3) + 1}"
  clone       = "ubuntu-k8s-template"
  
  cores   = 8
  memory  = 32768
  sockets = 1
  
  disk {
    size    = "100G"
    storage = "ceph-storage"
    type    = "scsi"
  }
  
  network {
    model  = "virtio"
    bridge = "vmbr0"
  }
  
  ipconfig0 = "ip=10.100.0.${20 + count.index}/24,gw=10.100.0.1"
  
  ciuser     = "ubuntu"
  cipassword = "your-secure-password"
  sshkeys    = file("~/.ssh/id_rsa.pub")
}
```

Deploy:

```bash
terraform init
terraform plan
terraform apply
```

---

#### **Phase 3: Kubernetes Installation (Week 3)**

**Step 3.1: Prepare All Nodes**

Run on all K8s VMs:

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Disable swap
sudo swapoff -a
sudo sed -i '/ swap / s/^/#/' /etc/fstab

# Load kernel modules
cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF

sudo modprobe overlay
sudo modprobe br_netfilter

# Sysctl params
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

sudo sysctl --system

# Install containerd
sudo apt install -y containerd
sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
sudo systemctl restart containerd
sudo systemctl enable containerd

# Install kubeadm, kubelet, kubectl
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gpg
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.31/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.31/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list
sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl
```

**Step 3.2: Initialize First Control Plane**

On `k8s-control-1`:

```bash
sudo kubeadm init \
  --control-plane-endpoint="10.100.0.100:6443" \
  --upload-certs \
  --pod-network-cidr=10.244.0.0/16 \
  --apiserver-advertise-address=10.100.0.10

# Save the output! Contains join commands for control plane and workers

# Configure kubectl for admin user
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

**Step 3.3: Join Other Control Planes**

On `k8s-control-2` and `k8s-control-3`:

```bash
# Use the control-plane join command from step 3.2
sudo kubeadm join 10.100.0.100:6443 --token <token> \
  --discovery-token-ca-cert-hash sha256:<hash> \
  --control-plane --certificate-key <cert-key>
```

**Step 3.4: Install CNI (Cilium)**

On `k8s-control-1`:

```bash
# Install Cilium CLI
CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-amd64.tar.gz{,.sha256sum}
sha256sum --check cilium-linux-amd64.tar.gz.sha256sum
sudo tar xzvfC cilium-linux-amd64.tar.gz /usr/local/bin
rm cilium-linux-amd64.tar.gz{,.sha256sum}

# Install Cilium
cilium install --version 1.16.3

# Verify
cilium status --wait
```

**Step 3.5: Join Worker Nodes**

On all worker VMs:

```bash
# Use the worker join command from step 3.2
sudo kubeadm join 10.100.0.100:6443 --token <token> \
  --discovery-token-ca-cert-hash sha256:<hash>
```

**Step 3.6: Verify Cluster**

```bash
kubectl get nodes
# All nodes should be Ready

kubectl get pods -A
# All system pods should be Running
```

---

#### **Phase 4: Storage & GPU Configuration (Week 4)**

**Step 4.1: Install Rook-Ceph for Persistent Storage**

```bash
# Clone Rook
git clone --single-branch --branch v1.15.1 https://github.com/rook/rook.git
cd rook/deploy/examples

# Install Rook operator
kubectl create -f crds.yaml
kubectl create -f common.yaml
kubectl create -f operator.yaml

# Wait for operator
kubectl -n rook-ceph get pod -w

# Create Ceph cluster (pointing to Proxmox Ceph)
cat <<EOF | kubectl apply -f -
apiVersion: ceph.rook.io/v1
kind:CephCluster
metadata:
  name: rook-ceph
  namespace: rook-ceph
spec:
  dataDirHostPath: /var/lib/rook
  external:
    enable: true
  cephVersion:
    image: quay.io/ceph/ceph:v18
EOF

# Create storage class
kubectl create -f csi/rbd/storageclass.yaml
```

**Step 4.2: GPU Passthrough (for AI Worker Node)**

On Proxmox host with GPU:

```bash
# Enable IOMMU
nano /etc/default/grub
# Add: intel_iommu=on iommu=pt (Intel) or amd_iommu=on (AMD)

update-grub
reboot

# Verify IOMMU groups
find /sys/kernel/iommu_groups/ -type l

# Add GPU to VM
qm set 102 -hostpci0 01:00,pcie=1
# Replace 01:00 with your GPU's PCI ID

# Reboot VM
qm reboot 102
```

Inside GPU worker VM:

```bash
# Install NVIDIA drivers
sudo apt install -y nvidia-driver-550
sudo reboot

# Verify GPU
nvidia-smi

# Install NVIDIA Container Toolkit
distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
curl -s -L https://nvidia.github.io/nvidia-docker/gpgkey | sudo apt-key add -
curl -s -L https://nvidia.github.io/nvidia-docker/$distribution/nvidia-docker.list | sudo tee /etc/apt/sources.list.d/nvidia-docker.list

sudo apt-get update
sudo apt-get install -y nvidia-container-toolkit

# Configure containerd
sudo nvidia-ctk runtime configure --runtime=containerd
sudo systemctl restart containerd

# Label GPU node
kubectl label nodes k8s-worker-2 nvidia.com/gpu=true
```

Install NVIDIA Device Plugin:

```bash
kubectl apply -f https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/v0.16.2/deployments/static/nvidia-device-plugin.yml
```

Test GPU:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gpu-test
spec:
  containers:
  - name: cuda
    image: nvidia/cuda:12.3.0-base-ubuntu22.04
    command: ["nvidia-smi"]
    resources:
      limits:
        nvidia.com/gpu: 1
  restartPolicy: Never
```

```bash
kubectl apply -f gpu-test.yaml
kubectl logs gpu-test
```

---

#### **Phase 5: HookProbe Backend Services (Week 5-6)**

**Step 5.1: Install Monitoring Stack**

```bash
# Install kube-prometheus-stack
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace \
  --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.resources.requests.storage=50Gi \
  --set grafana.persistence.enabled=true \
  --set grafana.persistence.size=10Gi
```

**Step 5.2: Deploy Qsecbit Centralized Analysis**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: qsecbit-backend
  namespace: hookprobe
spec:
  replicas: 3
  selector:
    matchLabels:
      app: qsecbit-backend
  template:
    metadata:
      labels:
        app: qsecbit-backend
    spec:
      containers:
      - name: qsecbit
        image: hookprobe/qsecbit:v5.0
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
        env:
        - name: REDIS_HOST
          value: "redis-service"
        - name: POSTGRES_HOST
          value: "postgres-service"
        - name: ML_MODEL_PATH
          value: "/models/qsecbit-v5.0.pkl"
        volumeMounts:
        - name: models
          mountPath: /models
          readOnly: true
        - name: data
          mountPath: /data
      volumes:
      - name: models
        persistentVolumeClaim:
          claimName: qsecbit-models-pvc
      - name: data
        persistentVolumeClaim:
          claimName: qsecbit-data-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: qsecbit-backend-service
  namespace: hookprobe
spec:
  selector:
    app: qsecbit-backend
  ports:
  - port: 8888
    targetPort: 8888
  type: ClusterIP
```

**Step 5.3: Deploy AI Content Generation Service**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ai-content-generator
  namespace: hookprobe
spec:
  replicas: 1  # Only 1 replica due to GPU constraint
  selector:
    matchLabels:
      app: ai-content-generator
  template:
    metadata:
      labels:
        app: ai-content-generator
    spec:
      nodeSelector:
        nvidia.com/gpu: "true"
      containers:
      - name: llm-service
        image: hookprobe/llm-content-gen:v1.0
        resources:
          limits:
            nvidia.com/gpu: 1
            memory: "16Gi"
            cpu: "4000m"
        env:
        - name: MODEL_NAME
          value: "meta-llama/Llama-3.3-70B-Instruct"
        - name: VLLM_GPU_MEMORY_UTILIZATION
          value: "0.9"
        volumeMounts:
        - name: model-cache
          mountPath: /root/.cache
      volumes:
      - name: model-cache
        persistentVolumeClaim:
          claimName: llm-cache-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: ai-content-service
  namespace: hookprobe
spec:
  selector:
    app: ai-content-generator
  ports:
  - port: 8000
    targetPort: 8000
  type: ClusterIP
```

**Step 5.4: Deploy Django Centralized Backend**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: django-central
  namespace: hookprobe
spec:
  replicas: 3
  selector:
    matchLabels:
      app: django-central
  template:
    metadata:
      labels:
        app: django-central
    spec:
      containers:
      - name: django
        image: hookprobe/django-central:v5.0
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: django-secrets
              key: database-url
        - name: REDIS_URL
          value: "redis://redis-service:6379/0"
        - name: QSECBIT_API_URL
          value: "http://qsecbit-backend-service:8888"
        - name: AI_CONTENT_API_URL
          value: "http://ai-content-service:8000"
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
---
apiVersion: v1
kind: Service
metadata:
  name: django-central-service
  namespace: hookprobe
spec:
  selector:
    app: django-central
  ports:
  - port: 80
    targetPort: 8000
  type: LoadBalancer  # Or use Ingress
```

---

## 4. Network Architecture

### 4.1 Network Topology

```
┌─────────────────────────────────────────────────────────────┐
│                     INTERNET                                 │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
          ┌────────────────────────┐
          │  Edge Firewall/Router  │
          │  (OPNsense/pfSense)    │
          └────────────┬───────────┘
                       │
                       ▼
          ┌────────────────────────┐
          │   10GbE Core Switch    │
          └──┬──────────┬─────────┬┘
             │          │         │
    ┌────────▼───┐ ┌───▼────┐ ┌─▼────────┐
    │ Proxmox    │ │Proxmox │ │ Proxmox  │
    │ Node 1     │ │Node 2  │ │ Node 3   │
    └────────────┘ └────────┘ └──────────┘
         │              │           │
         └──────────────┴───────────┘
                    │
         ┌──────────▼──────────┐
         │  Virtual Networks   │
         │                     │
         │  10.100.0.0/24  ←─  K8s Management
         │  10.244.0.0/16  ←─  K8s Pods
         │  10.96.0.0/12   ←─  K8s Services
         │  10.0.1.0/24    ←─  Ceph Public
         │  10.0.2.0/24    ←─  Ceph Cluster
         └─────────────────────┘
```

### 4.2 VLAN Segmentation

| VLAN ID | Network | Purpose |
|---------|---------|---------|
| 10 | 192.168.1.0/24 | Proxmox Management |
| 20 | 10.100.0.0/24 | K8s Node Network |
| 30 | 10.0.1.0/24 | Ceph Public |
| 40 | 10.0.2.0/24 | Ceph Cluster |
| 50 | 172.16.0.0/24 | Edge SBC Connection |

---

## 5. Integration with Edge SBCs

### 5.1 Communication Pattern

```
Edge SBC (Intel N100)          Backend Kubernetes
┌──────────────────┐           ┌──────────────────┐
│ HookProbe v5.0   │           │                  │
│                  │           │ Django Central   │
│ - Qsecbit Local  │──REST API─▶ - Aggregation   │
│ - Local Logs     │──HTTPS────▶ - Analysis       │
│ - Metrics        │──WireGuard─▶ - Storage       │
│                  │           │                  │
│                  │◀──Tasks────│ AI Content Gen  │
│                  │◀──Updates──│ Model Updates   │
└──────────────────┘           └──────────────────┘
```

### 5.2 API Endpoints

**Edge → Backend:**
- `POST /api/v1/sbc/register` - Register new edge SBC
- `POST /api/v1/sbc/metrics` - Push metrics
- `POST /api/v1/sbc/alerts` - Send Qsecbit alerts
- `GET /api/v1/sbc/tasks` - Poll for content generation tasks

**Backend → Edge:**
- `POST /api/v1/edge/content/publish` - Push new blog content
- `PUT /api/v1/edge/config/update` - Update configuration
- `GET /api/v1/edge/status` - Health check

---

## 6. Cost Analysis

### 6.1 Hardware Costs (3-Node Cluster)

| Item | Quantity | Unit Cost | Total |
|------|----------|-----------|-------|
| Server (32-core, 128GB RAM, 2TB NVMe) | 3 | €2,500 | €7,500 |
| NVIDIA A100 40GB | 1 | €8,000 | €8,000 |
| 10GbE Switch (24-port) | 1 | €1,500 | €1,500 |
| UPS (3000VA) | 1 | €800 | €800 |
| Networking cables, misc | - | €200 | €200 |
| **Total Hardware** | | | **€18,000** |

### 6.2 Software Costs (Annual)

| Item | Cost |
|------|------|
| Proxmox Enterprise Repo (3 nodes) | €270 |
| Domain & SSL certificates | €100 |
| Backup storage (cloud) | €500 |
| Monitoring/logging tools (optional) | €0 (open source) |
| **Total Software (Year 1)** | **€870** |

### 6.3 Operational Costs (Monthly)

| Item | Cost |
|------|------|
| Electricity (~2kW 24/7 @ €0.15/kWh) | €216 |
| Internet (1Gbps dedicated) | €100 |
| Colocation/hosting (if applicable) | €300 |
| **Total Monthly** | **€616** |

### 6.4 Total Cost Comparison

**HookProbe Backend (Proxmox + K8s):**
- Hardware: €18,000 (one-time)
- Year 1 total: €18,000 + €870 + (€616 × 12) = **€26,262**
- Year 2+: €870 + (€616 × 12) = **€8,262/year**

**VMware Alternative:**
- Hardware: €18,000
- vSphere licenses (3 nodes): €45,000
- vSAN licenses: €15,000
- Year 1 total: €78,000 + maintenance
- **3-4x more expensive!**

**Verdict:** Proxmox saves **€52,000+** in first year alone.

---

## 7. Automation & IaC

### 7.1 Terraform Structure

```
hookprobe-backend/
├── terraform/
│   ├── proxmox/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── vms.tf
│   │   └── outputs.tf
│   └── kubernetes/
│       ├── namespaces.tf
│       ├── deployments.tf
│       ├── services.tf
│       └── ingress.tf
├── ansible/
│   ├── inventory/
│   │   ├── hosts.yml
│   │   └── group_vars/
│   ├── playbooks/
│   │   ├── k8s-setup.yml
│   │   ├── gpu-config.yml
│   │   └── monitoring.yml
│   └── roles/
│       ├── docker/
│       ├── kubernetes/
│       └── nvidia/
└── kubernetes/
    ├── base/
    │   ├── namespaces/
    │   ├── services/
    │   └── storage/
    ├── apps/
    │   ├── qsecbit/
    │   ├── django/
    │   └── ai-content/
    └── monitoring/
        ├── prometheus/
        ├── grafana/
        └── loki/
```

### 7.2 GitOps with ArgoCD

```bash
# Install ArgoCD
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# Expose UI
kubectl patch svc argocd-server -n argocd -p '{"spec": {"type": "LoadBalancer"}}'

# Get admin password
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

# Create application
kubectl apply -f - <<EOF
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: hookprobe-backend
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/hookprobe/backend
    targetRevision: main
    path: kubernetes/apps
  destination:
    server: https://kubernetes.default.svc
    namespace: hookprobe
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
EOF
```

---

## 8. Security Hardening

### 8.1 Proxmox Hardening

```bash
# Enable 2FA
apt install libpam-google-authenticator
google-authenticator

# Restrict SSH
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
systemctl restart sshd

# Firewall
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 8006/tcp
ufw allow from 10.0.0.0/8
ufw enable

# TLS certificates
pvecm updatecerts
```

### 8.2 Kubernetes Security

```bash
# Install Falco (runtime security)
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco --namespace falco --create-namespace

# Pod Security Standards
kubectl label --overwrite ns hookprobe pod-security.kubernetes.io/enforce=restricted

# Network Policies
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: hookprobe
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
EOF
```

---

## 9. Monitoring & Observability

### 9.1 Metrics Collection

```
Prometheus                   Grafana
    ↑                           ↑
    │                           │
    ├─── Node Exporter (Host metrics)
    ├─── cAdvisor (Container metrics)
    ├─── kube-state-metrics (K8s objects)
    ├─── GPU Exporter (NVIDIA metrics)
    └─── Custom Exporters (Qsecbit, Django)
```

### 9.2 Key Dashboards

1. **Cluster Overview** - CPU, RAM, disk, network across all nodes
2. **GPU Utilization** - GPU memory, temperature, power
3. **Application Performance** - Qsecbit latency, AI inference time
4. **Cost Analysis** - Resource usage per application
5. **SBC Fleet Status** - Health of all edge devices

---

## 10. Disaster Recovery

### 10.1 Backup Strategy

**Level 1: Proxmox Backups**
```bash
# Schedule VM backups to NAS
vzdump 100 --mode snapshot --storage nas-backup --compress zstd
```

**Level 2: Kubernetes Backups (Velero)**
```bash
# Install Velero
velero install \
  --provider aws \
  --bucket hookprobe-k8s-backups \
  --backup-location-config region=us-east-1 \
  --snapshot-location-config region=us-east-1

# Schedule daily backups
velero schedule create daily-backup --schedule="0 2 * * *"
```

**Level 3: Database Backups**
```bash
# Automated PostgreSQL backups to S3
kubectl create cronjob postgres-backup \
  --image=postgres:16 \
  --schedule="0 3 * * *" \
  -- /bin/sh -c "pg_dump -h postgres-service -U hookprobe | gzip | aws s3 cp - s3://backups/postgres/$(date +%Y%m%d).sql.gz"
```

### 10.2 Recovery Procedures

**Scenario 1: Single Node Failure**
- Proxmox HA automatically migrates VMs to healthy nodes
- K8s reschedules pods to available workers
- **RTO**: < 5 minutes

**Scenario 2: Complete Cluster Loss**
1. Rebuild Proxmox cluster from ISO
2. Restore VMs from backups
3. Restore K8s with Velero
4. Restore databases from S3
- **RTO**: 4-6 hours

---

## 11. Performance Optimization

### 11.1 CPU Pinning for VMs

```bash
# Pin control plane VMs to dedicated cores
qm set 100 -cores 4 -cpuunits 2048 -numa 1
```

### 11.2 Huge Pages for etcd

```bash
# Enable huge pages on hosts
echo 1024 > /proc/sys/vm/nr_hugepages

# Configure K8s control plane
--feature-gates=HugePages=true
```

### 11.3 GPU Scheduling

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ai-training
spec:
  schedulerName: gpu-scheduler
  containers:
  - name: pytorch
    resources:
      limits:
        nvidia.com/gpu: 1
  nodeSelector:
    nvidia.com/gpu-model: A100
```

---

## 12. Migration Path

### 12.1 From Edge-Only to Backend

**Phase 1: Install Backend (Weeks 1-4)**
- Deploy Proxmox cluster
- Install Kubernetes
- Set up storage and networking

**Phase 2: Deploy Core Services (Weeks 5-6)**
- Migrate Django from edge to backend
- Deploy Qsecbit centralized analysis
- Set up monitoring

**Phase 3: Connect Edge Devices (Weeks 7-8)**
- Configure VPN between edge and backend
- Update edge SBCs to push data to backend
- Test failover scenarios

**Phase 4: Launch AI Content Generation (Week 9)**
- Deploy LLM service on GPU worker
- Integrate with Django
- Start autonomous content creation

**Phase 5: Optimize & Scale (Week 10+)**
- Fine-tune performance
- Add more edge devices
- Scale backend services as needed

---

## 13. Conclusion

### 13.1 Key Recommendations

✅ **Use Proxmox VE** for virtualization (cost-effective, flexible)  
✅ **Run Kubernetes on VMs** (not LXC) for production stability  
✅ **Use Cilium CNI** for advanced networking  
✅ **Use Rook-Ceph** for persistent storage  
✅ **GPU passthrough** for AI/ML workloads  
✅ **Automate everything** with Terraform + Ansible + ArgoCD  
✅ **Monitor extensively** with Prometheus + Grafana  
✅ **Backup religiously** with Proxmox + Velero + S3

### 13.2 Success Metrics

By implementing this architecture, HookProbe will achieve:

- **10x cost savings** vs. VMware (€52,000+ saved in first year)
- **24/7 availability** with HA clustering
- **GPU-accelerated AI** for content generation and ML analysis
- **Centralized management** of all edge SBCs
- **Scalable platform** ready to grow from 10 to 10,000 edge devices
- **Autonomous operations** with AI-driven content and threat response

### 13.3 Next Steps

1. **Procure hardware** (3x servers + GPU + switch)
2. **Install Proxmox VE** on all nodes
3. **Follow deployment phases** (Weeks 1-10)
4. **Connect edge SBCs** to backend
5. **Launch autonomous content generation**
6. **Scale and optimize**

---

## Appendices

### A. Hardware Vendors

**Recommended Server Vendors:**
- Dell PowerEdge R650 / R750
- HP ProLiant DL360 Gen11
- Supermicro SuperServer (custom builds)
- Lenovo ThinkSystem SR650 V3

**GPU Options:**
- NVIDIA A100 (40GB/80GB) - Best for training
- NVIDIA L40S - Balanced inference/training
- NVIDIA H100 - Bleeding edge (expensive)
- NVIDIA RTX 6000 Ada - Good value for SMBs

### B. Software Versions

- Proxmox VE: 8.2+
- Kubernetes: 1.31+
- Cilium: 1.16+
- Rook-Ceph: 1.15+
- Ubuntu: 24.04 LTS
- NVIDIA Driver: 550+
- Containerd: 1.7+

### C. Useful Commands

**Proxmox:**
```bash
# List VMs
qm list

# Start VM
qm start 100

# Migrate VM to another node
qm migrate 100 pve-node-2 --online

# Backup VM
vzdump 100 --mode snapshot
```

**Kubernetes:**
```bash
# Get all resources
kubectl get all -A

# Describe node
kubectl describe node k8s-worker-1

# Check logs
kubectl logs -f deployment/qsecbit-backend -n hookprobe

# Execute in pod
kubectl exec -it <pod> -n hookprobe -- bash
```

**Ceph:**
```bash
# Check cluster health
ceph status

# List pools
ceph osd pool ls

# Check OSD tree
ceph osd tree
```

---

**Document End**

For questions or support:
- GitHub: https://github.com/hookprobe/backend
- Email: qsecbit@hookprobe.com
