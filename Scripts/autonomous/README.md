🛡️💥
We're officially building the Autonomous Autonomous — a self-sustaining, self-monitoring, self-repairing, secure AI-enabled system.
This will be next-level stuff — think SpaceX Mission Control... but for your own cluster. 🚀

🧩 Here's Our MASTER PLAN:

```
Phase	System	Goal
1	Full repo bundle	Simple make deploy UX
2	AI-based IDS	Smarter, self-learning Suricata
3	Immutable infrastructure	Auto rebuild full stack from scratch
4	Distributed storage	Durable shared volumes (optional)
5	Self-tuning + Self-healing	System repairs and optimizes itself
6	Monitoring and Alerting	Grafana + Alertmanager + Slack/Webhooks
7	Zero-trust everywhere	Tailscale + Signed containers
```
🏗️ Phase 1: Full Autonomous GitHub Repo Structure

```
xsoc-autonomous/
├── ansible/
│   ├── inventory.ini
│   ├── playbook.yaml
│   ├── cleanup_playbook.yaml
│   ├── roles/
├── deploy/
│   ├── setup_environment.sh
│   ├── setup_vxlan.sh
│   ├── deploy_suricata.sh
│   ├── deploy_dashboard.sh
│   ├── deploy_cloudflare.sh
│   ├── deploy_ai_ids.sh
│   ├── deploy_monitoring.sh
│   ├── teardown.sh
│   ├── monitoring/
│   │   └── prometheus.yml
├── ai_ids/
│   ├── train_model.py
│   ├── detect_intrusions.py
│   ├── data/
├── terraform/
│   ├── main.tf
├── .github/
│   ├── workflows/
│   │   └── deploy.yaml
├── Makefile
├── .env
└── README.md
```
✅ Everything modular, neat, ONE-CLICK deploy.

🧠 Phase 2: AI-based IDS Enhancements


ai_ids/train_model.py

Train a lightweight model on Suricata logs.
Use scikit-learn or PyTorch.
Example flow:

```
from sklearn.ensemble import RandomForestClassifier

# Load labeled alerts dataset
# Train model
# Save model
```

✅ You can automatically retrain monthly based on real traffic!

ai_ids/detect_intrusions.py

Load model
Predict incoming events
Tag suspicious anomalies separately from signature-based ones

✅ Blends traditional IDS + ML-based detection!

📦 Phase 3: Immutable Infrastructure

Terraform will:

Provision your VPS/cloud nodes.
Install basic OS + ansible + docker/podman.
Setup Tailscale auth.
Example terraform/main.tf:
```
provider "hcloud" {
  token = var.hcloud_token
}

resource "hcloud_server" "node" {
  count = 3
  name = "xsoc-node-${count.index}"
  image = "ubuntu-22.04"
  server_type = "cx31"
  ssh_keys = ["my-key"]
}
```
✅ Rebuild entire clusters in minutes.

📡 Phase 4: Distributed Storage (Optional)

If you need shared volumes:

Use MinIO (S3-compatible) over VXLAN
Or full Ceph cluster if going hardcore
Lightweight version:
```
podman run -d --restart=always --name minio -p 9000:9000 -v minio-data:/data minio/minio server /data
```
🔄 Phase 5: Self-Tuning & Healing

We will set up:

Systemd watchdogs for services.
Container healthchecks for Podman.
Alertmanager to auto-reboot unhealthy nodes via Ansible.
✅ Full autonomic nervous system for XSOC.

📈 Phase 6: Monitoring & Alerting

Grafana Dashboards:

CPU, RAM, DISK
VXLAN health
Suricata alerts (signature + AI)
Alertmanager Config:

Slack notifications
Telegram bots
Email fallback
✅ You’ll get pings like:
```
🚨 XSOC: High CPU on node2
🚨 XSOC: IDS detected potential breach
🔒 Phase 7: Zero-Trust and Security
```
Use Tailscale ACLs for strict internal traffic
Funnel for external dashboards only (OAuth protected)
Cosign to sign all your containers
Trivy to scan images automatically during build
✅ Fully secured supply chain.

🚀 Quick Demo Flow

Imagine:
```
git clone https://github.com/yourname/xsoc-autonomous
cd xsoc-autonomous
make deploy
```
👉 In 10 minutes:

All nodes are live
VXLAN + Tailscale mesh up
Monitoring dashboards active
IDS detecting threats
AI model learning
Full auto-healing activated
GitHub auto-deploy on next update
You won't even have to SSH manually anymore. It’s pure self-orchestration.



# xSOC Edge AI Router

A fully autonomous edge device setup script and installer for Ubuntu 24.04 using Podman containers, AI/ML Intrusion Detection, Cloudflare tunnels, VXLAN networking, and a lightweight Django-based dashboard.

---

## 📦 Components Installed

- **Podman** + **Podman Compose**
- **Suricata** (WAN Traffic Inspection)
- **Cloudflare Tunnel** (Zero-Trust Access)
- **AI/ML Packet Analyzer** (IsolationForest Model)
- **PostgreSQL** (Persistent Database)
- **SQLite** (Transient Fast Storage)
- **Django + Gunicorn + Nginx** (Web Application)
- **cAdvisor** (Container Monitoring)
- **Cockpit + Podman GUI** (Web Admin)
- **VXLAN Virtual Networking**

## 🚀 Quick Start

```bash
bash deploy-xsoc.sh
```

Or install as a `.deb` package:

```bash
dpkg -i xsoc_<version>.deb
```

Access services:
- **Cockpit Podman GUI**: `https://YOUR-LAN-IP:9090`
- **xSOC Dashboard**: `http://YOUR-LAN-IP:8000`
- **AI/ML Analyzer**: `http://YOUR-LAN-IP:5000/detect`
- **cAdvisor Metrics**: `http://YOUR-LAN-IP:8080`

---

## 🔥 Features

- **Auto-Refreshing Dashboard**: CPU, Memory, Disk Live Stats (updates every 5s)
- **AI/ML IDS**: Suricata + Isolation Forest for anomaly detection
- **VXLAN LAN IP**: Default 172.28.1.1/24
- **Firewall**: Protect LAN and expose only secure services
- **Fully Podman Native**: No Docker needed
- **Cloudflare Tunnel**: Secure public access
- **Auto-Versioning**: Pulls version from Git tags during package build

---

## 🛠 Management

### Start services manually
```bash
sudo systemctl start xsoc
sudo bash /opt/xsoc/vxlan/vxlan-setup.sh
```

### Stop services manually
```bash
sudo systemctl stop xsoc
```

### Full Uninstall
```bash
sudo bash /opt/xsoc/uninstall-xsoc.sh
```

Or if installed via `.deb`:

```bash
sudo apt remove xsoc
```

---

## 📚 Directory Layout

```
/opt/xsoc/
├── cloudflared/
├── suricata/
├── persistentdb/
├── transientdb/
├── webapp/
│   ├── django/
│   ├── nginx/
│   └── gunicorn/
├── ai-ml/
│   └── packet-analyser/
├── monitoring/
├── vxlan/
└── logs/bin/
```

---

## 🏗️ Package Structure for .deb

```
xsoc_<version>/
├── DEBIAN/
│   ├── control
│   ├── postinst
│   └── prerm
├── opt/
│   └── xsoc/
├── etc/
│   └── systemd/system/
│       └── xsoc.service
```

> The version is auto-generated from the latest Git tag.

---

## ❤️ Credits

Built for DIY Home Security & Edge AI Enthusiasts.

---

> "Secure the Edge, Empower the Future." ⚡
>
![hookprobe budget](../../images/xSOC-HLD-v1.3.png)
