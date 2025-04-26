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
[![hookprobe budget](images/xSOC-HLD-v1.3.png)](/Documents/SecurityMitigationPlan.md)
