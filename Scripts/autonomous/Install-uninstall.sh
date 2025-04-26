#!/bin/bash
# xSOC Edge Router Full Auto Deployment Script
# Ubuntu 24.04 + Podman + Cloudflare + Suricata + AI/ML IDS + Podman GUI (Cockpit)

set -e

############################
# System Preparation
############################
echo "[INFO] Updating System..."
sudo apt update && sudo apt upgrade -y

# Install necessary packages
echo "[INFO] Installing Core Packages..."
sudo apt install -y podman podman-compose net-tools iproute2 suricata sqlite3 nginx python3 python3-pip curl cockpit cockpit-podman ufw

# PostgreSQL install
echo "[INFO] Installing PostgreSQL..."
sudo apt install -y postgresql postgresql-contrib

# Start Cockpit GUI
echo "[INFO] Enabling Podman GUI..."
sudo systemctl enable --now cockpit.socket

############################
# Firewall Rules
############################
echo "[INFO] Setting up Firewall Rules..."
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 9090/tcp    # Cockpit GUI
sudo ufw allow 5000/tcp    # AI/ML Packet Analyzer
sudo ufw allow 8080/tcp    # cAdvisor
sudo ufw allow from 172.28.1.0/24 to any port 80
sudo ufw allow from 172.28.1.0/24 to any port 443
sudo ufw enable

############################
# Cloudflare Tunnel Setup
############################
echo "[INFO] Installing and Configuring Cloudflare Tunnel..."
sudo mkdir -p /etc/cloudflared
sudo curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o cloudflared.deb
sudo dpkg -i cloudflared.deb
rm cloudflared.deb

sudo cloudflared tunnel login
sudo cloudflared tunnel create xsoc-tunnel

############################
# Directory Structure
############################
echo "[INFO] Creating Directory Structure..."
sudo mkdir -p /opt/xsoc/{cloudflared,suricata,persistentdb,transientdb,webapp/nginx,webapp/django,webapp/gunicorn,ai-ml/packet-analyser,monitoring,vxlan,logs/bin}
sudo chown -R $USER:$USER /opt/xsoc

############################
# Podman Compose Setup
############################
echo "[INFO] Creating Podman Compose File..."
cat <<EOF > /opt/xsoc/podman-compose.yml
version: '3.8'
services:
  suricata:
    image: docker.io/jasonish/suricata:latest
    network_mode: "host"
    cap_add:
      - NET_ADMIN
    volumes:
      - /opt/xsoc/suricata:/var/log/suricata
    command: -i wan0

  cloudflared:
    image: docker.io/cloudflare/cloudflared:latest
    network_mode: "host"
    volumes:
      - /etc/cloudflared:/etc/cloudflared
    command: tunnel run

  ai-packet-analyser:
    image: docker.io/python:3
    ports:
      - "5000:5000"
    volumes:
      - /opt/xsoc/ai-ml/packet-analyser:/app
      - /opt/xsoc/suricata:/var/log/suricata
    command: bash -c "pip install flask scikit-learn && python /app/app.py"

  container-monitoring:
    image: docker.io/google/cadvisor:latest
    ports:
      - "8080:8080"

  django-webapp:
    image: docker.io/python:3
    ports:
      - "8000:8000"
    volumes:
      - /opt/xsoc/webapp/django:/app
    command: bash -c "pip install django gunicorn psycopg2 && cd /app && gunicorn xsocweb.wsgi:application --bind 0.0.0.0:8000"
EOF

############################
# Create AI/ML Packet Analyzer
############################
echo "[INFO] Setting up AI/ML Packet Analyzer..."
cat <<EOF > /opt/xsoc/ai-ml/packet-analyser/app.py
from flask import Flask, jsonify
import json
import os
from sklearn.ensemble import IsolationForest

app = Flask(__name__)

@app.route('/')
def index():
    return "AI/ML Packet Analyzer Running!"

@app.route('/detect')
def detect():
    try:
        eve_path = '/var/log/suricata/eve.json'
        if not os.path.exists(eve_path):
            return jsonify({'error': 'Suricata logs not found'}), 404

        data = []
        with open(eve_path, 'r') as f:
            for line in f:
                record = json.loads(line)
                if 'alert' in record:
                    data.append([record['alert']['severity'], record.get('flow_id', 0)])

        if len(data) < 10:
            return jsonify({'warning': 'Not enough packet data yet.'})

        model = IsolationForest(contamination=0.1)
        model.fit(data)
        preds = model.predict(data)
        anomalies = preds.tolist().count(-1)

        return jsonify({'total_packets': len(data), 'anomalies_detected': anomalies})

    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
EOF

############################
# Scaffold Django Web App
############################
echo "[INFO] Creating Django App..."
cd /opt/xsoc/webapp/django
python3 -m venv venv
source venv/bin/activate
pip install django psycopg2 gunicorn

django-admin startproject xsocweb .

sed -i "s/ALLOWED_HOSTS = \[\]/ALLOWED_HOSTS = ['*']/" xsocweb/settings.py
sed -i "s/'ENGINE': 'django.db.backends.sqlite3'/'ENGINE': 'django.db.backends.postgresql'/" xsocweb/settings.py
sed -i "s/'NAME': BASE_DIR / 'db.sqlite3'/'NAME': 'xsocdb', 'USER': 'postgres', 'PASSWORD': '', 'HOST': 'localhost', 'PORT': '5432'/" xsocweb/settings.py

# Create system dashboard app
python manage.py startapp dashboard

cat <<EOF > dashboard/views.py
from django.shortcuts import render
import psutil

def home(request):
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    context = {'cpu': cpu, 'memory': memory, 'disk': disk}
    return render(request, 'dashboard/home.html', context)
EOF

mkdir -p dashboard/templates/dashboard

cat <<EOF > dashboard/templates/dashboard/home.html
<!DOCTYPE html>
<html>
<head>
    <title>xSOC Dashboard</title>
    <script>
      setInterval(function() { window.location.reload(); }, 5000);
    </script>
</head>
<body>
    <h1>System Dashboard (Auto-Refresh Every 5s)</h1>
    <ul>
        <li>CPU Usage: {{ cpu }}%</li>
        <li>Memory Usage: {{ memory }}%</li>
        <li>Disk Usage: {{ disk }}%</li>
    </ul>
</body>
</html>
EOF

# Add dashboard to settings.py
sed -i "/INSTALLED_APPS = \[/a \\    'dashboard'," xsocweb/settings.py

# Update urls.py
cat <<EOF > xsocweb/urls.py
from django.contrib import admin
from django.urls import path
from dashboard.views import home

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', home, name='home'),
]
EOF

python manage.py migrate
python manage.py collectstatic --noinput

############################
# Systemd Service Setup
############################
echo "[INFO] Creating Systemd Service..."
cat <<EOF | sudo tee /etc/systemd/system/xsoc.service
[Unit]
Description=xSOC Edge Stack
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/opt/xsoc
ExecStart=/usr/bin/podman-compose -f /opt/xsoc/podman-compose.yml up
ExecStop=/usr/bin/podman-compose -f /opt/xsoc/podman-compose.yml down
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable xsoc

############################
# Database Initialization
############################
echo "[INFO] Initializing Databases..."
sudo -u postgres psql -c "CREATE DATABASE xsocdb;"
sqlite3 /opt/xsoc/transientdb/xsoc_transient.db "VACUUM;"

############################
# VXLAN Setup Script
############################
echo "[INFO] Creating VXLAN Setup Script..."
cat <<EOF > /opt/xsoc/vxlan/vxlan-setup.sh
#!/bin/bash
ip link add vxlan0 type vxlan id 42 dev eth0 dstport 4789
ip addr add 172.28.1.1/24 dev vxlan0
ip link set up dev vxlan0
EOF
chmod +x /opt/xsoc/vxlan/vxlan-setup.sh

############################
# Uninstall Script
############################
echo "[INFO] Creating Uninstall Script..."
cat <<EOF > /opt/xsoc/uninstall-xsoc.sh
#!/bin/bash

read -p "Are you sure you want to remove xSOC and all related services? (y/n): " confirm
if [[ \$confirm != "y" ]]; then
  echo "Uninstall cancelled."
  exit 0
fi

sudo systemctl stop xsoc
sudo systemctl disable xsoc
sudo rm -f /etc/systemd/system/xsoc.service
sudo systemctl daemon-reload

sudo ufw delete allow ssh
sudo ufw delete allow 9090/tcp
sudo ufw delete allow 5000/tcp
sudo ufw delete allow 8080/tcp
sudo ufw disable

sudo rm -rf /opt/xsoc
sudo rm -rf /etc/cloudflared
sudo apt remove --purge -y podman podman-compose suricata nginx sqlite3 postgresql postgresql-contrib cockpit cockpit-podman ufw
sudo apt autoremove -y

echo "xSOC Uninstalled Successfully."
EOF
chmod +x /opt/xsoc/uninstall-xsoc.sh

############################
# Completion Message
############################
echo "[SUCCESS] xSOC AI Router Fully Deployed!"
echo "Commands to start everything:"
echo "  sudo systemctl start xsoc"
echo "  sudo bash /opt/xsoc/vxlan/vxlan-setup.sh"
echo "  sudo bash /opt/xsoc/uninstall-xsoc.sh  # to remove everything"
echo "Access Points:"
echo "- Web Cockpit Podman GUI: https://LAN-IP:9090"
echo "- AI Packet Analyzer API: http://LAN-IP:5000/detect"
echo "- Django WebApp Dashboard: http://LAN-IP:8000"
echo "- cAdvisor Monitoring: http://LAN-IP:8080"

exit 0
