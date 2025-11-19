How to Use:


# 1. Edit network-config.sh with your environment details
nano network-config.sh

# 2. Make scripts executable
chmod +x network-config.sh setup.sh uninstall.sh

# 3. Run the setup (as root)
sudo ./setup.sh

# 4. Access your Django CMS
# http://YOUR_IP/admin
# Username: admin
# Password: admin
What Happens During Setup:

✅ Validates environment and installs dependencies
✅ Creates OVS bridges with encrypted VXLAN tunnels
✅ Configures firewall rules
✅ Creates isolated Podman networks for each POD
✅ Deploys PostgreSQL database (POD 003)
✅ Deploys Redis cache (POD 004)
✅ Builds Django CMS application
✅ Deploys Django + Nginx in DMZ (POD 001)
✅ Sets up IDS/IPS (POD 006)
✅ Creates monitoring infrastructure (POD 005)
