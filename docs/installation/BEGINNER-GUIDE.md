# HookProbe Beginner's Guide - Linux Installation & Deployment

## 🎯 Complete Guide for Linux Beginners

This guide will walk you through **everything** you need to deploy HookProbe, even if you've never used Linux before.

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Hardware Requirements](#hardware-requirements)
3. [Choosing Your Linux Distribution](#choosing-your-linux-distribution)
4. [Downloading Linux](#downloading-linux)
5. [Creating Bootable USB](#creating-bootable-usb)
6. [Installing Linux](#installing-linux)
7. [Post-Installation Setup](#post-installation-setup)
8. [Installing HookProbe](#installing-hookprobe)
9. [Troubleshooting](#troubleshooting)

---

## Overview

### What You'll Do

1. **Download** a Linux distribution (free operating system)
2. **Create** a bootable USB drive
3. **Install** Linux on your hardware
4. **Configure** basic network settings
5. **Install** HookProbe with one command

**Time Required:** 1-2 hours (including downloads)

**Difficulty:** Beginner-friendly with step-by-step instructions

---

## Hardware Requirements

### Minimum Hardware for HookProbe

| Component | Minimum | Recommended | Best |
|-----------|---------|-------------|------|
| **CPU** | Intel N100 (4 cores) | Intel N100 | Intel Xeon/AMD EPYC |
| **RAM** | 8GB | 16GB | 32GB+ |
| **Storage** | 256GB SSD | 500GB SSD | 1TB+ NVMe SSD |
| **Network** | 1Gbps NIC | 2.5Gbps (Intel I226) | 10Gbps+ |

### Recommended Hardware Platforms

**Budget Option (~$150-300):**
- Intel N100 Mini PC (Beelink, GMKtec, etc.)
- 8-16GB RAM
- 256-500GB SSD
- Perfect for home/small office

**Enterprise Option ($500+):**
- Dell OptiPlex, HP EliteDesk
- Intel Core i5/i7 or equivalent
- 16-32GB RAM
- 500GB+ SSD
- Multiple NICs

---

## Choosing Your Linux Distribution

HookProbe supports two Linux families:

### Option 1: Fedora (RHEL-based) - Recommended for Beginners

**Why Choose Fedora:**
- ✅ Easy installation wizard
- ✅ Automatic hardware detection
- ✅ Modern software versions
- ✅ Great for Intel N100 and newer hardware
- ✅ Strong community support
- ✅ Free and open source

**Best For:** Intel N100, modern hardware, beginners

### Option 2: Ubuntu (Debian-based) - Most Popular

**Why Choose Ubuntu:**
- ✅ Largest community (most help available online)
- ✅ Extensive documentation
- ✅ Long-term support (LTS) versions
- ✅ Compatible with most hardware
- ✅ Free and open source

**Best For:** Most users, maximum compatibility

### Quick Decision Guide

```
┌─────────────────────────────────────────┐
│  Do you have Intel N100 or very new    │
│  hardware (2023+)?                      │
└─────────────┬───────────────────────────┘
              │
         Yes  │  No
              │
    ┌─────────▼─────────┐
    │                   │
┌───▼────┐        ┌─────▼──────┐
│ Fedora │        │  Ubuntu    │
│   40+  │        │  22.04 LTS │
└────────┘        └────────────┘
```

---

## Downloading Linux

### Fedora Workstation (Recommended for N100)

1. **Visit:** https://fedoraproject.org/workstation/download
2. **Click:** "Download Fedora Workstation"
3. **Version:** Fedora 40 or newer
4. **File Size:** ~2-3 GB
5. **Save to:** Your Downloads folder

**Direct Link:** https://download.fedoraproject.org/pub/fedora/linux/releases/40/Workstation/x86_64/iso/

### Ubuntu Desktop (Most Popular)

1. **Visit:** https://ubuntu.com/download/desktop
2. **Click:** "Download Ubuntu 24.04 LTS"
3. **Version:** Ubuntu 24.04 LTS (Long-Term Support)
4. **File Size:** ~4-5 GB
5. **Save to:** Your Downloads folder

**Direct Link:** https://ubuntu.com/download/desktop

### Alternative: Rocky Linux (For Enterprise)

If you need enterprise-grade stability:

1. **Visit:** https://rockylinux.org/download
2. **Choose:** Rocky Linux 9.x
3. **Variant:** Minimal or DVD
4. **File Size:** ~2-10 GB (depending on variant)

---

## Creating Bootable USB

You'll need:
- **USB drive:** 8GB or larger (will be erased!)
- **USB creation tool:** Rufus (Windows) or balenaEtcher (Windows/Mac/Linux)

### Method 1: Using Rufus (Windows - Recommended)

**Step 1:** Download Rufus
- Visit: https://rufus.ie
- Download: rufus-4.x.exe
- Run: No installation needed

**Step 2:** Prepare USB Drive
1. Insert USB drive (8GB+)
2. **Backup any files** (will be erased!)

**Step 3:** Create Bootable USB
1. Open Rufus
2. **Device:** Select your USB drive
3. **Boot selection:** Click "SELECT" → Choose your Linux ISO file
4. **Partition scheme:**
   - Modern PC (2020+): GPT
   - Older PC: MBR
5. **File system:** Keep default (usually FAT32)
6. **Click:** START
7. **Wait:** 5-10 minutes

**Step 4:** Verify
- USB drive name changes to distribution name
- Rufus shows "READY"

### Method 2: Using balenaEtcher (Windows/Mac/Linux)

**Step 1:** Download balenaEtcher
- Visit: https://etcher.balena.io
- Download for your OS
- Install the application

**Step 2:** Flash USB Drive
1. Open balenaEtcher
2. **Flash from file:** Select your Linux ISO
3. **Select target:** Choose your USB drive
4. **Flash!** Click to start
5. **Wait:** 5-10 minutes

---

## Installing Linux

### BIOS/UEFI Settings (Before Installation)

**Step 1:** Enter BIOS/UEFI
- Restart computer
- Press key during boot:
  - **Dell:** F2 or F12
  - **HP:** F10 or Esc
  - **Lenovo:** F1 or F2
  - **Intel NUC/N100:** F2
  - **Generic:** Del, F2, F10, or F12

**Step 2:** Configure Boot Settings
1. **Secure Boot:** Disable (if having issues)
2. **Boot Mode:** UEFI (preferred) or Legacy
3. **Boot Order:** USB drive first
4. **Save & Exit:** F10 (usually)

### Fedora Installation (Detailed)

**Step 1:** Boot from USB
1. Insert USB drive
2. Restart computer
3. Select USB drive from boot menu
4. Choose "Start Fedora Workstation"

**Step 2:** Start Installation
1. Click "Install to Hard Drive"
2. **Language:** Select your language
3. Click "Continue"

**Step 3:** Installation Summary

**Date & Time:**
- Set your timezone
- Enable "Network Time"

**Keyboard:**
- Add your keyboard layout
- Test in the box below

**Installation Destination (IMPORTANT):**
1. Click "Installation Destination"
2. Select your hard drive
3. **Storage Configuration:**

   **Option A: Automatic (Recommended for Beginners)**
   - Select "Automatic"
   - Click "Done"
   - Fedora handles partitioning

   **Option B: Custom (For Advanced Users)**
   - See [Advanced Partitioning](#advanced-partitioning) below

**Network & Host Name:**
1. Turn on network switch
2. Set hostname: `hookprobe` or your choice
3. Click "Apply"

**Step 4:** Begin Installation
1. Click "Begin Installation"
2. Wait 10-20 minutes
3. **Create User Account:**
   - Full name: Your name
   - Username: `admin` (or your choice)
   - **Make this user administrator:** ✓ Check this!
   - Password: Create strong password
   - **WRITE DOWN YOUR PASSWORD!**

**Step 5:** Complete Installation
1. Click "Finish Installation"
2. Remove USB drive
3. Click "Restart Now"

### Ubuntu Installation (Detailed)

**Step 1:** Boot from USB
1. Insert USB drive
2. Restart computer
3. Select USB drive from boot menu
4. Choose "Try or Install Ubuntu"

**Step 2:** Welcome Screen
1. **Language:** Select your language
2. Click "Install Ubuntu"

**Step 3:** Keyboard Layout
1. Select your keyboard layout
2. Click "Continue"

**Step 4:** Updates and Other Software
1. **Installation type:**
   - ✓ Normal installation
   - ✓ Download updates while installing
   - ✓ Install third-party software
2. Click "Continue"

**Step 5:** Installation Type (IMPORTANT)

**Option A: Erase Disk (Recommended for Beginners)**
- Select "Erase disk and install Ubuntu"
- Ubuntu handles partitioning automatically
- Click "Install Now"
- Confirm: "Continue"

**Option B: Something Else (Advanced)**
- See [Advanced Partitioning](#advanced-partitioning) below

**Step 6:** Location
1. Click your location on map
2. Click "Continue"

**Step 7:** User Account
1. **Your name:** Your full name
2. **Computer name:** `hookprobe`
3. **Username:** `admin` (or your choice)
4. **Password:** Create strong password
5. **WRITE DOWN YOUR PASSWORD!**
6. Click "Continue"

**Step 8:** Installation
1. Wait 15-30 minutes
2. Remove USB drive when prompted
3. Click "Restart Now"

---

## Advanced Partitioning

### Recommended Partition Scheme for HookProbe

Only use manual partitioning if you need specific configurations.

#### For 500GB+ Drives:

| Partition | Mount Point | Size | Type | Description |
|-----------|-------------|------|------|-------------|
| **EFI** | `/boot/efi` | 512 MB | FAT32 | Boot partition (UEFI) |
| **Boot** | `/boot` | 1 GB | ext4 | Linux boot files |
| **Root** | `/` | 100 GB | ext4 | System files |
| **Var** | `/var` | 150 GB | ext4 | Logs, databases |
| **Home** | `/home` | 50 GB | ext4 | User files |
| **Data** | `/opt/hookprobe` | Remaining | ext4 | HookProbe data |
| **Swap** | `swap` | 16 GB | swap | Virtual memory |

#### For 256GB Drives (Minimum):

| Partition | Mount Point | Size | Type | Description |
|-----------|-------------|------|------|-------------|
| **EFI** | `/boot/efi` | 512 MB | FAT32 | Boot partition |
| **Boot** | `/boot` | 512 MB | ext4 | Linux boot files |
| **Root** | `/` | 80 GB | ext4 | System + var |
| **Home** | `/home` | Remaining | ext4 | User + data |
| **Swap** | `swap` | 8 GB | swap | Virtual memory |

### How to Create Partitions

**Fedora:**
1. Installation Destination → Custom
2. Click "+" to add partition
3. Enter mount point and size
4. Repeat for each partition
5. Click "Done"

**Ubuntu:**
1. Select "Something else"
2. Select drive
3. Click "New Partition Table" (erases disk!)
4. Click "+" to add partition
5. Set size, type, and mount point
6. Repeat for each partition
7. Set boot loader to `/dev/sda` (or your drive)
8. Click "Install Now"

---

## Post-Installation Setup

### First Boot

**Step 1:** Initial Setup (Fedora)
1. Login with your password
2. Complete welcome wizard:
   - Privacy settings
   - Online accounts (optional)
   - Skip tour

**Step 2:** Initial Setup (Ubuntu)
1. Login with your password
2. Complete welcome wizard:
   - Connect online accounts (optional)
   - Livepatch (optional)
   - Help improve Ubuntu (optional)

### Update Your System

**Step 1:** Open Terminal
- **Fedora:** Press `Super` key → type "Terminal"
- **Ubuntu:** Press `Ctrl+Alt+T`

**Step 2:** Update System

**Fedora:**
```bash
sudo dnf update -y
```

**Ubuntu:**
```bash
sudo apt update && sudo apt upgrade -y
```

**Step 3:** Reboot
```bash
sudo reboot
```

### Configure Network

**Step 1:** Check Network Connection
```bash
ip addr show
```

**Step 2:** Note Your IP Address
- Look for `inet` followed by IP (e.g., 192.168.1.100)
- **Write this down** - you'll need it for HookProbe!

**Step 3:** Set Static IP (Recommended)

**Fedora:**
```bash
nmcli connection show
nmcli connection modify "Wired connection 1" ipv4.addresses 192.168.1.100/24
nmcli connection modify "Wired connection 1" ipv4.gateway 192.168.1.1
nmcli connection modify "Wired connection 1" ipv4.dns "8.8.8.8 8.8.4.4"
nmcli connection modify "Wired connection 1" ipv4.method manual
nmcli connection up "Wired connection 1"
```

**Ubuntu:**
```bash
sudo nano /etc/netplan/01-netcfg.yaml
```

Add:
```yaml
network:
  version: 2
  ethernets:
    enp1s0:  # Your interface name
      dhcp4: no
      addresses: [192.168.1.100/24]
      gateway4: 192.168.1.1
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
```

Apply:
```bash
sudo netplan apply
```

### Install Essential Tools

**Fedora:**
```bash
sudo dnf install -y git curl wget htop vim
```

**Ubuntu:**
```bash
sudo apt install -y git curl wget htop vim
```

---

## Installing HookProbe

Now you're ready for HookProbe installation!

### Quick Installation

**Step 1:** Clone Repository
```bash
cd ~
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe
```

**Step 2:** Run Interactive Installer
```bash
sudo ./install.sh
```

**Step 3:** Follow the Wizard
1. Select: `1) Edge Deployment`
2. Answer configuration questions:
   - Network interface: (auto-detected)
   - Host IP: Your IP address
   - Passwords: (auto-generated securely)
3. Wait 15-20 minutes for installation

**Step 4:** Access Services
- **Grafana:** http://YOUR_IP:3000
- **Qsecbit API:** http://YOUR_IP:8888

**Congratulations! HookProbe is now running!** 🎉

---

## Troubleshooting

### Installation Issues

**Problem:** "sudo: command not found"
```bash
# Login as root
su -
# Add user to sudoers
usermod -aG wheel username  # Fedora
usermod -aG sudo username   # Ubuntu
```

**Problem:** "Cannot connect to network"
- Check ethernet cable is connected
- Try DHCP first: `sudo dhclient` (Ubuntu) or `sudo dhclient eth0` (Fedora)
- Check firewall isn't blocking

**Problem:** "USB drive not bootable"
- Recreate USB with Rufus/Etcher
- Try different USB port
- Check BIOS/UEFI settings
- Verify ISO checksum

**Problem:** "Not enough disk space"
- Minimum 256GB required
- Check available space: `df -h`
- Consider smaller partition sizes

### HookProbe Installation Issues

**Problem:** "Permission denied"
```bash
chmod +x install.sh
sudo ./install.sh
```

**Problem:** "Git not found"
```bash
# Fedora
sudo dnf install git

# Ubuntu
sudo apt install git
```

**Problem:** "Cannot access services"
- Check firewall: `sudo systemctl status firewalld` (Fedora)
- Open ports if needed
- Verify services are running: `sudo podman ps`

---

## Next Steps

After successful installation:

1. **Read the Quick Start:** [QUICK-START.md](../../QUICK-START.md)
2. **Configure Security:** [SECURITY.md](../SECURITY.md)
3. **Review GDPR Settings:** [GDPR.md](../GDPR.md)
4. **Set Up Monitoring:** Access Grafana dashboards
5. **Join Community:** Report issues, contribute

---

## Additional Resources

### Learning Resources

**Linux Basics:**
- Linux Journey: https://linuxjourney.com
- Ubuntu Tutorial: https://ubuntu.com/tutorials
- Fedora Documentation: https://docs.fedoraproject.org

**Networking:**
- Basic networking concepts
- IP addressing and subnets
- Firewall configuration

**Security:**
- Linux security basics
- User management
- File permissions

### Video Tutorials

Search YouTube for:
- "Install Fedora 40 tutorial"
- "Install Ubuntu 24.04 tutorial"
- "Linux for beginners"
- "How to create bootable USB"

### Getting Help

- **HookProbe Issues:** https://github.com/hookprobe/hookprobe/issues
- **Fedora Forums:** https://ask.fedoraproject.org
- **Ubuntu Forums:** https://ubuntuforums.org
- **Reddit:** r/linux4noobs, r/linuxquestions

---

## Quick Reference

### Essential Commands

```bash
# Update system
sudo dnf update -y              # Fedora
sudo apt update && apt upgrade  # Ubuntu

# Check disk space
df -h

# Check memory
free -h

# Check network
ip addr show

# Check running services
sudo systemctl status [service]

# View logs
journalctl -xe

# Reboot
sudo reboot

# Shutdown
sudo shutdown -h now
```

### Default Credentials

**Linux User:**
- Username: What you set during installation
- Password: What you set during installation

**HookProbe Services:**
- Credentials: Generated during installation
- Location: Check installation output

---

**Last Updated:** 2025-11-24
**Version:** 5.0
**Difficulty:** Beginner-Friendly

**Ready to start?** Download your Linux distribution and begin your HookProbe journey! 🚀
