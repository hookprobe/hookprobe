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

### Supported Platforms - We Support Your Cybersecurity Journey!

HookProbe runs on a **wide variety of hardware** - from budget SBCs to enterprise servers. Choose what fits your needs and budget!

### Minimum Requirements

| Component | Minimum | Recommended | Enterprise |
|-----------|---------|-------------|------------|
| **CPU** | 4+ cores (2020+) | 6+ cores | 8+ cores |
| **RAM** | 8GB | 16GB | 32GB+ |
| **Storage** | 256GB SSD | 500GB SSD | 1TB+ NVMe SSD |
| **Network** | 1Gbps NIC | 2.5Gbps NIC | 10Gbps+ NIC |

### Supported CPU Architectures

**x86_64 (Intel/AMD):**
- ✅ Intel N-series (N100, N200, N300, N305)
- ✅ Intel Core mobile (i3, i5, i7, i9) - 8th gen+
- ✅ Intel Core desktop (i3, i5, i7, i9) - 8th gen+
- ✅ Intel Xeon (any recent generation)
- ✅ AMD Ryzen (3000 series+)
- ✅ AMD EPYC (any generation)

**ARM64 (ARMv8):**
- ✅ Raspberry Pi 4/5 (4GB+ RAM)
- ✅ Banana Pi (BPI-R3, BPI-R4, BPI-M5, etc.)
- ✅ Nvidia Jetson (Nano, Xavier, Orin)
- ✅ Radxa (ROCK 5, ROCK 4)
- ✅ Orange Pi (5/5+)
- ✅ Odroid (N2+, C4, etc.)

**Key: Hardware released 2020 or later with focus on energy efficiency**

### Hardware Examples by Budget

#### Budget-Friendly ($100-$300)
**Perfect for: Home users, learning, small deployments**

**x86_64 Options:**
- Intel N100/N200 Mini PC (Beelink, GMKtec, Trigkey)
  - 8-16GB RAM
  - Built-in 2.5Gbps NIC
  - ~15W power consumption
  - **Best value for beginners!**

- Intel NUC 11/12/13 (used/refurbished)
  - Core i3/i5
  - 8-16GB RAM
  - Low power, compact

**ARM64 Options:**
- Raspberry Pi 5 (8GB)
  - $80-100
  - Great community support
  - Perfect for learning

- Banana Pi BPI-R3
  - $100-150
  - Built-in 2.5Gbps
  - M.2 slot for expansion

#### Mid-Range ($300-$700)
**Perfect for: Small business, branch offices, enthusiasts**

**x86_64 Options:**
- Intel NUC 12/13/14 (new)
  - Core i5/i7
  - 16-32GB RAM
  - Thunderbolt, multiple displays
  - 25-65W power consumption

- Mini PC with Intel Core i5-12th gen+
  - 16-32GB RAM
  - Dual 2.5Gbps NICs
  - NVMe storage

- Dell OptiPlex Micro (refurbished)
- HP EliteDesk Mini (refurbished)

**ARM64 Options:**
- Nvidia Jetson Orin Nano
  - GPU acceleration
  - AI workloads
  - 8GB RAM

- Radxa ROCK 5B
  - 8-16GB RAM
  - PCIe 3.0
  - M.2 NVMe

#### Enterprise ($700+)
**Perfect for: MSSP, large deployments, production**

**x86_64 Options:**
- Dell PowerEdge (R340, R440, R640)
- HP ProLiant (DL20, DL360)
- Intel Xeon servers
- AMD EPYC servers
- Dual 10Gbps+ NICs
- ECC RAM
- Hardware RAID

**ARM64 Options:**
- Nvidia Jetson AGX Orin
  - Up to 64GB RAM
  - Enterprise-grade
  - GPU acceleration

### Platform-Specific Advantages

#### Intel N-Series (N100, N200, N300)
- ✅ **Excellent price/performance**
- ✅ Low power (15W)
- ✅ Built-in Intel I226 NIC (2.5Gbps)
- ✅ Full XDP/eBPF support
- ✅ Perfect for beginners
- ⚠️ Entry-level (good for most home/small business)

#### Intel Core i3/i5/i7 (8th gen+)
- ✅ **Better performance** than N-series
- ✅ More cores/threads
- ✅ Better for multiple VMs
- ✅ Great for small-medium business
- ⚠️ Higher power consumption (35-65W)

#### Intel NUC
- ✅ **Compact and reliable**
- ✅ Thunderbolt support
- ✅ Multiple display outputs
- ✅ Excellent Linux support
- ✅ Great for enthusiasts

#### Raspberry Pi
- ✅ **Largest community**
- ✅ Most tutorials available
- ✅ Very affordable
- ✅ Perfect for learning
- ⚠️ ARM architecture (some limitations)
- ⚠️ Generic XDP mode (not hardware-accelerated)

#### Banana Pi / Radxa / Orange Pi
- ✅ **More powerful** than Raspberry Pi
- ✅ Built-in networking features
- ✅ M.2/PCIe expansion
- ✅ Good ARM alternative
- ⚠️ Smaller community than Raspberry Pi

#### Nvidia Jetson
- ✅ **GPU acceleration**
- ✅ AI/ML workloads
- ✅ Computer vision support
- ✅ Great for advanced projects
- ⚠️ Higher cost
- ⚠️ More complex setup

### Quick Decision Guide

```
Budget?
├─ Under $200
│  ├─ Want x86_64? → Intel N100 Mini PC ✓
│  └─ Want ARM64? → Raspberry Pi 5 (8GB) ✓
│
├─ $200-$500
│  ├─ Want x86_64? → Intel NUC 12/13 (i5) ✓
│  └─ Want ARM64? → Banana Pi BPI-R3 / Radxa ROCK 5B ✓
│
└─ $500+
   ├─ Want x86_64? → Dell/HP Enterprise / Intel Xeon ✓
   └─ Want ARM64? → Nvidia Jetson Orin ✓

Need AI/ML? → Nvidia Jetson ✓
Need lowest power? → Intel N100 / Raspberry Pi ✓
Need best performance? → Intel Xeon / AMD EPYC ✓
Need most support? → Raspberry Pi / Intel NUC ✓
```

### Platform Compatibility Matrix

| Feature | Intel x86 | AMD x86 | Raspberry Pi | Other ARM | Nvidia Jetson |
|---------|-----------|---------|--------------|-----------|---------------|
| **Basic HookProbe** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| **XDP Hardware Mode** | ✅ Yes* | ✅ Yes* | ⚠️ Generic | ⚠️ Generic | ⚠️ Generic |
| **Podman Containers** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| **All 7 PODs** | ✅ Yes | ✅ Yes | ✅ Yes** | ✅ Yes** | ✅ Yes |
| **Energy Monitoring** | ✅ RAPL | ✅ RAPL | ⚠️ Limited | ⚠️ Limited | ⚠️ Limited |
| **GPU Acceleration** | ⚠️ Limited | ⚠️ Limited | ❌ No | ❌ No | ✅ Yes |

\* With Intel I226/I211 or compatible NIC
\** May need 8GB+ RAM for all PODs

**Bottom Line: Any modern hardware (2020+) with 8GB+ RAM will work!**

---

## Choosing Your Linux Distribution

HookProbe v5.x supports **Debian-based systems only**:

### Ubuntu (Recommended)

**Why Choose Ubuntu:**
- ✅ Largest community (most help available online)
- ✅ Extensive documentation
- ✅ Long-term support (LTS) versions
- ✅ Compatible with most hardware
- ✅ OpenVSwitch fully supported
- ✅ Free and open source

**Best For:** Most users, maximum compatibility

**Supported versions**: Ubuntu 22.04 LTS, Ubuntu 24.04 LTS

### Debian

**Why Choose Debian:**
- ✅ Rock-solid stability
- ✅ Minimal bloat
- ✅ Long-term support
- ✅ Great for servers

**Supported versions**: Debian 11 (Bullseye), Debian 12 (Bookworm)

### Raspberry Pi OS

**For ARM64 devices:**
- ✅ Optimized for Raspberry Pi 4/5
- ✅ Based on Debian
- ✅ Easy to flash and setup

**Supported version**: Raspberry Pi OS (Bookworm, 64-bit)

> **Note**: RHEL-based systems (Fedora, CentOS, Rocky, RHEL) are not supported due to OpenVSwitch availability limitations. Support planned for future release.

### Quick Decision Guide

```
┌─────────────────────────────────────────┐
│  What hardware are you using?           │
└─────────────┬───────────────────────────┘
              │
   Raspberry  │  Intel/AMD
   Pi 4/5     │  (N100, etc)
              │
    ┌─────────▼─────────┐
    │                   │
┌───▼────────┐    ┌─────▼──────┐
│ RPi OS     │    │  Ubuntu    │
│ (Bookworm) │    │  22.04 LTS │
└────────────┘    └────────────┘
```

---

## Downloading Linux

### Ubuntu Desktop (Recommended)

1. **Visit:** https://ubuntu.com/download/desktop
2. **Click:** "Download Ubuntu 22.04 LTS" or "24.04 LTS"
3. **File Size:** ~5 GB
4. **Save to:** Your Downloads folder

**Direct Link:** https://ubuntu.com/download/desktop

### Raspberry Pi OS (For Raspberry Pi 4/5)

1. **Visit:** https://www.raspberrypi.com/software/operating-systems/
2. **Click:** "Raspberry Pi OS (64-bit)"
3. **Version:** Bookworm (latest)
4. **File Size:** ~1 GB
5. **Use:** Raspberry Pi Imager for easy flashing

**Direct Link:** https://www.raspberrypi.com/software/

### Debian (For Servers)

If you need maximum stability:

1. **Visit:** https://www.debian.org/download
2. **Choose:** Debian 12 (Bookworm)
3. **Variant:** netinst or DVD
4. **File Size:** ~400 MB - 4 GB

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

### Ubuntu Installation (Detailed)

**Step 1:** Boot from USB
1. Insert USB drive
2. Restart computer
3. Select USB drive from boot menu
4. Choose "Try or Install Ubuntu"

**Step 2:** Start Installation
1. Click "Install Ubuntu"
2. **Language:** Select your language
3. Click "Continue"

**Step 3:** Installation Options

**Keyboard Layout:**
- Select your keyboard layout
- Test in the box below
- Click "Continue"

**Installation Type (IMPORTANT):**
1. Select "Normal installation"
2. Check "Download updates while installing"
3. Check "Install third-party software..."

**Disk Setup:**

   **Option A: Erase Disk (Recommended for Beginners)**
   - Select "Erase disk and install Ubuntu"
   - Click "Install Now"
   - Ubuntu handles partitioning automatically

   **Option B: Custom (For Advanced Users)**
   - Select "Something else"
   - See [Advanced Partitioning](#advanced-partitioning) below

**Step 4:** Configure System
1. **Timezone:** Select your location on map
2. **Your Details:**
   - Your name: Enter your name
   - Computer name: `hookprobe` or your choice
   - Username: `admin` (or your choice)
   - Password: Create strong password
   - **WRITE DOWN YOUR PASSWORD!**

**Step 5:** Complete Installation
1. Wait 10-20 minutes
2. Click "Restart Now"
3. Remove USB drive when prompted
4. Press Enter to continue

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

**Step 1:** Initial Setup
1. Login with your password
2. Complete welcome wizard:
   - Connect online accounts (optional)
   - Livepatch (optional)
   - Help improve Ubuntu (optional)

### Update Your System

**Step 1:** Open Terminal
- Press `Ctrl+Alt+T` (or search for "Terminal" in applications)

**Step 2:** Update System

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
usermod -aG sudo username
```

**Problem:** "Cannot connect to network"
- Check ethernet cable is connected
- Try DHCP first: `sudo dhclient`
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
sudo apt install git
```

**Problem:** "Cannot access services"
- Check firewall: `sudo ufw status`
- Open ports if needed: `sudo ufw allow 3000/tcp`
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
- Debian Documentation: https://www.debian.org/doc/

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
- "Install Ubuntu 24.04 tutorial"
- "Install Debian 12 tutorial"
- "Linux for beginners"
- "How to create bootable USB"

### Getting Help

- **HookProbe Issues:** https://github.com/hookprobe/hookprobe/issues
- **Ubuntu Forums:** https://ubuntuforums.org
- **Debian Forums:** https://forums.debian.net
- **Reddit:** r/linux4noobs, r/linuxquestions

---

## Quick Reference

### Essential Commands

```bash
# Update system
sudo apt update && sudo apt upgrade -y

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
