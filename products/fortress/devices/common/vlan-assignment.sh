#!/bin/bash
# ============================================================
# HookProbe Fortress - VLAN Assignment Manager
# ============================================================
# Manages vendor/OUI-based VLAN assignment for FreeRADIUS and hostapd
#
# Features:
#   - OUI (vendor) based VLAN auto-assignment
#   - FreeRADIUS authorize file generation
#   - hostapd accept_mac file generation
#   - MAC-to-VLAN database management
#
# VLAN Assignment Strategy:
#   10 - Management (admin laptops/phones, network equipment)
#   20 - POS (payment terminals, POS vendors)
#   30 - Staff (employee devices - Apple, Samsung, Google, Dell, HP)
#   40 - Guest (unknown devices - default)
#   99 - IoT (cameras, sensors, smart home devices)
# ============================================================

set -e

# ============================================================
# CONFIGURATION
# ============================================================
FORTRESS_ETC="${FORTRESS_ETC:-/etc/fortress}"
FORTRESS_DATA="${FORTRESS_DATA:-/var/lib/fortress}"
RADIUS_DIR="${RADIUS_DIR:-/etc/freeradius/3.0}"
HOSTAPD_DIR="${HOSTAPD_DIR:-/etc/hostapd}"

MAC_VLAN_DB="$FORTRESS_ETC/mac_vlan.json"
OUI_RULES_FILE="$FORTRESS_ETC/oui_vlan_rules.conf"
RADIUS_AUTHORIZE="$RADIUS_DIR/mods-config/files/authorize"
HOSTAPD_ACCEPT_MAC="$HOSTAPD_DIR/accept_mac"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ============================================================
# OUI DATABASE - VENDOR TO VLAN MAPPING
# ============================================================
# Format: OUI_PREFIX:VLAN_ID:VENDOR_NAME
#
# OUI = First 3 bytes of MAC address (e.g., 00:1C:B3)

generate_oui_rules() {
    log_info "Generating OUI-based VLAN rules..."

    mkdir -p "$FORTRESS_ETC"

    cat > "$OUI_RULES_FILE" << 'OUIEOF'
# HookProbe Fortress - OUI to VLAN Assignment Rules
# Format: OUI_PREFIX:VLAN_ID:VENDOR_NAME
# OUI = First 3 bytes of MAC (uppercase, colon-separated)
#
# VLAN Assignments:
#   10 - Management (network infrastructure)
#   20 - POS (payment devices)
#   30 - Staff (consumer devices - Apple, Samsung, Google, etc.)
#   40 - Guest (unknown - default)
#   99 - IoT (cameras, smart home, sensors)

# ============================================================
# VLAN 10 - MANAGEMENT (Network Infrastructure)
# ============================================================
# Cisco
00:00:0C:10:Cisco
00:01:42:10:Cisco
00:01:43:10:Cisco
00:01:63:10:Cisco
00:01:64:10:Cisco
00:01:96:10:Cisco
00:02:3D:10:Cisco
00:02:4A:10:Cisco
00:02:4B:10:Cisco
00:02:7D:10:Cisco
00:02:7E:10:Cisco
00:02:B9:10:Cisco
00:02:FC:10:Cisco
00:03:31:10:Cisco
00:03:32:10:Cisco
00:03:6B:10:Cisco
00:03:9F:10:Cisco
00:03:E3:10:Cisco
00:03:E4:10:Cisco
00:03:FD:10:Cisco
00:03:FE:10:Cisco

# Ubiquiti
00:27:22:10:Ubiquiti
04:18:D6:10:Ubiquiti
24:5A:4C:10:Ubiquiti
44:D9:E7:10:Ubiquiti
68:72:51:10:Ubiquiti
74:83:C2:10:Ubiquiti
78:8A:20:10:Ubiquiti
80:2A:A8:10:Ubiquiti
B4:FB:E4:10:Ubiquiti
DC:9F:DB:10:Ubiquiti
F0:9F:C2:10:Ubiquiti
FC:EC:DA:10:Ubiquiti

# MikroTik
48:8F:5A:10:MikroTik
4C:5E:0C:10:MikroTik
6C:3B:6B:10:MikroTik
74:4D:28:10:MikroTik
B8:69:F4:10:MikroTik
C4:AD:34:10:MikroTik
CC:2D:E0:10:MikroTik
D4:01:C3:10:MikroTik
DC:2C:6E:10:MikroTik
E4:8D:8C:10:MikroTik

# Aruba Networks
00:0B:86:10:Aruba
00:1A:1E:10:Aruba
00:24:6C:10:Aruba
04:BD:88:10:Aruba
18:64:72:10:Aruba
20:4C:03:10:Aruba
24:DE:C6:10:Aruba
40:E3:D6:10:Aruba
6C:F3:7F:10:Aruba
9C:1C:12:10:Aruba
AC:A3:1E:10:Aruba
D8:C7:C8:10:Aruba

# ============================================================
# VLAN 20 - POS (Payment/Point of Sale)
# ============================================================
# Verifone
00:1C:C5:20:Verifone
00:23:C8:20:Verifone
00:26:76:20:Verifone
1C:87:76:20:Verifone
5C:1F:05:20:Verifone

# Ingenico
00:07:81:20:Ingenico
00:14:C9:20:Ingenico
00:1A:44:20:Ingenico
00:1E:13:20:Ingenico
2C:BE:08:20:Ingenico
40:F4:FD:20:Ingenico
64:64:4A:20:Ingenico
90:4E:2B:20:Ingenico
E0:B9:E5:20:Ingenico
F0:22:1D:20:Ingenico

# Square
58:D5:6E:20:Square

# Clover/First Data
00:0E:6A:20:First-Data

# PAX Technology
00:1E:E5:20:PAX
00:26:B8:20:PAX
98:DA:C4:20:PAX
B4:AB:2C:20:PAX

# NCR
00:10:20:20:NCR
00:1C:5E:20:NCR
00:21:93:20:NCR
00:60:E0:20:NCR

# Zebra/Symbol (Barcode scanners, POS)
00:15:70:20:Zebra
00:17:23:20:Zebra
00:1B:B1:20:Zebra
00:22:58:20:Zebra
00:23:68:20:Zebra
00:A0:F8:20:Zebra
8C:C8:4B:20:Zebra
AC:3F:A4:20:Zebra

# ============================================================
# VLAN 30 - STAFF (Consumer Devices)
# ============================================================
# Apple
00:03:93:30:Apple
00:0A:27:30:Apple
00:0A:95:30:Apple
00:0D:93:30:Apple
00:10:FA:30:Apple
00:11:24:30:Apple
00:14:51:30:Apple
00:16:CB:30:Apple
00:17:F2:30:Apple
00:19:E3:30:Apple
00:1B:63:30:Apple
00:1C:B3:30:Apple
00:1D:4F:30:Apple
00:1E:52:30:Apple
00:1E:C2:30:Apple
00:1F:5B:30:Apple
00:1F:F3:30:Apple
00:21:E9:30:Apple
00:22:41:30:Apple
00:23:12:30:Apple
00:23:32:30:Apple
00:23:6C:30:Apple
00:23:DF:30:Apple
00:24:36:30:Apple
00:25:00:30:Apple
00:25:4B:30:Apple
00:25:BC:30:Apple
00:26:08:30:Apple
00:26:4A:30:Apple
00:26:B0:30:Apple
00:26:BB:30:Apple
3C:06:30:30:Apple
3C:07:54:30:Apple
40:30:04:30:Apple
40:33:1A:30:Apple
44:2A:60:30:Apple
48:60:BC:30:Apple
54:26:96:30:Apple
54:4E:90:30:Apple
58:55:CA:30:Apple
5C:59:48:30:Apple
60:69:44:30:Apple
68:5B:35:30:Apple
6C:94:F8:30:Apple
70:DE:E2:30:Apple
78:31:C1:30:Apple
78:CA:39:30:Apple
7C:6D:62:30:Apple
84:38:35:30:Apple
8C:2D:AA:30:Apple
8C:85:90:30:Apple
8C:FA:BA:30:Apple
90:84:0D:30:Apple
9C:04:EB:30:Apple
9C:F3:87:30:Apple
A4:5E:60:30:Apple
A4:B1:97:30:Apple
AC:BC:32:30:Apple
B0:34:95:30:Apple
B8:09:8A:30:Apple
B8:17:C2:30:Apple
B8:C7:5D:30:Apple
BC:52:B7:30:Apple
C0:84:7A:30:Apple
C8:2A:14:30:Apple
D0:03:4B:30:Apple
D4:9A:20:30:Apple
DC:2B:2A:30:Apple
E0:B9:BA:30:Apple
E0:C7:67:30:Apple
F0:B4:79:30:Apple
F4:5C:89:30:Apple
F8:1E:DF:30:Apple

# Samsung
00:00:F0:30:Samsung
00:07:AB:30:Samsung
00:09:18:30:Samsung
00:12:47:30:Samsung
00:12:FB:30:Samsung
00:13:77:30:Samsung
00:15:99:30:Samsung
00:15:B9:30:Samsung
00:16:32:30:Samsung
00:16:6B:30:Samsung
00:16:6C:30:Samsung
00:17:C9:30:Samsung
00:17:D5:30:Samsung
00:18:AF:30:Samsung
00:1A:8A:30:Samsung
00:1B:98:30:Samsung
00:1C:43:30:Samsung
00:1D:25:30:Samsung
00:1D:F6:30:Samsung
00:1E:7D:30:Samsung
00:1F:CC:30:Samsung
00:21:4C:30:Samsung
00:21:D1:30:Samsung
00:21:D2:30:Samsung
00:24:54:30:Samsung
00:24:91:30:Samsung
00:24:E9:30:Samsung
00:25:66:30:Samsung
00:26:37:30:Samsung
08:37:3D:30:Samsung
08:D4:2B:30:Samsung
10:1D:C0:30:Samsung
14:49:E0:30:Samsung
18:67:B0:30:Samsung
1C:66:AA:30:Samsung
24:4B:81:30:Samsung
28:27:BF:30:Samsung
30:96:FB:30:Samsung
34:23:BA:30:Samsung
38:01:97:30:Samsung
40:0E:85:30:Samsung
44:4E:1A:30:Samsung
4C:BC:A5:30:Samsung
50:01:D9:30:Samsung
50:A4:D0:30:Samsung
54:88:0E:30:Samsung
58:C3:8B:30:Samsung
5C:0A:5B:30:Samsung
60:A1:0A:30:Samsung
64:B3:10:30:Samsung
68:48:98:30:Samsung
6C:2F:2C:30:Samsung
70:F9:27:30:Samsung
74:45:8A:30:Samsung
78:00:9E:30:Samsung
7C:0B:C6:30:Samsung
84:38:38:30:Samsung
88:32:9B:30:Samsung
8C:71:F8:30:Samsung
90:F1:AA:30:Samsung
94:01:C2:30:Samsung
98:52:B1:30:Samsung
9C:02:98:30:Samsung
A0:0B:BA:30:Samsung
A4:07:B6:30:Samsung
AC:5F:3E:30:Samsung
B0:47:BF:30:Samsung
B4:3A:28:30:Samsung
B8:5A:73:30:Samsung
BC:14:85:30:Samsung
C0:BD:D1:30:Samsung
C4:42:02:30:Samsung
C8:BA:94:30:Samsung
CC:07:AB:30:Samsung
D0:22:BE:30:Samsung
D4:87:D8:30:Samsung
D8:90:E8:30:Samsung
E4:12:1D:30:Samsung
E8:50:8B:30:Samsung
EC:1F:72:30:Samsung
F0:25:B7:30:Samsung
F4:7B:5E:30:Samsung
F8:04:2E:30:Samsung
FC:A1:3E:30:Samsung

# Google (Pixel phones, Chromebooks)
3C:5A:B4:30:Google
54:60:09:30:Google
58:CB:52:30:Google
6C:AD:F8:30:Google
94:94:26:30:Google
94:EB:2C:30:Google
98:D2:93:30:Google
A4:77:33:30:Google
F4:F5:D8:30:Google
F4:F5:E8:30:Google
F8:8F:CA:30:Google

# Dell (Laptops)
00:06:5B:30:Dell
00:08:74:30:Dell
00:0B:DB:30:Dell
00:0D:56:30:Dell
00:0F:1F:30:Dell
00:11:43:30:Dell
00:12:3F:30:Dell
00:13:72:30:Dell
00:14:22:30:Dell
00:15:C5:30:Dell
00:18:8B:30:Dell
00:19:B9:30:Dell
00:1A:A0:30:Dell
00:1C:23:30:Dell
00:1D:09:30:Dell
00:1E:4F:30:Dell
00:1E:C9:30:Dell
00:21:70:30:Dell
00:21:9B:30:Dell
00:22:19:30:Dell
00:24:E8:30:Dell
00:25:64:30:Dell
00:26:B9:30:Dell
14:18:77:30:Dell
14:9E:CF:30:Dell
14:FE:B5:30:Dell
18:03:73:30:Dell
18:DB:F2:30:Dell
1C:40:24:30:Dell
24:B6:FD:30:Dell
28:F1:0E:30:Dell
34:17:EB:30:Dell
34:E6:D7:30:Dell
44:A8:42:30:Dell
54:9F:35:30:Dell
5C:26:0A:30:Dell
74:86:7A:30:Dell
74:E6:E2:30:Dell
78:2B:CB:30:Dell
84:7B:EB:30:Dell
90:B1:1C:30:Dell
98:90:96:30:Dell
A4:1F:72:30:Dell
A4:BA:DB:30:Dell
B0:83:FE:30:Dell
B8:AC:6F:30:Dell
B8:CA:3A:30:Dell
BC:30:5B:30:Dell
C8:1F:66:30:Dell
D0:67:E5:30:Dell
D4:81:D7:30:Dell
D4:BE:D9:30:Dell
E4:B9:7A:30:Dell
EC:F4:BB:30:Dell
F0:1F:AF:30:Dell
F4:8E:38:30:Dell
F8:B1:56:30:Dell

# HP (Laptops, Workstations)
00:01:E6:30:HP
00:02:A5:30:HP
00:04:EA:30:HP
00:08:02:30:HP
00:0A:57:30:HP
00:0B:CD:30:HP
00:0D:9D:30:HP
00:0E:7F:30:HP
00:0F:20:30:HP
00:10:83:30:HP
00:11:0A:30:HP
00:12:79:30:HP
00:13:21:30:HP
00:14:38:30:HP
00:15:60:30:HP
00:16:35:30:HP
00:17:08:30:HP
00:18:71:30:HP
00:19:BB:30:HP
00:1A:4B:30:HP
00:1B:78:30:HP
00:1C:C4:30:HP
00:1E:0B:30:HP
00:1F:29:30:HP
00:21:5A:30:HP
00:22:64:30:HP
00:23:7D:30:HP
00:24:81:30:HP
00:25:B3:30:HP
00:26:55:30:HP
00:30:C1:30:HP
10:1F:74:30:HP
10:60:4B:30:HP
14:02:EC:30:HP
18:A9:05:30:HP
1C:C1:DE:30:HP
28:80:23:30:HP
2C:44:FD:30:HP
2C:59:E5:30:HP
30:8D:99:30:HP
34:64:A9:30:HP
38:63:BB:30:HP
3C:52:82:30:HP
3C:D9:2B:30:HP
40:A8:F0:30:HP
48:0F:CF:30:HP
50:65:F3:30:HP
5C:B9:01:30:HP
64:51:06:30:HP
6C:3B:E5:30:HP
70:5A:0F:30:HP
78:AC:C0:30:HP
80:C1:6E:30:HP
84:34:97:30:HP
8C:DC:D4:30:HP
94:57:A5:30:HP
98:4B:E1:30:HP
9C:B6:54:30:HP
A0:1D:48:30:HP
A0:D3:C1:30:HP
A4:5D:36:30:HP
AC:16:2D:30:HP
B0:5A:DA:30:HP
B4:B6:76:30:HP
B8:AF:67:30:HP
C0:91:34:30:HP
C4:34:6B:30:HP
C8:CB:B8:30:HP
D0:BF:9C:30:HP
D4:C9:EF:30:HP
D8:D3:85:30:HP
E4:11:5B:30:HP
E8:39:35:30:HP
EC:8E:B5:30:HP
F0:92:1C:30:HP
F4:30:B9:30:HP
F8:63:3F:30:HP
FC:15:B4:30:HP

# Lenovo (Laptops)
00:06:1B:30:Lenovo
00:09:2D:30:Lenovo
00:1E:4C:30:Lenovo
00:21:86:30:Lenovo
00:26:2D:30:Lenovo
20:47:47:30:Lenovo
28:D2:44:30:Lenovo
40:B0:34:30:Lenovo
54:EE:75:30:Lenovo
60:D8:19:30:Lenovo
6C:C2:17:30:Lenovo
70:72:0D:30:Lenovo
74:70:FD:30:Lenovo
7C:67:A2:30:Lenovo
84:A6:C8:30:Lenovo
8C:16:45:30:Lenovo
8C:A9:82:30:Lenovo
98:FA:9B:30:Lenovo
B0:A4:60:30:Lenovo
C8:5B:76:30:Lenovo
D0:57:7B:30:Lenovo
E4:A7:A0:30:Lenovo
EC:B1:D7:30:Lenovo
F4:54:33:30:Lenovo
FC:44:82:30:Lenovo

# Microsoft (Surface, Xbox)
00:03:FF:30:Microsoft
00:0D:3A:30:Microsoft
00:12:5A:30:Microsoft
00:15:5D:30:Microsoft
00:17:FA:30:Microsoft
00:1D:D8:30:Microsoft
00:22:48:30:Microsoft
00:25:AE:30:Microsoft
00:50:F2:30:Microsoft
28:18:78:30:Microsoft
30:59:B7:30:Microsoft
50:1A:C5:30:Microsoft
58:82:A8:30:Microsoft
60:45:BD:30:Microsoft
7C:1E:52:30:Microsoft
7C:ED:8D:30:Microsoft
98:5F:D3:30:Microsoft
B4:0E:DE:30:Microsoft
C4:9D:ED:30:Microsoft
D4:38:9C:30:Microsoft
DC:B4:C4:30:Microsoft
E4:B3:18:30:Microsoft

# ============================================================
# VLAN 99 - IoT (Cameras, Smart Home, Sensors)
# ============================================================
# Hikvision (Security Cameras)
08:71:90:99:Hikvision
10:E2:4E:99:Hikvision
18:68:CB:99:Hikvision
28:57:BE:99:Hikvision
44:19:B6:99:Hikvision
4C:BD:8F:99:Hikvision
54:C4:15:99:Hikvision
58:49:3B:99:Hikvision
64:D9:89:99:Hikvision
74:DA:38:99:Hikvision
7C:29:93:99:Hikvision
8C:E7:48:99:Hikvision
94:E1:AC:99:Hikvision
A4:A6:15:99:Hikvision
BC:AD:28:99:Hikvision
C0:56:E3:99:Hikvision
C4:2F:90:99:Hikvision
CC:26:2D:99:Hikvision
E0:50:8B:99:Hikvision

# Dahua (Security Cameras)
00:1A:6B:99:Dahua
3C:EF:8C:99:Dahua
4C:11:BF:99:Dahua
78:A8:73:99:Dahua
90:02:A9:99:Dahua
9C:14:63:99:Dahua
A0:BD:1D:99:Dahua
B0:A7:32:99:Dahua
E0:2F:6D:99:Dahua

# Ring (Doorbells, Cameras)
00:62:6E:99:Ring
18:B4:30:99:Ring
34:DB:FD:99:Ring
40:4E:36:99:Ring
48:EE:0C:99:Ring
4C:94:6F:99:Ring
64:9A:BE:99:Ring
8C:FC:A0:99:Ring
9C:76:0E:99:Ring
AC:5F:EA:99:Ring
C0:76:BE:99:Ring
D4:E8:80:99:Ring
FC:A1:83:99:Ring

# Nest/Google (Thermostats, Cameras)
18:B4:30:99:Nest
64:16:66:99:Nest
F4:F5:D8:99:Nest

# Philips Hue (Smart Lights)
00:17:88:99:Philips
EC:B5:FA:99:Philips

# TP-Link (Smart Home, IoT)
00:27:19:99:TP-Link
14:CC:20:99:TP-Link
30:B5:C2:99:TP-Link
50:C7:BF:99:TP-Link
54:C8:0F:99:TP-Link
60:E3:27:99:TP-Link
64:70:02:99:TP-Link
6C:5A:B0:99:TP-Link
74:DA:88:99:TP-Link
90:9A:4A:99:TP-Link
98:DA:C4:99:TP-Link
AC:84:C6:99:TP-Link
B0:4E:26:99:TP-Link
B0:BE:76:99:TP-Link
C0:06:C3:99:TP-Link
C0:4A:00:99:TP-Link
D4:6E:0E:99:TP-Link
E4:C3:2A:99:TP-Link
EC:08:6B:99:TP-Link
F4:EC:38:99:TP-Link

# Tuya (Smart Home devices - generic)
10:D5:61:99:Tuya
18:69:D8:99:Tuya
24:62:AB:99:Tuya
48:3F:DA:99:Tuya
50:8A:06:99:Tuya
68:C6:3A:99:Tuya
7C:78:7E:99:Tuya
84:E3:42:99:Tuya
A8:48:FA:99:Tuya
BC:DD:C2:99:Tuya
CC:50:E3:99:Tuya
D8:F1:5B:99:Tuya
DC:4F:22:99:Tuya

# Sonoff/ITEAD (Smart Switches)
24:62:AB:99:Sonoff
60:01:94:99:Sonoff
68:C6:3A:99:Sonoff
BC:DD:C2:99:Sonoff

# Amazon Echo/Alexa
00:FC:8B:99:Amazon
0C:47:C9:99:Amazon
10:CE:A9:99:Amazon
18:74:2E:99:Amazon
24:4C:E3:99:Amazon
34:D2:70:99:Amazon
38:F7:3D:99:Amazon
40:A2:DB:99:Amazon
44:65:0D:99:Amazon
4C:EF:C0:99:Amazon
50:DC:E7:99:Amazon
50:F5:DA:99:Amazon
5C:41:5A:99:Amazon
68:37:E9:99:Amazon
68:54:FD:99:Amazon
6C:56:97:99:Amazon
74:C2:46:99:Amazon
78:E1:03:99:Amazon
84:D6:D0:99:Amazon
8C:AA:B5:99:Amazon
A0:02:DC:99:Amazon
AC:63:BE:99:Amazon
B0:FC:0D:99:Amazon
B4:7C:9C:99:Amazon
CC:9E:A2:99:Amazon
F0:27:2D:99:Amazon
F0:F0:A4:99:Amazon
FC:65:DE:99:Amazon

# ESP8266/ESP32 (Generic IoT modules - Espressif)
18:FE:34:99:Espressif
24:0A:C4:99:Espressif
24:62:AB:99:Espressif
24:B2:DE:99:Espressif
30:AE:A4:99:Espressif
3C:71:BF:99:Espressif
48:3F:DA:99:Espressif
4C:11:AE:99:Espressif
5C:CF:7F:99:Espressif
60:01:94:99:Espressif
68:C6:3A:99:Espressif
84:0D:8E:99:Espressif
84:CC:A8:99:Espressif
84:F3:EB:99:Espressif
8C:AA:B5:99:Espressif
90:97:D5:99:Espressif
98:F4:AB:99:Espressif
A4:7B:9D:99:Espressif
A4:CF:12:99:Espressif
AC:67:B2:99:Espressif
B4:E6:2D:99:Espressif
BC:DD:C2:99:Espressif
C4:4F:33:99:Espressif
CC:50:E3:99:Espressif
D8:BF:C0:99:Espressif
D8:F1:5B:99:Espressif
DC:4F:22:99:Espressif
EC:FA:BC:99:Espressif

# Shelly (Smart Home)
E8:DB:84:99:Shelly
98:CD:AC:99:Shelly

# Wyze (Cameras, Sensors)
2C:AA:8E:99:Wyze

# Reolink (Cameras)
EC:71:DB:99:Reolink
B4:A2:EB:99:Reolink

# Axis (Security Cameras)
00:40:8C:99:Axis
AC:CC:8E:99:Axis
B8:A4:4F:99:Axis

# Printers (to IoT/separate network)
# Brother
00:1B:A9:99:Brother
00:80:77:99:Brother
00:80:92:99:Brother
30:05:5C:99:Brother
44:87:FC:99:Brother
90:74:9D:99:Brother
B4:22:00:99:Brother
E8:93:09:99:Brother
F8:5B:3B:99:Brother

# Epson
00:00:48:99:Epson
00:26:AB:99:Epson
20:C3:8F:99:Epson
3C:18:A0:99:Epson
44:D2:44:99:Epson
88:12:4E:99:Epson
A4:EE:57:99:Epson
C8:D0:83:99:Epson
E0:3F:49:99:Epson

# Canon
00:00:85:99:Canon
00:1E:8F:99:Canon
18:0C:AC:99:Canon
34:15:9E:99:Canon
58:6D:8F:99:Canon
98:E7:F4:99:Canon
B8:26:6C:99:Canon
E0:98:61:99:Canon
F4:81:39:99:Canon

OUIEOF

    chmod 644 "$OUI_RULES_FILE"
    log_success "OUI rules saved: $OUI_RULES_FILE"
}

# ============================================================
# FREERADIUS AUTHORIZE FILE GENERATION
# ============================================================
generate_radius_authorize() {
    log_info "Generating FreeRADIUS authorize file..."

    if [ ! -d "$RADIUS_DIR/mods-config/files" ]; then
        log_warn "FreeRADIUS not installed, skipping"
        return 0
    fi

    # Read MAC-VLAN database for manual assignments
    local manual_entries=""
    if [ -f "$MAC_VLAN_DB" ]; then
        # Extract manual MAC assignments from JSON
        manual_entries=$(python3 -c "
import json
import sys
try:
    with open('$MAC_VLAN_DB') as f:
        data = json.load(f)
    for mac, info in data.get('devices', {}).items():
        vlan = info.get('vlan_id', 40)
        name = info.get('name', 'Manual')
        print(f'{mac}:{vlan}:{name}')
except Exception as e:
    pass
" 2>/dev/null) || true
    fi

    cat > "$RADIUS_AUTHORIZE" << 'HEADEREOF'
# ============================================================
# HookProbe Fortress - FreeRADIUS MAC Authentication
# ============================================================
# Auto-generated by vlan-assignment.sh
# DO NOT EDIT MANUALLY - changes will be overwritten
#
# VLAN Assignments:
#   10 - Management (network infrastructure)
#   20 - POS (payment terminals)
#   30 - Staff (consumer devices)
#   40 - Guest (unknown devices - default)
#   99 - IoT (cameras, smart home, sensors)
# ============================================================

HEADEREOF

    # Add manual MAC assignments first (highest priority)
    if [ -n "$manual_entries" ]; then
        echo "# ============================================================" >> "$RADIUS_AUTHORIZE"
        echo "# MANUAL MAC ASSIGNMENTS (from mac_vlan.json)" >> "$RADIUS_AUTHORIZE"
        echo "# ============================================================" >> "$RADIUS_AUTHORIZE"

        echo "$manual_entries" | while IFS=: read -r mac vlan name; do
            [ -z "$mac" ] && continue
            mac_normalized=$(echo "$mac" | tr ':' '-' | tr '[:lower:]' '[:upper:]')
            cat >> "$RADIUS_AUTHORIZE" << EOF
# $name
$mac Cleartext-Password := "$mac"
    Tunnel-Type = VLAN,
    Tunnel-Medium-Type = IEEE-802,
    Tunnel-Private-Group-Id = $vlan

EOF
        done
    fi

    # Add OUI-based rules
    if [ -f "$OUI_RULES_FILE" ]; then
        echo "" >> "$RADIUS_AUTHORIZE"
        echo "# ============================================================" >> "$RADIUS_AUTHORIZE"
        echo "# OUI-BASED VLAN ASSIGNMENTS (vendor detection)" >> "$RADIUS_AUTHORIZE"
        echo "# ============================================================" >> "$RADIUS_AUTHORIZE"

        local current_vlan=""
        local current_vendor=""

        grep -v '^#' "$OUI_RULES_FILE" | grep -v '^$' | while IFS=: read -r oui vlan vendor; do
            [ -z "$oui" ] && continue

            # Convert OUI format for RADIUS (replace : with -)
            oui_radius=$(echo "$oui" | tr ':' '-' | tr '[:lower:]' '[:upper:]')

            # Add vendor comment when it changes
            if [ "$vendor" != "$current_vendor" ]; then
                echo "" >> "$RADIUS_AUTHORIZE"
                echo "# $vendor (VLAN $vlan)" >> "$RADIUS_AUTHORIZE"
                current_vendor="$vendor"
            fi

            # Use RADIUS pattern matching with % wildcard
            cat >> "$RADIUS_AUTHORIZE" << EOF
$oui_radius% Cleartext-Password := "%{User-Name}"
    Tunnel-Type = VLAN,
    Tunnel-Medium-Type = IEEE-802,
    Tunnel-Private-Group-Id = $vlan

EOF
        done
    fi

    # Add DEFAULT rule (Guest VLAN)
    cat >> "$RADIUS_AUTHORIZE" << 'DEFAULTEOF'

# ============================================================
# DEFAULT - Unknown devices go to Guest VLAN (40)
# ============================================================
DEFAULT Cleartext-Password := "%{User-Name}"
    Tunnel-Type = VLAN,
    Tunnel-Medium-Type = IEEE-802,
    Tunnel-Private-Group-Id = 40,
    Reply-Message = "Welcome to HookProbe Fortress - Guest Network"
DEFAULTEOF

    # Set permissions
    chmod 640 "$RADIUS_AUTHORIZE"
    chown freerad:freerad "$RADIUS_AUTHORIZE" 2>/dev/null || true

    log_success "FreeRADIUS authorize file saved: $RADIUS_AUTHORIZE"
}

# ============================================================
# HOSTAPD MAC ACCEPT LIST
# ============================================================
generate_hostapd_accept_mac() {
    log_info "Generating hostapd accept_mac file..."

    mkdir -p "$HOSTAPD_DIR"

    cat > "$HOSTAPD_ACCEPT_MAC" << 'HEADEREOF'
# HookProbe Fortress - MAC Accept List with VLAN Assignment
# Format: MAC_ADDRESS VLAN_ID
# Auto-generated by vlan-assignment.sh
#
# This file works with hostapd's dynamic_vlan and accept_mac_file
# For WPA-Enterprise (RADIUS), this serves as a fallback
# For WPA-PSK with VLAN, this provides MAC-VLAN mapping

HEADEREOF

    # Add manual MAC assignments from database
    if [ -f "$MAC_VLAN_DB" ]; then
        echo "# Manual assignments from mac_vlan.json" >> "$HOSTAPD_ACCEPT_MAC"

        python3 -c "
import json
try:
    with open('$MAC_VLAN_DB') as f:
        data = json.load(f)
    for mac, info in data.get('devices', {}).items():
        vlan = info.get('vlan_id', 40)
        print(f'{mac} {vlan}')
except:
    pass
" 2>/dev/null >> "$HOSTAPD_ACCEPT_MAC" || true
    fi

    chmod 644 "$HOSTAPD_ACCEPT_MAC"
    log_success "hostapd accept_mac file saved: $HOSTAPD_ACCEPT_MAC"
}

# ============================================================
# MAC-VLAN DATABASE MANAGEMENT
# ============================================================
add_device() {
    # Add a device to the MAC-VLAN database
    # Args: MAC VLAN_ID NAME [DEVICE_TYPE]

    local mac="${1:-}"
    local vlan="${2:-40}"
    local name="${3:-Unknown}"
    local device_type="${4:-unknown}"

    if [ -z "$mac" ]; then
        log_error "Usage: $0 add-device MAC VLAN_ID NAME [DEVICE_TYPE]"
        return 1
    fi

    # Normalize MAC address
    mac=$(echo "$mac" | tr '[:lower:]' '[:upper:]' | tr '-' ':')

    log_info "Adding device: $mac -> VLAN $vlan ($name)"

    # Update JSON database
    python3 << PYEOF
import json
from datetime import datetime

mac = "$mac"
vlan = int("$vlan")
name = "$name"
device_type = "$device_type"

db_file = "$MAC_VLAN_DB"

try:
    with open(db_file) as f:
        data = json.load(f)
except:
    data = {"version": "1.0", "vlans": {}, "devices": {}}

data["devices"][mac] = {
    "vlan_id": vlan,
    "name": name,
    "device_type": device_type,
    "added": datetime.now().isoformat()
}

with open(db_file, 'w') as f:
    json.dump(data, f, indent=2)

print(f"Added {mac} -> VLAN {vlan}")
PYEOF

    # Regenerate RADIUS file
    generate_radius_authorize

    # Reload FreeRADIUS
    systemctl reload freeradius 2>/dev/null || true

    log_success "Device $mac added to VLAN $vlan"
}

remove_device() {
    # Remove a device from the MAC-VLAN database
    local mac="${1:-}"

    if [ -z "$mac" ]; then
        log_error "Usage: $0 remove-device MAC"
        return 1
    fi

    mac=$(echo "$mac" | tr '[:lower:]' '[:upper:]' | tr '-' ':')

    log_info "Removing device: $mac"

    python3 << PYEOF
import json

mac = "$mac"
db_file = "$MAC_VLAN_DB"

try:
    with open(db_file) as f:
        data = json.load(f)

    if mac in data.get("devices", {}):
        del data["devices"][mac]
        with open(db_file, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Removed {mac}")
    else:
        print(f"Device {mac} not found")
except Exception as e:
    print(f"Error: {e}")
PYEOF

    generate_radius_authorize
    systemctl reload freeradius 2>/dev/null || true

    log_success "Device $mac removed"
}

list_devices() {
    # List all devices in the MAC-VLAN database
    log_info "Devices in MAC-VLAN database:"

    if [ ! -f "$MAC_VLAN_DB" ]; then
        echo "No devices registered"
        return 0
    fi

    python3 << 'PYEOF'
import json

try:
    with open("/etc/fortress/mac_vlan.json") as f:
        data = json.load(f)

    devices = data.get("devices", {})
    if not devices:
        print("No devices registered")
    else:
        print(f"{'MAC Address':<20} {'VLAN':<6} {'Name':<20} {'Type':<15}")
        print("-" * 65)
        for mac, info in sorted(devices.items()):
            vlan = info.get('vlan_id', 40)
            name = info.get('name', 'Unknown')[:20]
            dtype = info.get('device_type', 'unknown')[:15]
            print(f"{mac:<20} {vlan:<6} {name:<20} {dtype:<15}")
except Exception as e:
    print(f"Error: {e}")
PYEOF
}

lookup_vendor() {
    # Look up VLAN for a MAC address based on OUI
    local mac="${1:-}"

    if [ -z "$mac" ]; then
        log_error "Usage: $0 lookup MAC"
        return 1
    fi

    mac=$(echo "$mac" | tr '[:lower:]' '[:upper:]' | tr '-' ':')
    local oui="${mac:0:8}"

    log_info "Looking up MAC: $mac (OUI: $oui)"

    # First check manual database
    if [ -f "$MAC_VLAN_DB" ]; then
        local manual_vlan=$(python3 -c "
import json
try:
    with open('$MAC_VLAN_DB') as f:
        data = json.load(f)
    info = data.get('devices', {}).get('$mac', {})
    if info:
        print(info.get('vlan_id', ''))
except:
    pass
" 2>/dev/null)

        if [ -n "$manual_vlan" ]; then
            echo "Manual assignment: VLAN $manual_vlan"
            return 0
        fi
    fi

    # Check OUI rules
    if [ -f "$OUI_RULES_FILE" ]; then
        local match=$(grep -i "^$oui:" "$OUI_RULES_FILE" 2>/dev/null | head -1)
        if [ -n "$match" ]; then
            local vlan=$(echo "$match" | cut -d: -f2)
            local vendor=$(echo "$match" | cut -d: -f3)
            echo "OUI match: $vendor -> VLAN $vlan"
            return 0
        fi
    fi

    echo "No match found - will use default Guest VLAN (40)"
}

# ============================================================
# INITIALIZATION
# ============================================================
initialize() {
    log_info "Initializing VLAN assignment system..."

    mkdir -p "$FORTRESS_ETC"
    mkdir -p "$FORTRESS_DATA"

    # Generate OUI rules
    generate_oui_rules

    # Initialize MAC-VLAN database if not exists
    if [ ! -f "$MAC_VLAN_DB" ]; then
        cat > "$MAC_VLAN_DB" << 'DBEOF'
{
  "version": "1.0",
  "description": "HookProbe Fortress - MAC to VLAN Assignment Database",
  "default_vlan": 40,
  "vlans": {
    "10": {"name": "management", "description": "Admin/Network devices"},
    "20": {"name": "pos", "description": "Payment terminals"},
    "30": {"name": "staff", "description": "Employee devices"},
    "40": {"name": "guest", "description": "Guest/Unknown devices"},
    "99": {"name": "iot", "description": "IoT/Cameras/Sensors"}
  },
  "devices": {}
}
DBEOF
        chmod 644 "$MAC_VLAN_DB"
    fi

    # Generate FreeRADIUS config
    generate_radius_authorize

    # Generate hostapd accept_mac
    generate_hostapd_accept_mac

    # Reload services
    systemctl reload freeradius 2>/dev/null || true

    log_success "VLAN assignment system initialized"
}

# ============================================================
# HELP
# ============================================================
show_help() {
    cat << 'HELPEOF'
HookProbe Fortress - VLAN Assignment Manager

USAGE:
    vlan-assignment.sh <command> [arguments]

COMMANDS:
    init                Initialize VLAN assignment system
    generate            Regenerate all configuration files
    add-device          Add device to MAC-VLAN database
                        Usage: add-device MAC VLAN_ID NAME [DEVICE_TYPE]
    remove-device       Remove device from database
                        Usage: remove-device MAC
    list                List all registered devices
    lookup              Look up VLAN for a MAC address
                        Usage: lookup MAC
    help                Show this help message

EXAMPLES:
    # Initialize the system
    vlan-assignment.sh init

    # Add a staff laptop
    vlan-assignment.sh add-device AA:BB:CC:DD:EE:FF 30 "Johns-MacBook" laptop

    # Add a POS terminal
    vlan-assignment.sh add-device 11:22:33:44:55:66 20 "Register-1" pos

    # Look up what VLAN a device will get
    vlan-assignment.sh lookup 00:17:88:12:34:56

    # List all registered devices
    vlan-assignment.sh list

VLAN ASSIGNMENTS:
    10 - Management (network infrastructure, admin devices)
    20 - POS (payment terminals, card readers)
    30 - Staff (employee laptops, phones - Apple, Samsung, Dell, HP, etc.)
    40 - Guest (unknown devices - DEFAULT)
    99 - IoT (cameras, sensors, smart home devices)

AUTO-DETECTION:
    Devices are automatically assigned to VLANs based on their MAC address
    vendor (OUI prefix). The OUI rules file contains mappings for:
    - Network equipment (Cisco, Ubiquiti, MikroTik) -> VLAN 10
    - Payment devices (Verifone, Ingenico, PAX) -> VLAN 20
    - Consumer devices (Apple, Samsung, Dell, HP) -> VLAN 30
    - IoT devices (Hikvision, Ring, TP-Link Smart) -> VLAN 99

FILES:
    /etc/fortress/mac_vlan.json           - MAC-to-VLAN database
    /etc/fortress/oui_vlan_rules.conf     - OUI-based VLAN rules
    /etc/freeradius/3.0/.../authorize     - FreeRADIUS users file
    /etc/hostapd/accept_mac               - hostapd MAC accept list

HELPEOF
}

# ============================================================
# MAIN
# ============================================================
main() {
    local command="${1:-help}"
    shift 2>/dev/null || true

    case "$command" in
        init|initialize)
            initialize
            ;;
        generate|regenerate)
            generate_oui_rules
            generate_radius_authorize
            generate_hostapd_accept_mac
            ;;
        add-device|add)
            add_device "$@"
            ;;
        remove-device|remove|del)
            remove_device "$@"
            ;;
        list|ls)
            list_devices
            ;;
        lookup|find)
            lookup_vendor "$@"
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
