# Nexus VPN Gateway Configuration

This directory contains IKEv2/strongSwan configuration for the Nexus mesh gateway.

## Architecture

```
Phone (iOS/Android) ←──IKEv2──→ Nexus ←──HTP──→ Guardian/Fortress
                                  │
                                  └── Logto IAM (authentication)
```

## Components

- `swanctl.conf` - Main strongSwan configuration
- `ipsec.conf` - Legacy ipsec.conf (optional)
- `charon.conf` - Charon daemon configuration
- `hookprobe-updown.sh` - Script for VPN connection events

## Quick Setup

```bash
# 1. Install strongSwan
apt-get install strongswan strongswan-pki libcharon-extra-plugins

# 2. Copy configuration
cp swanctl.conf /etc/swanctl/swanctl.conf
cp charon.conf /etc/strongswan.d/charon.conf
cp hookprobe-updown.sh /etc/strongswan.d/

# 3. Generate CA and server certificates
./generate-certs.sh

# 4. Start strongSwan
systemctl enable --now strongswan-starter

# 5. Verify
swanctl --list-conns
```

## Certificate Management

Certificates are managed by the Django VPN app:
- CA certificate: `/etc/hookprobe/vpn/ca.crt`
- Server certificate: `/etc/hookprobe/vpn/server.crt`
- User certificates: Generated on-demand via API

## Integration with HTP

When a VPN session is established:
1. strongSwan authenticates user via certificate
2. `hookprobe-updown.sh` notifies Django API
3. Django initiates HTP tunnel to target Guardian/Fortress
4. Traffic is routed: VPN tunnel → HTP tunnel → Device

## Bandwidth Management

Bandwidth allocation is configured per-user in Django.
The `hookprobe-updown.sh` script applies tc (traffic control) rules.
