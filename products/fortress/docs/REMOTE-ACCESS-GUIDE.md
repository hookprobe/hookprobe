# Fortress Remote Access Guide

**Access Your Business Security From Anywhere**

This guide shows you how to securely access your Fortress dashboard from your phone, laptop, or any device - whether you're at home, traveling, or checking on your shop from vacation.

---

## What You'll Achieve

After following this guide:
- Access `https://fortress.yourbusiness.com` from anywhere
- Check security status from your phone
- Get alerts and respond to threats remotely
- No port forwarding or exposed IP addresses
- Enterprise-grade security via Cloudflare

**Time Required**: 15-20 minutes

---

## Prerequisites

Before you start, you need:

1. **A website with Cloudflare** (free tier works)
   - If your business website isn't on Cloudflare, [sign up here](https://dash.cloudflare.com/sign-up)
   - Add your domain to Cloudflare and update your nameservers

2. **Fortress installed and running**
   - You should be able to access the Fortress dashboard locally

3. **An internet connection** at your business location

---

## Step 1: Install Cloudflare Tunnel Client

If you installed Fortress with `--enable-remote-access`, skip to Step 2.

### Option A: Via Fortress Web UI (Recommended)

1. Open Fortress dashboard at `https://localhost:8443`
2. Click **Remote Access** in the sidebar
3. Click **Setup Remote Access**
4. Click **Install cloudflared**

### Option B: Manual Installation

```bash
# For x86_64 (most PCs)
curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared
chmod +x /usr/local/bin/cloudflared

# For ARM64 (Raspberry Pi 4/5, etc.)
curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64 -o /usr/local/bin/cloudflared
chmod +x /usr/local/bin/cloudflared

# Verify installation
cloudflared version
```

---

## Step 2: Create Tunnel in Cloudflare Dashboard

1. **Open Cloudflare Zero Trust Dashboard**
   - Go to: https://one.dash.cloudflare.com/
   - Log in with your Cloudflare account

2. **Navigate to Tunnels**
   - Click **Networks** in the left sidebar
   - Click **Tunnels**

3. **Create a New Tunnel**
   - Click **Create a tunnel**
   - Select **Cloudflared** as the connector type
   - Click **Next**

4. **Name Your Tunnel**
   - Enter a name like `fortress-mybakery` or `fortress-myshop`
   - Click **Save tunnel**

5. **Copy the Tunnel Token**
   - You'll see a long token starting with `eyJ...`
   - **Copy this token** - you'll need it in the next step
   - Click **Next**

6. **Configure Public Hostname**

   | Field | Value | Example |
   |-------|-------|---------|
   | **Subdomain** | Your choice | `fortress` or `security` |
   | **Domain** | Select your domain | `mybakery.com` |
   | **Type** | HTTPS | |
   | **URL** | `localhost:8443` | |

   This creates: `https://fortress.mybakery.com`

7. **Save the Tunnel**
   - Click **Save tunnel**

---

## Step 3: Configure Fortress

### Option A: Via Web UI (Recommended)

1. Go to **Remote Access** in Fortress dashboard
2. Click **Setup Remote Access** (or continue wizard)
3. Paste the **Tunnel Token** from Cloudflare
4. Enter your **Access URL** (e.g., `fortress.mybakery.com`)
5. Enable **Start automatically on boot**
6. Click **Connect Tunnel**

### Option B: Via Command Line

```bash
# Configure the tunnel
python3 /opt/hookprobe/fortress/lib/cloudflare_tunnel.py configure \
  --token "eyJhIjoiMTIzNDU2Nzg5MGFi..." \
  --hostname "fortress.mybakery.com"

# Start the tunnel
python3 /opt/hookprobe/fortress/lib/cloudflare_tunnel.py start

# Check status
python3 /opt/hookprobe/fortress/lib/cloudflare_tunnel.py status
```

---

## Step 4: Test Your Connection

1. **Wait 2-3 minutes** for DNS to propagate

2. **Test from your phone** (on mobile data, not WiFi):
   - Open browser
   - Go to `https://fortress.yourbusiness.com`
   - You should see the Fortress login page

3. **Bookmark it!**
   - Save the URL to your home screen for quick access

---

## Troubleshooting

### "Site can't be reached"

**Cause**: DNS hasn't propagated yet

**Fix**: Wait 5-10 minutes and try again. You can check DNS propagation at [whatsmydns.net](https://www.whatsmydns.net/)

### "ERR_SSL_PROTOCOL_ERROR"

**Cause**: HTTPS configuration issue

**Fix**: In Cloudflare tunnel settings, ensure:
- Service Type is `HTTPS`
- URL is `localhost:8443`
- "No TLS Verify" is enabled (for self-signed certs)

### Tunnel Shows "Disconnected"

**Cause**: Token invalid or network issue

**Fix**:
1. Check internet connection at your business
2. Verify the token was copied correctly
3. Check tunnel logs: `journalctl -u fortress-tunnel -f`

### Can't Login Remotely

**Cause**: Session/cookie issue

**Fix**: Clear browser cache and try again

---

## Security Best Practices

### 1. Use Strong Passwords
Change the default Fortress password immediately:
- Go to **Settings** > **Users**
- Click on your user
- Set a strong, unique password

### 2. Enable Cloudflare Access (Optional but Recommended)
Add an extra layer of authentication:

1. Go to Cloudflare Zero Trust dashboard
2. Click **Access** > **Applications**
3. Click **Add an application**
4. Choose **Self-hosted**
5. Configure:
   - Application name: `Fortress Dashboard`
   - Session duration: 24 hours
   - Application domain: `fortress.yourbusiness.com`
6. Add a policy (e.g., allow your email)
7. Save

Now users must authenticate via Cloudflare before reaching Fortress.

### 3. Monitor Access Logs
Check who's accessing your dashboard:
- Fortress logs: **Settings** > **Audit Log**
- Cloudflare logs: Zero Trust dashboard > **Logs**

### 4. Keep Software Updated
Regularly update Fortress and cloudflared:
```bash
# Update cloudflared
cloudflared update

# Update Fortress (follow your update procedure)
```

---

## Quick Reference

| Task | Command/Location |
|------|-----------------|
| Check tunnel status | `cloudflared tunnel info` |
| View tunnel logs | `journalctl -u fortress-tunnel -f` |
| Restart tunnel | `systemctl restart fortress-tunnel` |
| Stop tunnel | `systemctl stop fortress-tunnel` |
| Start tunnel | `systemctl start fortress-tunnel` |
| Web UI tunnel config | Fortress > Remote Access |
| Cloudflare dashboard | https://one.dash.cloudflare.com |

---

## Support

Need help? Here are your options:

1. **Community Forum**: [community.hookprobe.com](https://community.hookprobe.com)
2. **GitHub Issues**: [github.com/hookprobe/hookprobe/issues](https://github.com/hookprobe/hookprobe/issues)
3. **Documentation**: [docs.hookprobe.com](https://docs.hookprobe.com)

---

## Architecture Overview

```
Your Phone (anywhere)
       │
       │ HTTPS (encrypted)
       ▼
┌──────────────────┐
│   Cloudflare     │  ← DDoS protection, TLS termination
│   (Global CDN)   │
└────────┬─────────┘
         │
         │ Outbound tunnel (no open ports!)
         ▼
┌──────────────────┐
│  cloudflared     │  ← Runs on your Fortress
│  (tunnel client) │
└────────┬─────────┘
         │
         │ localhost:8443
         ▼
┌──────────────────┐
│ Fortress Web UI  │  ← Your security dashboard
│ (HTTPS server)   │
└──────────────────┘
```

**Key Security Benefits**:
- **No open ports**: Tunnel is outbound-only
- **End-to-end encryption**: TLS from phone to Fortress
- **Cloudflare protection**: DDoS mitigation, WAF
- **Zero Trust ready**: Add Cloudflare Access for extra auth

---

*HookProbe Fortress - One node's detection → Everyone's protection*
