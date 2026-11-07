# Fingerbank API Setup Guide

**For Small Businesses with < 600 Devices/Month**

This guide explains how to set up the Fingerbank API for enhanced device fingerprinting in HookProbe Fortress. The free tier is perfect for small businesses.

---

## What is Fingerbank?

Fingerbank is a cloud-based device fingerprinting service that identifies devices based on their DHCP fingerprint, MAC address, and other network characteristics. When the local fingerprint database can't identify a device, Fortress queries Fingerbank for enrichment.

**Benefits:**
- Identify unknown devices automatically
- Get accurate device type, vendor, and OS information
- Improve NAC policy assignment
- 99%+ device identification accuracy

---

## Free Tier Limits

| Feature | Free Tier |
|---------|-----------|
| **Requests/Month** | 600 |
| **Requests/Day** | ~20 |
| **Perfect For** | Small offices with < 50 devices |
| **Cost** | $0 |

**For most small businesses, the free tier is sufficient.** New devices are only queried once (results are cached locally), so you only use API requests for truly unknown devices.

---

## Step 1: Register for API Key

1. Visit: **https://api.fingerbank.org/email_registrations/current**

2. Enter your email address

3. Check your email for the API key (arrives within minutes)

4. Copy your API key (looks like: `a1b2c3d4e5f6g7h8i9j0...`)

---

## Step 2: Configure Fortress

### Using fortress-ctl (Recommended)

```bash
# Set your API key
sudo fortress-ctl fingerbank set-api-key YOUR_API_KEY_HERE

# Verify configuration
fortress-ctl fingerbank status

# Test the API
fortress-ctl fingerbank test
```

### Manual Configuration

Create `/etc/hookprobe/fingerbank.json`:

```json
{
    "api_key": "YOUR_API_KEY_HERE",
    "enabled": true,
    "requests_today": 0,
    "last_reset": "2024-01-15"
}
```

Set permissions:
```bash
sudo chmod 600 /etc/hookprobe/fingerbank.json
```

---

## Step 3: Verify Integration

### Check Status

```bash
fortress-ctl fingerbank status
```

Expected output:
```
==> Fingerbank API Status

  Status:     Enabled
  API Key:    a1b2c3d4...
  Requests:   0/20 today (free tier: ~20/day)
  Last Reset: 2024-01-15

  → Testing API connectivity...
  API Test:   OK

  Learned from API: 0 fingerprints
```

### Test a Fingerprint

```bash
# Test with a known macOS fingerprint
fortress-ctl fingerbank test "1,121,3,6,15,119,252,95,44,46"
```

Expected output:
```
==> Testing Fingerbank API

  → Querying fingerprint: 1,121,3,6,15,119,252,95,44,46

API Response:
{
    "device": {
        "name": "macOS",
        "parents": ["Operating System", "Apple", "Apple macOS"]
    },
    "score": 95
}

[INFO] Identified: macOS (score: 95)
```

---

## How It Works

### Automatic Flow

1. **New device connects** to your network
2. **DHCP fingerprint collected** from DHCP request
3. **Local database checked** first (10,000+ fingerprints)
4. **If unknown** and confidence < 50%, Fingerbank API queried
5. **Result cached** locally for future use
6. **Policy assigned** based on device category

### What Gets Sent to Fingerbank

Only anonymized data is sent:
- DHCP Option 55 fingerprint (e.g., `1,3,6,15,119,252`)
- MAC OUI prefix (first 3 bytes only, e.g., `00:11:22`)
- Hostname (optional)
- DHCP vendor class (optional)

**No IP addresses or full MAC addresses are sent.**

---

## Managing API Usage

### Check Daily Usage

```bash
fortress-ctl fingerbank status
```

Look for: `Requests: X/20 today`

### Disable Temporarily

```bash
# Disable API queries
sudo fortress-ctl fingerbank disable

# Re-enable when ready
sudo fortress-ctl fingerbank enable
```

### Monthly Reset

The 600 requests/month limit resets on your registration anniversary date.

---

## Troubleshooting

### "Rate limited" Error

**Cause:** Exceeded daily/monthly limit

**Solution:**
- Wait for daily reset (midnight UTC)
- Or wait for monthly reset
- Consider reducing unknown devices on network

### "Invalid API key" Error

**Cause:** Typo or expired key

**Solution:**
```bash
# Remove old config
sudo rm /etc/hookprobe/fingerbank.json

# Re-register at fingerbank.org
# Get new key and reconfigure
sudo fortress-ctl fingerbank set-api-key NEW_KEY
```

### "Connection failed" Error

**Cause:** Network/firewall issue

**Solution:**
- Check internet connectivity
- Ensure `api.fingerbank.org` is reachable
- Check firewall allows HTTPS outbound

### No Devices Being Identified

**Cause:** API might be disabled

**Solution:**
```bash
# Check status
fortress-ctl fingerbank status

# Enable if disabled
sudo fortress-ctl fingerbank enable
```

---

## Best Practices

### 1. Pre-populate Known Devices

Before enabling the API, let known devices connect first. The local database will identify most Apple, Samsung, and common devices without API calls.

### 2. Monitor Usage

Check usage weekly:
```bash
fortress-ctl fingerbank status
```

### 3. Trust Local First

The system automatically uses local identification first. API is only called for truly unknown devices.

### 4. Cache Management

Identified devices are cached. You won't use API requests for devices you've already identified.

---

## API Endpoints Reference

| Endpoint | Purpose | Usage |
|----------|---------|-------|
| `/api/v2/combinations/interrogate` | Identify device | POST with fingerprint data |
| `/api/v2/devices` | List known devices | GET (rate limited) |

---

## Privacy

- Fingerbank is operated by Inverse Inc.
- Only network fingerprints are sent (no personal data)
- MAC addresses are truncated to OUI
- See: https://fingerbank.org/privacy

---

## Support

- **Fingerbank Docs:** https://api.fingerbank.org/api_doc
- **HookProbe Issues:** https://github.com/hookprobe/hookprobe/issues
- **Commercial Plans:** Contact fingerbank@inverse.ca

---

## Quick Reference

```bash
# Configure API key
sudo fortress-ctl fingerbank set-api-key YOUR_KEY

# Check status
fortress-ctl fingerbank status

# Test API
fortress-ctl fingerbank test

# Disable/Enable
sudo fortress-ctl fingerbank disable
sudo fortress-ctl fingerbank enable
```

---

*HookProbe Fortress - SDN Autopilot with AI-Powered Device Fingerprinting*
