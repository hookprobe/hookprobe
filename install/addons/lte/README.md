# LTE/CGNAT Hosting Recommendations for HookProbe

**Document Version**: 1.0  
**Last Updated**: November 2025  
**Target Platform**: SBC (Single Board Computer) with LTE/CGNAT Connection

---

## 📋 Table of Contents

1. [Connection Analysis](#connection-analysis)
2. [Critical Issue: CGNAT](#critical-issue-cgnat)
3. [Performance Analysis](#performance-analysis)
4. [Latency & Bufferbloat](#latency--bufferbloat)
5. [Why Lightweight Stack is Essential](#why-lightweight-stack-is-essential)
6. [Optimized Architecture](#optimized-architecture)
7. [Expected Performance](#expected-performance)
8. [Optimization Checklist](#optimization-checklist)
9. [Before/After Comparison](#beforeafter-comparison)
10. [Implementation Guide](#implementation-guide)

---

## 🔍 Connection Analysis

### Your Current Specs EXAMPLE in most ISP providers of LTE

```
Download Speed: 32 Mbps
Upload Speed:   43 Mbps
Latency:
  - Unloaded: 56 ms
  - Loaded:   200 ms (⚠️ Bufferbloat detected)

Servers:  Bucharest, RO | Vienna, AT
Provider: CGNAT (Carrier-Grade NAT)
```

---

## 🔴 Critical Issue: CGNAT

### The Problem

**CGNAT** (Carrier-Grade NAT) means you don't have a public IP address. Multiple customers share the same public IP through provider-level NAT.

**Result**: ❌ **You CANNOT host directly** - no port forwarding, no incoming connections.

### ✅ The Solution: Cloudflare Tunnel

**Cloudflare Tunnel** (already in your `setup.sh`) creates an outbound-only tunnel to Cloudflare's edge network.

**How it works**:
```
Internet User
     ↓
Cloudflare Edge (Public)
     ↓
Encrypted Tunnel (Outbound from your SBC)
     ↓
Your SBC (Private CGNAT IP)
```

**Benefits**:
- ✅ Bypasses CGNAT completely
- ✅ No port forwarding needed
- ✅ Free SSL/TLS certificates
- ✅ DDoS protection (unlimited on free tier)
- ✅ Global CDN caching
- ✅ Reduces bandwidth usage by 80-95%

**Configuration** (already in setup.sh):
```bash
podman run -d --restart always \
  --name cloudflared \
  cloudflare/cloudflared:latest \
  tunnel --no-autoupdate run --token $CLOUDFLARE_TUNNEL_TOKEN
```

**Cloudflare Dashboard Setup**:
1. Go to [Cloudflare Zero Trust Dashboard](https://one.dash.cloudflare.com/)
2. Navigate to **Access** → **Tunnels**
3. Create tunnel → Get token
4. Add public hostname: `yourdomain.com` → `http://localhost:80`

---

## 📊 Performance Analysis

### Upload Bandwidth Math

Your 43 Mbps upload translates to:

```
43 Mbps = 5.375 MB/sec (theoretical maximum)

Lightweight site (100KB per page):
  5.375 MB/sec ÷ 0.1 MB = ~53 pages/sec
  = ~3,180 pages/min
  = ~190,000 pages/hour (theoretical)

Realistic with overhead (50% efficiency):
  ~25 pages/sec
  = ~90,000 pages/hour

With 200KB pages (HTML5 UP):
  ~12 pages/sec = ~43,000 pages/hour

With 2MB pages (Heavy ThemeForest):
  ~2.5 pages/sec = ~9,000 pages/hour
```

### Concurrent User Capacity

| Site Type | Page Size | Concurrent Users | Load Time |
|-----------|-----------|------------------|-----------|
| **Lightweight** (HTML5 UP) | 100KB | 10-20 | 2-3 sec |
| **Medium** (Basic Bootstrap) | 500KB | 5-10 | 5-8 sec |
| **Heavy** (ThemeForest) | 2MB+ | 2-5 | 10-15 sec |

**Recommendation**: ✅ **Lightweight stack is mandatory** for LTE hosting.

---

## ⚠️ Latency & Bufferbloat

### The Problem

```
Unloaded Latency: 56 ms   ✅ Good
Loaded Latency:   200 ms  🔴 Bad (+144ms penalty)
```

This **+144ms penalty** is **bufferbloat** - your LTE modem's buffer fills up during uploads, causing massive latency spikes.

**Impact**:
- Users experience sluggish responses during traffic bursts
- Multiple simultaneous requests feel slow
- WebSocket connections may timeout

### Solution 1: QoS with CAKE

**Install and configure CAKE qdisc** (best anti-bufferbloat solution):

```bash
# Install traffic control tools
sudo dnf install -y iproute-tc

# Apply CAKE to LTE interface (check your interface name with 'ip a')
# Common names: wwan0, usb0, eth1
sudo tc qdisc add dev wwan0 root cake bandwidth 40mbit diffserv4

# Verify
tc qdisc show dev wwan0

# Make persistent (add to /etc/rc.local or systemd service)
```

**Why 40mbit instead of 43mbit?**
- Set to 93% of actual bandwidth to prevent buffer filling
- This keeps latency at ~80-100ms even under load

**Expected improvement**:
```
Before QoS:
  Loaded latency: 200ms

After QoS:
  Loaded latency: 80-100ms
```

### Solution 2: Rate Limiting in Nginx

Prevent single users from saturating your connection:

```nginx
# /etc/nginx/nginx.conf

http {
    # Limit connections per IP
    limit_conn_zone $binary_remote_addr zone=conn_limit:10m;
    
    # Limit request rate
    limit_req_zone $binary_remote_addr zone=req_limit:10m rate=10r/s;
    
    server {
        # Max 5 concurrent connections per IP
        limit_conn conn_limit 5;
        
        # Max 10 requests/sec, allow bursts up to 20
        limit_req zone=req_limit burst=20 nodelay;
        
        # Rest of your config...
    }
}
```

---

## 🚀 Why Lightweight Stack is Essential

### Comparison Table

| Metric | Heavy Stack | Light Stack | Impact on LTE |
|--------|-------------|-------------|---------------|
| **Page size** | 2 MB | 100 KB | 20x less bandwidth |
| **CSS** | 400 KB | 15 KB | 27x smaller |
| **JavaScript** | 800 KB | 30 KB | 27x smaller |
| **Concurrent users** | 2-5 | 10-20 | 4x capacity |
| **Cache hit rate** | 60% | 95% | Most served by Cloudflare |
| **Time to first byte** | 800 ms | 200 ms | 4x faster |
| **Monthly bandwidth** (10k views) | 20 GB | 500 MB | 40x less |

### Real-World Impact

**Heavy Site on Your LTE**:
- ❌ Unusable during traffic spikes
- ❌ Can only handle 2-3 simultaneous users
- ❌ 800ms+ page loads
- ❌ Bandwidth exhausted quickly

**Light Site on Your LTE**:
- ✅ Snappy even at 15 concurrent users
- ✅ 150-250ms page loads
- ✅ Bandwidth barely touched (95% served by Cloudflare)
- ✅ Can handle 1-5M pageviews/month

---

## 🏗️ Optimized Architecture

### Three-Layer Caching Strategy

```
Layer 1: Cloudflare CDN (Edge Cache)
  ↓ (95% of requests stop here)
Layer 2: Nginx Microcache (60 second cache)
  ↓ (4% of requests stop here)
Layer 3: Django Application (Dynamic)
  ↓ (1% of requests hit database)
```

### Layer 1: Cloudflare CDN

**Configuration in Cloudflare Dashboard**:

1. **Caching → Configuration**:
   ```
   Cache Level: Standard
   Browser Cache TTL: 1 year
   ```

2. **Page Rules**:
   ```
   *.css, *.js, *.png, *.jpg, *.webp:
     Cache Level: Everything
     Edge Cache TTL: 1 year
   
   /blog/*:
     Cache Level: Cache Everything
     Edge Cache TTL: 1 hour
   
   /admin/*:
     Cache Level: Bypass
   
   /:
     Cache Level: Cache Everything
     Edge Cache TTL: 5 minutes
   ```

3. **Auto Minify**:
   ```
   ✅ JavaScript
   ✅ CSS
   ✅ HTML
   ```

4. **Brotli Compression**:
   ```
   ✅ Enabled (better than gzip)
   ```

**Expected Cache Hit Rate**: 95%+

**Result**: Only 5% of traffic hits your SBC

### Layer 2: Nginx Microcache

**Complete Nginx Configuration**:

```nginx
# /etc/nginx/nginx.conf

user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "Cache:$upstream_cache_status"';
    
    access_log /var/log/nginx/access.log main;
    
    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 10M;
    
    # Compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript 
               application/json application/javascript application/xml+rss 
               application/rss+xml font/truetype font/opentype 
               application/vnd.ms-fontobject image/svg+xml;
    gzip_disable "msie6";
    
    # Brotli (if available)
    brotli on;
    brotli_comp_level 6;
    brotli_types text/plain text/css text/xml text/javascript 
                 application/json application/javascript;
    
    # Rate Limiting
    limit_conn_zone $binary_remote_addr zone=conn_limit:10m;
    limit_req_zone $binary_remote_addr zone=req_limit:10m rate=10r/s;
    
    # Microcache Configuration
    proxy_cache_path /var/cache/nginx/micro 
        levels=1:2 
        keys_zone=microcache:10m 
        max_size=100m 
        inactive=1h 
        use_temp_path=off;
    
    # Static cache
    proxy_cache_path /var/cache/nginx/static 
        levels=1:2 
        keys_zone=staticcache:10m 
        max_size=500m 
        inactive=7d 
        use_temp_path=off;
    
    upstream django {
        server 10.200.1.10:8000;
        keepalive 32;
    }
    
    server {
        listen 80;
        server_name _;
        
        # Connection limiting
        limit_conn conn_limit 5;
        
        # Static files (served from RAM - see tmpfs section)
        location /static/ {
            alias /var/www/static/;
            
            # Cache in Nginx
            proxy_cache staticcache;
            proxy_cache_valid 200 7d;
            
            # Browser cache
            expires 1y;
            add_header Cache-Control "public, immutable";
            add_header X-Cache-Status $upstream_cache_status;
            
            # Security
            add_header X-Content-Type-Options "nosniff" always;
            add_header X-Frame-Options "SAMEORIGIN" always;
            
            # CORS for fonts
            location ~* \.(woff|woff2|ttf|otf|eot)$ {
                add_header Access-Control-Allow-Origin "*";
                expires 1y;
            }
        }
        
        location /media/ {
            alias /var/www/media/;
            expires 30d;
            add_header Cache-Control "public, immutable";
        }
        
        # Admin (no cache)
        location /admin/ {
            limit_req zone=req_limit burst=10 nodelay;
            
            proxy_pass http://django;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            proxy_cache_bypass 1;
            proxy_no_cache 1;
        }
        
        # Blog (1 hour cache)
        location /blog/ {
            limit_req zone=req_limit burst=20 nodelay;
            
            proxy_pass http://django;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # Microcache
            proxy_cache microcache;
            proxy_cache_key $scheme$host$request_uri;
            proxy_cache_valid 200 1h;
            proxy_cache_bypass $http_pragma $http_authorization;
            proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
            proxy_cache_background_update on;
            proxy_cache_lock on;
            
            add_header X-Cache-Status $upstream_cache_status;
        }
        
        # Homepage and other pages (5 minute microcache)
        location / {
            limit_req zone=req_limit burst=20 nodelay;
            
            proxy_pass http://django;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # Microcache
            proxy_cache microcache;
            proxy_cache_key $scheme$host$request_uri;
            proxy_cache_valid 200 5m;
            proxy_cache_bypass $http_pragma $http_authorization $cookie_sessionid;
            proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
            proxy_cache_background_update on;
            proxy_cache_lock on;
            
            add_header X-Cache-Status $upstream_cache_status;
        }
        
        # API endpoints (no cache)
        location /api/ {
            limit_req zone=req_limit burst=5 nodelay;
            
            proxy_pass http://django;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            proxy_cache_bypass 1;
            proxy_no_cache 1;
        }
    }
}
```

### Layer 3: Static Files from RAM (tmpfs)

**Mount static files to RAM for instant serving**:

```bash
# Create mount point
sudo mkdir -p /var/www/static

# Mount 512MB RAM disk
sudo mount -t tmpfs -o size=512M tmpfs /var/www/static

# Make persistent across reboots
echo "tmpfs /var/www/static tmpfs size=512M,uid=nginx,gid=nginx,mode=0755 0 0" | \
  sudo tee -a /etc/fstab

# Copy static files from Django container
sudo podman cp hookprobe-pod-001-web-dmz-django:/app/static/. /var/www/static/

# Set permissions
sudo chown -R nginx:nginx /var/www/static
sudo chmod -R 755 /var/www/static
```

**Benefits**:
- ✅ 0.01ms read time (vs 5ms from SSD)
- ✅ No disk I/O wear
- ✅ Survives reboots (recreated from container)
- ✅ Perfect for lightweight sites (<512MB assets)

**Auto-populate on boot** (systemd service):

```bash
# Create service file
sudo tee /etc/systemd/system/populate-static.service << 'EOF'
[Unit]
Description=Populate static files to tmpfs
After=podman.service
Requires=podman.service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'podman cp hookprobe-pod-001-web-dmz-django:/app/static/. /var/www/static/ && chown -R nginx:nginx /var/www/static'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Enable
sudo systemctl enable populate-static.service
sudo systemctl start populate-static.service
```

---

## 📈 Expected Performance

### Scenario 1: Normal Traffic (1-5 concurrent users)

```
With Cloudflare cache hit rate: 95%

User Request Flow:
1. User requests page
2. Cloudflare serves from edge (closest datacenter)
3. 95% of requests NEVER hit your SBC
4. 5% that do: Nginx microcache serves in <50ms

Your SBC Statistics:
- Bandwidth usage: ~2 Mbps average
- Requests/sec: ~1-2 (most cached)
- Latency: 56ms (unloaded)
- Load: <10% CPU

User Experience: ⚡ Lightning fast (50-100ms page loads)
```

### Scenario 2: Traffic Spike (20 concurrent users)

```
Cloudflare still serves 95% from edge cache

Your SBC handles:
- Requests: ~1 req/sec (5% of 20 users browsing)
- Nginx serves from microcache
- Bandwidth: ~5-10 Mbps
- Latency: 80ms (slight increase with QoS)
- Load: ~30% CPU

User Experience: Still fast ✅ (100-200ms page loads)
```

### Scenario 3: Cache Miss Storm (worst case)

```
Cloudflare cache purged, everyone requests fresh content

100 users/min all requesting new content:

Without optimization: 
  ❌ DEAD - Upload saturated, 5+ second page loads

With light stack + microcache:
  - First 10 users: Django generates page (~200ms)
  - Nginx caches result
  - Next 90 users: Nginx serves cached version (~50ms)
  - Bandwidth: 15-20 Mbps (within capacity)
  - Latency: 100-150ms (with QoS)
  - Load: ~60% CPU

User Experience: Slight slowdown but survives ✅ (200-400ms)
```

---

## ⚡ Optimization Checklist

### 🔴 Critical (Must Do)

#### 1. Enable Cloudflare Tunnel

```bash
# Verify it's running
podman logs hookprobe-pod-001-web-dmz-cloudflared

# Should show: "Connection established"

# If not running, check network-config.sh:
CLOUDFLARE_TUNNEL_TOKEN="your_token_here"
```

#### 2. Configure Cloudflare Caching

**In Cloudflare Dashboard**:
1. Go to your domain → **Caching** → **Configuration**
2. **Cache Level**: Standard
3. **Browser Cache TTL**: Respect Existing Headers
4. **Always Online**: ON

**Create Page Rules** (Rules → Page Rules):
```
Rule 1: yourdomain.com/static/*
  Cache Level: Cache Everything
  Edge Cache TTL: 1 year

Rule 2: yourdomain.com/blog/*
  Cache Level: Cache Everything
  Edge Cache TTL: 1 hour

Rule 3: yourdomain.com/admin/*
  Cache Level: Bypass

Rule 4: yourdomain.com/*
  Cache Level: Cache Everything
  Edge Cache TTL: 5 minutes
```

#### 3. Enable QoS on LTE Interface

```bash
# Find your LTE interface
ip addr show

# Common names: wwan0, usb0, eth1, enp0s20f0u2
# Replace 'wwan0' below with your actual interface

# Install tools
sudo dnf install -y iproute-tc

# Apply CAKE qdisc
sudo tc qdisc add dev wwan0 root cake bandwidth 40mbit diffserv4

# Verify
tc qdisc show dev wwan0

# Make persistent (create systemd service)
sudo tee /etc/systemd/system/qos-lte.service << 'EOF'
[Unit]
Description=QoS for LTE interface
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/tc qdisc add dev wwan0 root cake bandwidth 40mbit diffserv4
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable qos-lte.service
sudo systemctl start qos-lte.service
```

#### 4. Enable Nginx Compression

```nginx
# Add to /etc/nginx/nginx.conf (or POD config)

http {
    # Gzip
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript 
               application/json application/javascript application/xml+rss;
    
    # Brotli (if module available)
    brotli on;
    brotli_comp_level 6;
    brotli_types text/plain text/css text/xml text/javascript 
                 application/json application/javascript;
}
```

#### 5. Serve Static Files from RAM

```bash
# Create tmpfs mount
sudo mkdir -p /var/www/static
sudo mount -t tmpfs -o size=512M tmpfs /var/www/static

# Copy static files
sudo podman cp hookprobe-pod-001-web-dmz-django:/app/static/. /var/www/static/

# Make persistent
echo "tmpfs /var/www/static tmpfs size=512M,uid=nginx,gid=nginx 0 0" | \
  sudo tee -a /etc/fstab

# Update Nginx to serve from /var/www/static
```

### 🟡 Important (Should Do)

#### 6. Image Optimization

```bash
# Install WebP tools
sudo dnf install -y libwebp-tools

# Convert all images to WebP
find /var/www/static -type f \( -name "*.jpg" -o -name "*.png" \) | while read img; do
    cwebp -q 80 "$img" -o "${img%.*}.webp"
    echo "Converted: $img"
done

# Use <picture> tags for fallback
```

**HTML Example**:
```html
<picture>
  <source srcset="image.webp" type="image/webp">
  <source srcset="image.jpg" type="image/jpeg">
  <img src="image.jpg" alt="Description" loading="lazy" width="800" height="600">
</picture>
```

#### 7. Lazy Loading

```html
<!-- Native lazy loading (supported by all modern browsers) -->
<img src="large-image.jpg" loading="lazy" width="800" height="600" alt="Description">

<!-- For background images, use Intersection Observer -->
<div class="lazy-bg" data-bg="hero-background.jpg"></div>

<script>
const lazyBgs = document.querySelectorAll('.lazy-bg');
const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.style.backgroundImage = `url(${entry.target.dataset.bg})`;
            observer.unobserve(entry.target);
        }
    });
});
lazyBgs.forEach(bg => observer.observe(bg));
</script>
```

#### 8. Minify CSS/JS

**Tailwind** (does this automatically):
```bash
# In your theme directory
npm run build

# Outputs minified CSS (~15KB)
```

**For custom CSS/JS**:
```bash
# Install minifiers
npm install -g clean-css-cli uglify-js

# Minify CSS
cleancss -o style.min.css style.css

# Minify JS
uglifyjs script.js -o script.min.js -c -m
```

#### 9. HTTP/2 (Cloudflare enables automatically)

Verify it's working:
```bash
curl -I --http2 https://yourdomain.com | grep HTTP
# Should show: HTTP/2 200
```

#### 10. Database Query Optimization

```python
# Django settings.py

# Enable query logging in development
LOGGING = {
    'version': 1,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'django.db.backends': {
            'handlers': ['console'],
            'level': 'DEBUG',
        },
    },
}

# Find slow queries, then optimize with:
# - select_related() for foreign keys
# - prefetch_related() for many-to-many
# - Database indexes

# Example:
# Bad (N+1 queries)
posts = BlogPost.objects.all()
for post in posts:
    print(post.author.name)  # Queries for each post!

# Good (2 queries)
posts = BlogPost.objects.select_related('author').all()
for post in posts:
    print(post.author.name)  # No extra queries
```

### 🟢 Nice to Have (Optional)

#### 11. Preconnect to External Resources

```html
<!-- In your <head> -->
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://cdn.jsdelivr.net">
<link rel="dns-prefetch" href="https://www.google-analytics.com">
```

#### 12. Resource Hints

```html
<!-- Preload critical resources -->
<link rel="preload" href="/static/css/style.css" as="style">
<link rel="preload" href="/static/js/alpine.js" as="script">

<!-- Prefetch next page (for blogs) -->
<link rel="prefetch" href="/blog/next-article/">
```

#### 13. Service Worker for Offline Support

```javascript
// /static/js/sw.js
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open('hookprobe-v1').then((cache) => {
            return cache.addAll([
                '/',
                '/static/css/style.css',
                '/static/js/alpine.js',
                '/static/images/logo.png'
            ]);
        })
    );
});

self.addEventListener('fetch', (event) => {
    event.respondWith(
        caches.match(event.request).then((response) => {
            return response || fetch(event.request);
        })
    );
});
```

```html
<!-- Register in your main template -->
<script>
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/static/js/sw.js');
}
</script>
```

---

## 📊 Before/After Comparison

### Heavy Stack (ThemeForest Template)

```
Page Size:        2 MB
CSS:              400 KB
JavaScript:       800 KB
Images:           800 KB

Load Time on LTE:
  Transfer:       2 MB ÷ 5.375 MB/s = 372ms
  Latency:        + 200ms (loaded)
  Server:         + 300ms (Django processing)
  ────────────────────────────────────
  Total TTFB:     872ms

Concurrent Capacity: 5 users max
Monthly Bandwidth (10k views):
  10,000 × 2 MB = 20 GB upload
```

**Result**: ❌ Barely usable, saturates quickly

---

### Light Stack (HTML5 UP + Cloudflare)

```
Page Size:        100 KB
CSS:              15 KB (Tailwind purged)
JavaScript:       30 KB (Alpine.js)
Images:           40 KB (WebP)
HTML:             15 KB

Cloudflare Cache: 95% hit rate

Cached Load Time (95% of requests):
  Edge server:    ~50ms (from nearest Cloudflare datacenter)

Uncached Load Time (5% of requests):
  Transfer:       100 KB ÷ 5.375 MB/s = 18ms
  Latency:        + 56ms (unloaded with QoS)
  Server:         + 50ms (Nginx microcache)
  ────────────────────────────────────
  Total TTFB:     124ms

Concurrent Capacity: 20 users
Monthly Bandwidth (10k views):
  With 95% cache: 500 MB upload
  Without cache:  1 GB upload
```

**Result**: ✅ **7x faster, 4x more users, 40x less bandwidth**

---

## 🎯 Realistic Capacity Estimates

### Monthly Traffic Capacity

| Pageviews/Month | Light Stack | Heavy Stack |
|-----------------|-------------|-------------|
| **100,000** | ✅ Easy | ⚠️ Possible |
| **500,000** | ✅ Easy | ❌ Impossible |
| **1,000,000** | ✅ Easy | ❌ Impossible |
| **5,000,000** | ✅ Possible | ❌ Impossible |
| **10,000,000** | ⚠️ Need image CDN | ❌ Impossible |

**Bandwidth Usage** (with 95% Cloudflare cache):

```
1M pageviews/month:
  50,000 hits to SBC × 100 KB = 5 GB upload/month
  = ~165 MB/day
  = ~7 MB/hour average
  
5M pageviews/month:
  250,000 hits to SBC × 100 KB = 25 GB upload/month
  = ~830 MB/day
  = ~35 MB/hour average
  
10M pageviews/month:
  500,000 hits to SBC × 100 KB = 50 GB upload/month
  = ~1.7 GB/day
  = ~70 MB/hour average
```

All well within 43 Mbps capacity! ✅

---

## 🛠️ Implementation Guide

### Step-by-Step Setup

#### Phase 1: Cloudflare Configuration (30 minutes)

1. **Sign up for Cloudflare** (free tier):
   - Go to https://dash.cloudflare.com/sign-up
   - Add your domain
   - Update nameservers at your registrar

2. **Create Cloudflare Tunnel**:
   - Dashboard → Zero Trust → Access → Tunnels
   - Create tunnel → Name: `hookprobe-tunnel`
   - Copy token → Save to `network-config.sh`

3. **Configure caching**:
   - Caching → Configuration → Cache Level: Standard
   - Create 4 page rules (see "Configure Cloudflare Caching" section)

4. **Enable optimizations**:
   - Speed → Optimization → Auto Minify: ON (all)
   - Speed → Optimization → Brotli: ON

#### Phase 2: SBC Optimization (45 minutes)

1. **Install QoS**:
   ```bash
   sudo dnf install -y iproute-tc
   sudo tc qdisc add dev wwan0 root cake bandwidth 40mbit diffserv4
   ```

2. **Create tmpfs for static files**:
   ```bash
   sudo mkdir -p /var/www/static
   sudo mount -t tmpfs -o size=512M tmpfs /var/www/static
   sudo podman cp hookprobe-pod-001-web-dmz-django:/app/static/. /var/www/static/
   echo "tmpfs /var/www/static tmpfs size=512M,uid=nginx,gid=nginx 0 0" | sudo tee -a /etc/fstab
   ```

3. **Update Nginx config**:
   - Copy complete config from "Layer 2: Nginx Microcache" section
   - Restart Nginx container

4. **Convert images to WebP**:
   ```bash
   sudo dnf install -y libwebp-tools
   find /var/www/static -name "*.jpg" -o -name "*.png" | while read img; do
       cwebp -q 80 "$img" -o "${img%.*}.webp"
   done
   ```

#### Phase 3: Testing & Validation (30 minutes)

1. **Test Cloudflare cache**:
   ```bash
   curl -I https://yourdomain.com
   # Look for: cf-cache-status: HIT
   ```

2. **Test Nginx cache**:
   ```bash
   curl -I http://localhost/blog/
   # Look for: X-Cache-Status: HIT
   ```

3. **Run Lighthouse audit**:
   - Open Chrome DevTools
   - Lighthouse tab
   - Run audit
   - Target: Score >90

4. **Load test**:
   ```bash
   # Install Apache Bench
   sudo dnf install -y httpd-tools
   
   # Test 100 requests, 10 concurrent
   ab -n 100 -c 10 https://yourdomain.com/
   
   # Should handle without errors
   ```

5. **Monitor bandwidth**:
   ```bash
   # Install vnstat
   sudo dnf install -y vnstat
   sudo systemctl enable --now vnstat
   
   # Monitor LTE interface
   vnstat -i wwan0 -l
   
   # Check monthly usage
   vnstat -i wwan0 -m
   ```

---

## 📱 Monitoring & Maintenance

### Daily Checks

```bash
# Check Cloudflare tunnel status
podman logs --tail 20 hookprobe-pod-001-web-dmz-cloudflared

# Check Nginx cache hit rate
tail -100 /var/log/nginx/access.log | grep -o "Cache:[A-Z]*" | sort | uniq -c

# Monitor bandwidth
vnstat -i wwan0 -d

# Check QoS
tc -s qdisc show dev wwan0
```

### Weekly Checks

1. **Cloudflare analytics**:
   - Dashboard → Analytics → Traffic
   - Check cache hit rate (should be >90%)
   - Review bandwidth savings

2. **Performance audit**:
   - Run Lighthouse
   - Check for degradation
   - Review slow queries in Django logs

3. **Security**:
   - Check Qsecbit status
   - Review WAF blocks
   - Update containers

### Monthly Tasks

1. **Clear Nginx cache** (force fresh):
   ```bash
   sudo rm -rf /var/cache/nginx/*
   sudo systemctl restart nginx
   ```

2. **Optimize database**:
   ```bash
   podman exec hookprobe-pod-003-db-persistent-postgres \
     psql -U hookprobe_admin -d hookprobe_db -c "VACUUM ANALYZE;"
   ```

3. **Review bandwidth usage**:
   ```bash
   vnstat -i wwan0 -m
   # Should be <10 GB/month for light traffic
   ```

---

## 🎯 Success Metrics

### Performance Targets

| Metric | Target | How to Measure |
|--------|--------|----------------|
| **Lighthouse Score** | >90 | Chrome DevTools |
| **TTFB** (cached) | <100ms | Cloudflare Analytics |
| **TTFB** (uncached) | <300ms | curl -w "%{time_starttransfer}" |
| **Cache Hit Rate** | >90% | Cloudflare Dashboard |
| **Page Size** | <200KB | Browser DevTools → Network |
| **Concurrent Users** | 10-20 | Load testing (ab, siege) |
| **Monthly Bandwidth** | <10GB | vnstat |

### How to Test

```bash
# 1. Lighthouse (install Chrome)
google-chrome --headless --disable-gpu \
  --dump-dom https://yourdomain.com

# 2. TTFB
curl -w "TTFB: %{time_starttransfer}s\n" -o /dev/null -s https://yourdomain.com

# 3. Cache hit rate
# Check Cloudflare dashboard

# 4. Page size
curl -s https://yourdomain.com | wc -c

# 5. Load test
ab -n 1000 -c 20 https://yourdomain.com/

# 6. Bandwidth
vnstat -i wwan0
```

---

## 🚨 Troubleshooting

### Problem: High Latency (>300ms)

**Diagnosis**:
```bash
# Check loaded latency
ping -c 100 8.8.8.8 | tail -1

# Check if QoS is active
tc qdisc show dev wwan0
```

**Solutions**:
1. Ensure QoS/CAKE is running
2. Lower CAKE bandwidth limit: `40mbit → 38mbit`
3. Check for background uploads (system updates, backups)

### Problem: Low Cache Hit Rate (<80%)

**Diagnosis**:
```bash
# Check Nginx cache status
tail -100 /var/log/nginx/access.log | grep -o "Cache:[A-Z]*" | sort | uniq -c
```

**Solutions**:
1. Check Cloudflare page rules are correct
2. Verify cookies aren't breaking cache (check `proxy_cache_bypass`)
3. Increase cache TTL in Cloudflare

### Problem: Out of RAM (tmpfs)

**Diagnosis**:
```bash
df -h | grep tmpfs
```

**Solutions**:
1. Reduce tmpfs size: `512M → 256M`
2. Move only critical assets to tmpfs
3. Keep images on SSD

### Problem: Slow Database Queries

**Diagnosis**:
```python
# Enable query logging in Django
LOGGING = {
    'version': 1,
    'loggers': {
        'django.db.backends': {
            'level': 'DEBUG',
        },
    },
}
```

**Solutions**:
1. Add database indexes
2. Use `select_related()` / `prefetch_related()`
3. Enable Redis caching in Django

---

## ✅ Final Checklist

### Before Going Live

- [ ] Cloudflare Tunnel connected and working
- [ ] Cloudflare cache rules configured (4 page rules)
- [ ] QoS/CAKE enabled on LTE interface
- [ ] Nginx microcache configured
- [ ] Static files in tmpfs (RAM)
- [ ] Images converted to WebP
- [ ] Gzip/Brotli compression enabled
- [ ] Rate limiting configured (5 conn/IP, 10 req/sec)
- [ ] Lighthouse score >90
- [ ] Load test passed (100 concurrent requests)
- [ ] Bandwidth monitoring with vnstat
- [ ] Backup strategy in place

### Post-Launch Monitoring

- [ ] Daily: Check Cloudflare tunnel status
- [ ] Daily: Review Nginx cache hit rate
- [ ] Weekly: Run Lighthouse audit
- [ ] Weekly: Check bandwidth usage
- [ ] Monthly: Optimize database
- [ ] Monthly: Review Cloudflare analytics

---

## 📚 Additional Resources

### Documentation

- **Cloudflare Tunnel**: https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/
- **CAKE qdisc**: https://www.bufferbloat.net/projects/codel/wiki/Cake/
- **Nginx caching**: https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache
- **Django optimization**: https://docs.djangoproject.com/en/stable/topics/performance/

### Testing Tools

- **Lighthouse**: Built into Chrome DevTools
- **Apache Bench**: `sudo dnf install httpd-tools`
- **GTmetrix**: https://gtmetrix.com/
- **WebPageTest**: https://www.webpagetest.org/
- **vnStat**: `sudo dnf install vnstat`

### Performance Monitoring

- **Cloudflare Analytics**: Free in dashboard
- **Grafana**: Already in HookProbe POD 005
- **Prometheus**: Already in HookProbe POD 005
- **Google Analytics**: Add for visitor tracking

---

## 🎯 Summary

### Can You Host on LTE/CGNAT?

**YES** - with these requirements:

1. ✅ **Cloudflare Tunnel** (bypasses CGNAT)
2. ✅ **Lightweight stack** (<200KB pages)
3. ✅ **Aggressive caching** (95%+ hit rate)
4. ✅ **QoS/CAKE** (reduces bufferbloat)

### Expected Capacity

- **10-20 concurrent users**
- **1-5M pageviews/month**
- **<10 GB upload/month** (with caching)

### Performance

- **Cached**: 50-80ms (Cloudflare edge)
- **Uncached**: 150-250ms (acceptable)
- **Spikes**: 300-400ms (still usable)

### Why Lightweight Matters

- Heavy stack: **❌ 2-5 users max, barely functional**
- Light stack: **✅ 10-20 users, production-ready**

**This is why HTML5 UP + Tailwind + Alpine.js was recommended** - it's not just nice, it's **essential** for LTE hosting.

---

**Document Version**: 1.0  
**Last Updated**: November 2025  
**Author**: HookProbe Team  
**License**: MIT

For questions or issues, open a GitHub issue or contact: qsecbit@hookprobe.com
