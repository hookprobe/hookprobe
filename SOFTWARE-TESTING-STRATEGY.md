# Software Testing Strategy for HookProbe MSSP
## Raspberry Pi 4 (4GB RAM) - Web Services Only

> **⚠️ IMPORTANT: This document is for TESTING and DEVELOPMENT only**
>
> **For Production Installation**, see:
> - **[QUICK-START.md](QUICK-START.md)** - Interactive 3-step installation
> - **[install/edge/README.md](install/edge/README.md)** - Edge deployment guide
> - **[install/cloud/README.md](install/cloud/README.md)** - Cloud/MSSP deployment
> - **[DOCUMENTATION-INDEX.md](DOCUMENTATION-INDEX.md)** - Complete documentation guide
>
> This document covers testing infrastructure for developers, QA teams, and CI/CD pipelines.

**Target Platform:** Raspberry Pi 4 Model B (4GB RAM)
**Scope:** Web-related services testing (POD-001, POD-002, POD-003, POD-005)
**Excluded:** AI workloads (POD-007), Heavy monitoring (POD-004 Grafana stack)
**Budget:** Minimal - Using existing hardware and free/open-source tools
**Container Runtime:** Podman-only (no Docker)

---

## 🎯 Testing Objectives

1. Validate web application functionality (Django + NAXSI/ModSecurity WAF)
2. Verify IAM integration (Logto authentication flows)
3. Test configuration management (unified config system)
4. Ensure database operations (PostgreSQL migrations, queries)
5. Validate container deployments (Podman on ARM64)
6. Performance testing under resource constraints (4GB RAM)

---

## 📋 Three Testing Strategies

### Strategy 1: Native Raspberry Pi Testing (Direct Hardware)

**Approach:** Install and test directly on Raspberry Pi 4 hardware

**Setup:**
```bash
# Hardware: Raspberry Pi 4 (4GB RAM)
# OS: Ubuntu Server 22.04 LTS ARM64 or Raspberry Pi OS (64-bit)
# Storage: 32GB+ microSD card (Class 10/UHS-I) or USB 3.0 SSD

# Services to run:
- POD-001: Web Server (Django + Gunicorn + Nginx)
- POD-002: IAM (Logto - optional, can use mock auth)
- POD-003: Database (PostgreSQL 16 - lightweight config)
- POD-005: Network Manager (basic routing/firewall)
```

**Testing Process:**
1. **Installation Testing:**
   - Run lightweight installation: `cd install/testing && sudo bash lightweight-setup.sh`
   - OR use interactive wizard: `sudo ./install.sh` → Select "Lightweight Testing"
   - Validate each POD starts successfully: `podman pod ps`
   - Check memory usage: `free -h` and `podman stats`
   - Verify containers: `podman ps -a`

2. **Functional Testing:**
   - Manual UI testing via web browser (http://localhost)
   - Django admin panel verification (http://localhost/admin)
   - User authentication flows (login/logout/signup)
   - CRUD operations on blog posts, pages
   - WAF rule triggering (test XSS/SQLi payloads)

3. **Integration Testing:**
   - Database connectivity tests: `podman exec hookprobe-database-postgres pg_isready`
   - IAM token validation (Logto at http://localhost:3002)
   - Inter-POD communication (web → database → cache)
   - Configuration reload tests

4. **Performance Testing:**
   - Apache Bench (ab) for load testing: `ab -n 1000 -c 10 http://localhost/`
   - Monitor with `htop`, `free -h`, `podman stats`
   - Measure response times under load
   - Identify memory/CPU bottlenecks

**Pros:**
- ✅ True hardware representation
- ✅ Actual ARM64 performance metrics
- ✅ Real-world I/O and network behavior
- ✅ No virtualization overhead
- ✅ Tests exact deployment scenario

**Cons:**
- ❌ Requires physical Raspberry Pi hardware
- ❌ Slow test iteration (flashing SD cards, reboots)
- ❌ Single test environment (can't run parallel tests)
- ❌ Risk of SD card corruption during testing
- ❌ Difficult to snapshot/restore state
- ❌ Manual setup/teardown for each test cycle

**Resource Requirements:**
- Hardware: 1x Raspberry Pi 4 (4GB) - $55-75
- Storage: 32GB microSD or USB SSD - $10-30
- Power supply: Official USB-C adapter - $8-12
- Total: ~$73-117

---

### Strategy 2: QEMU ARM64 Emulation (Virtual Hardware)

**Approach:** Emulate ARM64 Raspberry Pi on x86_64 development machine

**Setup:**
```bash
# Host: Any x86_64 Linux/macOS/Windows machine
# Emulator: QEMU with ARM64 virtualization
# Guest OS: Ubuntu Server 22.04 ARM64 or Raspberry Pi OS

# Installation:
sudo apt install qemu-system-arm qemu-efi-aarch64 qemu-utils

# Create VM:
qemu-img create -f qcow2 rpi-test.qcow2 32G

qemu-system-aarch64 \
  -M virt \
  -cpu cortex-a72 \
  -smp 4 \
  -m 4096 \
  -bios /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
  -device virtio-net-pci,netdev=net0 \
  -netdev user,id=net0,hostfwd=tcp::8080-:80,hostfwd=tcp::8443-:443 \
  -device virtio-blk-device,drive=hd0 \
  -drive if=none,file=rpi-test.qcow2,format=qcow2,id=hd0 \
  -nographic
```

**Testing Process:**
1. **Automated Testing:**
   - Snapshot VM before tests (`qemu-img snapshot`)
   - Run installation scripts via SSH
   - Execute pytest/Django test suite
   - Restore snapshot for clean state

2. **CI/CD Integration:**
   - GitHub Actions self-hosted runner on x86_64
   - QEMU ARM64 emulation in workflow
   - Automated test execution on every commit

3. **Scripted Test Scenarios:**
   ```bash
   # test-runner.sh
   snapshot_create "clean-base"
   run_installation_tests
   snapshot_restore "clean-base"
   run_functional_tests
   snapshot_restore "clean-base"
   run_performance_tests
   ```

**Pros:**
- ✅ No physical hardware required
- ✅ Fast snapshot/restore (seconds)
- ✅ Scriptable and automatable
- ✅ Can run on CI/CD infrastructure
- ✅ Easy to replicate environments
- ✅ Can run multiple VMs in parallel
- ✅ Safe experimentation (isolated)

**Cons:**
- ❌ Slower than native (QEMU emulation overhead ~2-10x)
- ❌ Performance metrics not accurate
- ❌ Some hardware-specific issues may not appear
- ❌ Requires x86_64 host with good specs (8GB+ RAM, 4+ cores)
- ❌ Network emulation differs from real hardware
- ❌ Peripheral testing limited (GPIO, USB, etc.)

**Resource Requirements:**
- Hardware: Existing development laptop/desktop
- Host specs: 8GB+ RAM, 4+ CPU cores, 50GB+ disk
- Total: $0 (using existing hardware)

---

### Strategy 3: Hybrid Podman Container Testing (Lightweight)

**Approach:** Test individual components in ARM64 containers using Podman, full integration on Pi

**Setup:**
```bash
# Host: x86_64 machine with Podman
# Multi-arch builds: ARM64 containers on x86_64 via QEMU user-mode

# Install Podman and dependencies:
sudo apt install podman qemu-user-static
pip3 install podman-compose

# Enable ARM64 emulation:
podman run --rm --privileged multiarch/qemu-user-static --reset -p yes

# Build ARM64 containers with Podman:
podman build --arch arm64 -t hookprobe-web:arm64 .
```

**Testing Process:**
1. **Unit Testing (Development Machine):**
   - Run Django unit tests in ARM64 container
   - Test individual POD functionality
   - Database migration testing
   - Fast iteration on x86_64 host

2. **Component Testing (Containers):**
   ```yaml
   # docker-compose-test.yml
   services:
     web:
       platform: linux/arm64
       image: hookprobe-web:arm64
       mem_limit: 1g
       cpus: 2

     db:
       platform: linux/arm64
       image: postgres:16-alpine
       mem_limit: 512m

     iam:
       platform: linux/arm64
       image: logto:latest
       mem_limit: 512m
   ```

3. **Integration Testing (Raspberry Pi):**
   - Deploy containers to actual Pi hardware
   - Full system integration tests
   - Real performance validation
   - End-to-end user acceptance testing

**Testing Layers:**
```
Layer 1: Unit Tests (x86_64 native) - Fast feedback (seconds)
Layer 2: Container Tests (ARM64 emulated) - Component validation (minutes)
Layer 3: Integration Tests (Pi hardware) - Full system (hours/days)
```

**Pros:**
- ✅ Best of both worlds (fast dev + real hardware validation)
- ✅ Resource-efficient (Podman containers vs full VMs)
- ✅ CI/CD friendly (Podman in GitHub Actions)
- ✅ Mimics actual deployment (Podman containers on Pi)
- ✅ Easy to isolate and test individual services
- ✅ Fast unit test iteration
- ✅ Reliable integration testing on real hardware
- ✅ Rootless container support with Podman
- ✅ Docker-compatible but more secure

**Cons:**
- ❌ More complex setup (multi-arch tooling)
- ❌ Still requires Pi for final integration tests
- ❌ Container overhead on Pi (though minimal)
- ❌ ARM64 emulation still slower for containers
- ❌ Need to manage both container and native deployments

**Resource Requirements:**
- Hardware: 1x Raspberry Pi 4 (4GB) for integration - $55-75
- Development machine: Existing laptop/desktop
- Total: ~$55-75

---

## 🔬 Analysis: Which Strategy to Apply?

### Decision Matrix

| Criteria | Strategy 1 (Native) | Strategy 2 (QEMU) | Strategy 3 (Hybrid) |
|----------|---------------------|-------------------|---------------------|
| **Cost** | Medium ($73-117) | Free ($0) | Low ($55-75) |
| **Speed** | Slow (manual) | Medium (automated) | Fast (hybrid) |
| **Accuracy** | Perfect | Low (emulated) | High (real HW final) |
| **Automation** | Difficult | Excellent | Good |
| **CI/CD** | Not feasible | Excellent | Good |
| **Iteration** | Slow | Fast | Very Fast |
| **Learning Curve** | Low | Medium | High |
| **Maintenance** | High | Low | Medium |

### Budget Considerations

**Absolute Minimum Budget ($0):**
- Use Strategy 2 (QEMU) exclusively
- Accept slower performance and less accurate results
- Suitable for initial development and unit testing

**Low Budget ($55-75):**
- Use Strategy 3 (Hybrid)
- Fast development iteration + real hardware validation
- Best ROI for testing accuracy vs cost

**Full Testing Setup ($150-200):**
- Strategy 3 + additional Raspberry Pi for dedicated test environment
- Separate dev and production-like test hardware
- Can run parallel tests

### Recommendations by Use Case

**For Initial Development (Phase 3-4):**
→ **Strategy 2 (QEMU)** or **Strategy 3 (Hybrid - containers only)**
- Fast iteration without hardware
- Focus on functionality, not performance
- Good for TDD and unit testing

**For Integration Testing (Phase 5-6):**
→ **Strategy 3 (Hybrid)**
- Validate component interactions
- Test on real ARM64 hardware
- Catch platform-specific issues

**For Performance Testing (Phase 7+):**
→ **Strategy 1 (Native)** on real Pi
- Accurate memory/CPU measurements
- Real I/O performance
- Identify optimization opportunities

**For CI/CD Automation:**
→ **Strategy 2 (QEMU)** or **Strategy 3 (Container layer)**
- Automated test execution
- Fast feedback on PRs
- Parallel test execution

---

## ✅ Final Recommended Strategy

### **Strategy 3 (Hybrid) + Incremental Hardware Investment**

**Phase 1: Development & Unit Testing (Week 1-4)**
- Use multi-arch containers on development machine
- Run Django unit tests, pytest suite
- Fast iteration on features
- **Cost: $0** (using existing hardware)

**Phase 2: Component Testing (Week 5-8)**
- ARM64 container integration tests
- Docker Compose multi-service validation
- Database migration testing
- **Cost: $0** (still using dev machine)

**Phase 3: Hardware Integration (Week 9+)**
- Purchase 1x Raspberry Pi 4 (4GB) setup
- Deploy containers to real hardware
- Full integration testing
- Performance validation
- **Cost: $55-75** (one-time hardware purchase)

**Phase 4: Production-Like Testing (Optional)**
- Add second Raspberry Pi for staging environment
- Separate dev/test/production environments
- **Cost: +$55-75** (if needed)

---

## 🛠️ Implementation Plan

### Step 1: Set Up Development Environment (Day 1-2)

**Prerequisites:**
```bash
# Install Podman with multi-arch support
sudo apt update
sudo apt install podman qemu-user-static python3-pip

# Install podman-compose
pip3 install podman-compose

# Verify Podman installation
podman --version

# Enable ARM64 emulation
podman run --rm --privileged multiarch/qemu-user-static --reset -p yes
```

**Create Test Configuration:**
```bash
# File: docker-compose.test.yml
version: '3.8'

services:
  web-test:
    platform: linux/arm64
    build:
      context: ./src/web
      dockerfile: Dockerfile.test
    environment:
      DJANGO_ENV: test
      POSTGRES_HOST: db-test
    depends_on:
      - db-test
    mem_limit: 1g
    cpus: "2.0"

  db-test:
    platform: linux/arm64
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: hookprobe_test
      POSTGRES_USER: hookprobe
      POSTGRES_PASSWORD: test_password
    mem_limit: 512m
    cpus: "1.0"
```

### Step 2: Create Test Scripts (Day 3)

**Unit Test Runner:**
```bash
#!/bin/bash
# scripts/run-unit-tests.sh

set -e

echo "🧪 Running unit tests in ARM64 container..."

podman build \
  --arch arm64 \
  -t hookprobe-web-test:latest \
  -f src/web/Dockerfile.test \
  src/web

podman run --rm \
  -e DJANGO_ENV=test \
  hookprobe-web-test:latest \
  pytest --cov=apps --cov-report=term-missing

echo "✅ Unit tests completed"
```

**Integration Test Runner:**
```bash
#!/bin/bash
# scripts/run-integration-tests.sh

set -e

echo "🔗 Running integration tests..."

# Start services
podman-compose -f docker-compose.test.yml up -d

# Wait for services
sleep 10

# Run migrations
podman-compose -f docker-compose.test.yml exec -T web-test \
  python manage.py migrate --noinput

# Run integration tests
podman-compose -f docker-compose.test.yml exec -T web-test \
  pytest tests/integration/ -v

# Cleanup
podman-compose -f docker-compose.test.yml down -v

echo "✅ Integration tests completed"
```

**Performance Baseline Test:**
```bash
#!/bin/bash
# scripts/run-performance-tests.sh

set -e

echo "📊 Running performance baseline tests..."

# Start services
podman-compose -f docker-compose.test.yml up -d

# Wait for readiness
sleep 15

# Get container name
WEB_CONTAINER="hookprobe-web-test"

# Run Apache Bench test inside container
podman exec $WEB_CONTAINER ab -n 1000 -c 10 http://localhost:8000/ > performance-results.txt

echo "✅ Performance tests completed"
echo "Results saved to: performance-results.txt"

podman-compose -f docker-compose.test.yml down
```

### Step 3: Configure CI/CD (Day 4)

**GitHub Actions Workflow:**
```yaml
# .github/workflows/arm64-tests.yml
name: ARM64 Integration Tests (Podman)

on:
  push:
    branches: [ main, 'claude/**' ]
  pull_request:
    branches: [ main ]

jobs:
  test-arm64:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Install Podman and dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y podman qemu-user-static python3-pip
          pip3 install podman-compose
          podman --version

      - name: Set up QEMU for ARM64 emulation
        run: |
          podman run --rm --privileged multiarch/qemu-user-static --reset -p yes

      - name: Build ARM64 test image with Podman
        run: |
          podman build \
            --arch arm64 \
            -t hookprobe-web-test:arm64 \
            -f src/web/Dockerfile.test \
            src/web

      - name: Run unit tests
        run: |
          podman run --rm \
            -e DJANGO_ENV=test \
            hookprobe-web-test:arm64 \
            pytest --cov=apps -v

      - name: Run integration tests
        run: |
          podman-compose -f docker-compose.test.yml up -d
          sleep 10
          podman-compose -f docker-compose.test.yml exec -T web-test \
            python manage.py test
          podman-compose -f docker-compose.test.yml down -v
```

### Step 4: Raspberry Pi Hardware Testing (Week 2+)

**When Hardware Arrives:**
```bash
# SSH into Raspberry Pi
ssh ubuntu@raspberrypi.local

# Install required packages
sudo apt update
sudo apt install podman python3-pip git

# Clone repository
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe

# Option 1: Interactive installation (Recommended)
sudo ./install.sh
# Select: 2) Select Deployment Mode
# Choose: 3) Lightweight Testing (Raspberry Pi 4 / Development)

# Option 2: Direct lightweight installation
cd install/testing
sudo bash lightweight-setup.sh

# Verify installation
podman pod ps        # Check pods
podman ps -a         # Check containers
podman stats         # Check resource usage

# Test web access
curl http://localhost
curl http://localhost/admin

# Monitor resources
htop
free -h
df -h
```

**Hardware Test Checklist:**
- [ ] All PODs start successfully (web, database, cache, iam)
- [ ] Web UI accessible: `http://raspberry-pi-ip/`
- [ ] Django admin accessible: `http://raspberry-pi-ip/admin`
- [ ] Database migrations complete
- [ ] Logto IAM accessible: `http://raspberry-pi-ip:3002`
- [ ] User login/logout works
- [ ] Blog CRUD operations function
- [ ] WAF blocks malicious requests
- [ ] Memory usage < 3GB under load
- [ ] Response time < 500ms (simple pages)
- [ ] System stable for 24+ hours

### Step 5: Create Test Reports (Ongoing)

**Test Result Template:**
```markdown
# Test Report - [Date]

## Environment
- **Platform:** ARM64 Container / Raspberry Pi 4 (4GB)
- **OS:** Ubuntu Server 22.04 ARM64
- **Kernel:** 5.15.0
- **PODs Tested:** 001, 002, 003, 005

## Unit Tests
- Total: 127 tests
- Passed: 125 ✅
- Failed: 2 ❌
- Duration: 45 seconds

## Integration Tests
- Database connectivity: ✅ PASS
- IAM authentication: ✅ PASS
- WAF rule enforcement: ✅ PASS
- Configuration reload: ❌ FAIL (timeout)

## Performance Tests
- Concurrent users: 10
- Requests: 1000
- Avg response time: 145ms
- Memory usage: 2.1GB
- CPU usage: 65%

## Issues Found
1. Configuration reload causes 5s timeout
2. Database connection pool exhaustion at >20 concurrent users

## Action Items
- [ ] Optimize config reload mechanism
- [ ] Increase PostgreSQL max_connections to 50
- [ ] Add connection pooling (pgbouncer)
```

---

## 📈 Success Metrics

**Week 1-4 Goals:**
- ✅ 100% unit test coverage for critical paths
- ✅ All CI/CD tests passing on ARM64 containers
- ✅ Docker Compose multi-service stack working

**Week 5-8 Goals:**
- ✅ Integration tests automated and reliable
- ✅ Performance baseline established
- ✅ Container images optimized (<500MB each)

**Week 9+ Goals:**
- ✅ Hardware validation complete on Raspberry Pi
- ✅ Memory usage < 3GB under normal load
- ✅ System stable for 7+ days continuous operation
- ✅ All PODs (001, 002, 003, 005) functioning correctly

---

## 💰 Total Budget Breakdown

### Minimum Viable Testing Setup
- **Development machine:** $0 (existing hardware)
- **QEMU/Docker setup:** $0 (free software)
- **CI/CD:** $0 (GitHub Actions free tier)
- **Total: $0**

### Recommended Setup (Hybrid)
- **Development machine:** $0 (existing)
- **Raspberry Pi 4 (4GB):** $55-75
- **32GB microSD (UHS-I):** $8-12
- **USB-C power supply:** $8-12
- **Total: $71-99**

### Optimal Setup (Staging + Production)
- **Above setup:** $71-99
- **Second Raspberry Pi 4:** $55-75
- **Network switch (5-port):** $15-20
- **Ethernet cables:** $10-15
- **Total: $151-209**

---

## 🎓 Learning Resources

**Multi-arch Docker:**
- https://www.docker.com/blog/multi-arch-build-and-images-the-simple-way/
- https://docs.docker.com/build/building/multi-platform/

**QEMU ARM64 Emulation:**
- https://www.qemu.org/docs/master/system/target-arm.html
- https://wiki.debian.org/Arm64Qemu

**Raspberry Pi Testing:**
- https://www.raspberrypi.com/documentation/computers/getting-started.html
- https://ubuntu.com/download/raspberry-pi

**Django Testing:**
- https://docs.djangoproject.com/en/5.0/topics/testing/
- https://pytest-django.readthedocs.io/

---

## 🚀 Quick Start

```bash
# 1. Clone repository
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe

# 2. Set up multi-arch support
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes

# 3. Run unit tests (ARM64)
./scripts/run-unit-tests.sh

# 4. Run integration tests (ARM64 containers)
./scripts/run-integration-tests.sh

# 5. (Optional) Deploy to Raspberry Pi hardware
ssh ubuntu@raspberrypi.local
git clone https://github.com/hookprobe/hookprobe.git
cd hookprobe && sudo ./install/install-pod-001.sh
```

---

## 📝 Next Steps

1. **Immediate (This Week):**
   - [ ] Set up Docker Buildx with ARM64 support
   - [ ] Create `Dockerfile.test` for web application
   - [ ] Write initial unit test suite
   - [ ] Configure GitHub Actions for ARM64 CI

2. **Short-term (Next 2 Weeks):**
   - [ ] Build integration test suite
   - [ ] Create docker-compose.test.yml
   - [ ] Establish performance baselines
   - [ ] Document test procedures

3. **Long-term (Month 2+):**
   - [ ] Order Raspberry Pi 4 hardware
   - [ ] Validate on real hardware
   - [ ] Create staging environment
   - [ ] Set up monitoring/alerting

---

**Document Version:** 1.0
**Last Updated:** 2025-12-02
**Owner:** HookProbe Development Team
**Status:** Draft - Ready for Implementation
