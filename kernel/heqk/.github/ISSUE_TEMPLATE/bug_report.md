---
name: Bug Report
about: Report a bug or issue with HookProbe deployment or operation
title: '[BUG] '
labels: bug
assignees: ''
---

## 🐛 Bug Description

**Clear description of the bug:**
<!-- Describe what's wrong in 1-2 sentences -->

## 📋 Environment

**HookProbe Version:**
<!-- e.g., v5.0.0 -->

**Operating System:**
<!-- e.g., Ubuntu 24.04, Debian 12, Raspberry Pi OS (Bookworm) -->

**Podman Version:**
```bash
podman --version
```

**Hardware:**
- **CPU:** <!-- e.g., Intel N100, Raspberry Pi 5 -->
- **RAM:** <!-- e.g., 16GB -->
- **Storage:** <!-- e.g., 500GB SSD -->

## 🔄 Steps to Reproduce

1. <!-- First step -->
2. <!-- Second step -->
3. <!-- Third step -->
4. <!-- See error -->

## ✅ Expected Behavior

<!-- What should happen -->

## ❌ Actual Behavior

<!-- What actually happens -->

## 📊 Logs and Output

**Deployment logs (if applicable):**
```bash
# Output from setup.sh
```

**Container logs:**
```bash
podman logs <container-name>
```

**POD status:**
```bash
podman pod ps
podman ps -a
```

**Network status:**
```bash
ovs-vsctl show
```

## 📸 Screenshots

<!-- If applicable, add screenshots to help explain the problem -->

## 🔍 Additional Context

<!-- Any other information that might help -->

**Have you:**
- [ ] Changed default credentials in `network-config.sh`?
- [ ] Checked the deployment checklist (`Scripts/autonomous/install/checklist.md`)?
- [ ] Run `uninstall.sh` before re-deploying?
- [ ] Verified network `10.200.0.0/16` is available?
- [ ] Checked firewall rules?

## 💡 Possible Solution

<!-- If you have ideas on how to fix this, share them here -->
