#!/bin/sh
# secrets-init.sh — keep host secrets on the ENCRYPTED data volume, not the plaintext root (ADR 0007
# E2, closes flow-analysis gap #2). SSH host keys are the main secret generated on the root at first
# boot; generate them into /var/lib/hookprobe/secrets/ssh (encrypted) and point sshd there via a
# drop-in, so no host key ever lands on the unencrypted SD. Migrate + shred any plaintext originals.
# Runs AFTER the data volume is up (data-guard: encrypted, or degraded-tmpfs), BEFORE ssh.service.
# NOTE: in degraded (tmpfs) mode keys are volatile → host key changes each boot; acceptable — the
# encryption is already broken and QSECBIT flags it.
set -u
SEC=/var/lib/hookprobe/secrets
install -d -m0700 "$SEC" "$SEC/ssh"

# 1. Migrate any pre-existing plaintext host keys off the root, then shred the originals.
for k in /etc/ssh/ssh_host_*; do
  [ -e "$k" ] || continue
  b=$(basename "$k"); [ -e "$SEC/ssh/$b" ] || cp -a "$k" "$SEC/ssh/$b"
  shred -u "$k" 2>/dev/null || rm -f "$k"
done
# 2. Generate on the encrypted volume if missing.
[ -f "$SEC/ssh/ssh_host_ed25519_key" ] || ssh-keygen -q -t ed25519 -N '' -f "$SEC/ssh/ssh_host_ed25519_key" -C hookprobe
[ -f "$SEC/ssh/ssh_host_rsa_key" ]     || ssh-keygen -q -t rsa -b 3072 -N '' -f "$SEC/ssh/ssh_host_rsa_key" -C hookprobe
chmod 600 "$SEC"/ssh/ssh_host_*_key 2>/dev/null || true
chmod 644 "$SEC"/ssh/ssh_host_*_key.pub 2>/dev/null || true

# 3. Point sshd at the encrypted keys (drop-in is just paths, not secret). ssh.service starts after us.
install -d -m0755 /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/20-hookprobe-hostkeys.conf <<'EOF'
# SSH host keys live on the ENCRYPTED data volume (ADR 0007 E2), never the plaintext root.
HostKey /var/lib/hookprobe/secrets/ssh/ssh_host_ed25519_key
HostKey /var/lib/hookprobe/secrets/ssh/ssh_host_rsa_key
EOF
echo "secrets-init: SSH host keys on encrypted volume ($SEC/ssh); sshd pointed there"
