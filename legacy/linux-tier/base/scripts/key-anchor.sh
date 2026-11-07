#!/bin/sh
# key-anchor.sh — self-detecting root-of-trust for the data-volume master key (ADR 0007 E3).
# ONE HookProbe OS across every board (Pi 4/5, CM5, Radxa, Waveshare, Banana Pi, N100, VM): it detects
# the BEST anchor the hardware actually has and wraps/unwraps the dm-crypt master key with it. This is
# "capabilities, not branches" applied to encryption — the code never asks "is this a CM5?", it asks
# "can this box seal to a TPM / OTP / …?". Detect ONCE (at provisioning), store the choice, query forever.
#
#   Anchors, best → weakest:
#     passphrase : customer-managed (openssl AES-256-CBC + PBKDF2 600k KEK; Argon2 when the argon2 CLI
#                  is added to the image) — strongest secrecy, opt-in via the wizard (E4c). The
#                  passphrase is NEVER stored; it's supplied per boot (pp_source).
#     tpm        : systemd-creds --with-key=tpm2 — hardware-bound (N100 fTPM, CM5 fTPM, any TPM HAT)
#     cm5-otp    : CM5 OTP secure-boot key — device-bound (STUB: full impl when a CM5 arrives)
#     tang       : network-bound (Clevis/Tang) — fleet, additive
#     software   : plaintext factory key on /etc — WEAK fallback (bare boards w/o a root of trust)
#
#   Usage:  key-anchor.sh detect                 → the anchor this box can use (functional probe)
#           key-anchor.sh wrap <keyfile>         → wrap the master key with the detected anchor
#           key-anchor.sh unwrap                 → print the master key (stdout) via the stored anchor
#           key-anchor.sh enroll-passphrase      → re-wrap under a passphrase (stdin); flip to passphrase
#                                                  tier; drop the old factory anchor (the wizard calls this)
set -u
KD=/etc/hookprobe/keys
ANCHOR_STATE="$KD/anchor"
install -d -m0700 "$KD" 2>/dev/null || true

# Runtime passphrase source for the `passphrase` anchor — the passphrase is NEVER stored on disk; the
# wizard/admin supplies it per boot via (in order): an env var, a /run (tmpfs) drop the wizard writes,
# or an interactive console prompt. Empty result → unlock fails → data-guard fails closed (correct).
pp_source() {
  [ -n "${HOOKPROBE_PASSPHRASE:-}" ] && { printf '%s' "$HOOKPROBE_PASSPHRASE"; return; }
  [ -f /run/hookprobe-passphrase ] && { cat /run/hookprobe-passphrase; return; }
  command -v systemd-ask-password >/dev/null 2>&1 && systemd-ask-password --timeout=0 "HookProbe data-volume passphrase:"
}

# ── detect: FUNCTIONAL probe (not mere device presence — the dev box has a TPM but no tpm2 libs) ──
detect() {
  # customer passphrase enrolled → always wins (strongest, explicit operator choice)
  [ -f "$KD/data.pass.enc" ] && { echo passphrase; return; }
  # TPM: actually try a seal (handles "partial" TPMs missing libtss2 → falls through). NB: systemd-creds
  # writes the cred to the OUTPUT PATH — as root, passing "/dev/null" CLOBBERS it into a regular file and
  # breaks the whole system, so probe to a real temp file and remove it.
  if [ -e /dev/tpmrm0 ]; then
    _pp="$(mktemp)"
    if printf x | systemd-creds encrypt --with-key=tpm2 --name=hp-probe - "$_pp" >/dev/null 2>&1; then
      rm -f "$_pp"; echo tpm; return
    fi
    rm -f "$_pp"
  fi
  # CM5 OTP secure-boot key (device-bound). STUB: detect the board; real OTP-wrap lands with CM5 hw.
  if grep -qiE "Compute Module 5|CM5" /proc/device-tree/model 2>/dev/null && [ -f "$KD/anchor.cm5otp" ]; then
    echo cm5-otp; return
  fi
  # network-bound (Clevis/Tang) if a Tang policy is configured
  [ -f /etc/hookprobe/tang.json ] && command -v clevis >/dev/null 2>&1 && { echo tang; return; }
  echo software
}

wrap() {  # $1 = plaintext master-key file
  a=$(detect)
  case "$a" in
    tpm)        systemd-creds encrypt --with-key=tpm2 --name=hookprobe-data "$1" "$KD/data.tpm.cred" ;;
    passphrase) pp_source | openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -in "$1" -out "$KD/data.pass.enc" -pass stdin ;;
    tang)       clevis encrypt tang "$(cat /etc/hookprobe/tang.json)" < "$1" > "$KD/data.tang.jwe" ;;
    cm5-otp)    install -m0400 "$1" "$KD/data.key"; echo "key-anchor: cm5-otp STUB → stored software-style (harden on CM5)" >&2 ;;
    software|*) install -m0400 "$1" "$KD/data.key" ;;
  esac
  echo "$a" > "$ANCHOR_STATE"
  echo "key-anchor: master key wrapped with anchor=$a" >&2
}

unwrap() {  # → master key on stdout
  a=$(cat "$ANCHOR_STATE" 2>/dev/null || detect)
  case "$a" in
    tpm)        systemd-creds decrypt --name=hookprobe-data "$KD/data.tpm.cred" - ;;
    passphrase) pp_source | openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in "$KD/data.pass.enc" -pass stdin ;;
    tang)       clevis decrypt < "$KD/data.tang.jwe" ;;
    software|cm5-otp|*) cat "$KD/data.key" ;;
  esac
}

# enroll-passphrase — re-wrap the EXISTING master key under a customer passphrase (read from stdin),
# flip the anchor to `passphrase`, and remove the old (weaker) factory anchor so ONLY the passphrase
# unlocks. The MASTER KEY is unchanged, so the encrypted data stays readable — only its wrapping moves.
# Safe-ordered: build + VERIFY the passphrase blob before flipping the anchor, so any failure leaves the
# current anchor fully working. The passphrase is never written to disk (stdin → openssl only).
enroll_passphrase() {
  newpp="$(cat)"; [ -n "$newpp" ] || { echo "enroll: empty passphrase — refusing" >&2; return 1; }
  MK="$(mktemp /run/hp-mk.XXXXXX)"; chmod 600 "$MK"
  unwrap > "$MK" 2>/dev/null
  [ -s "$MK" ] || { shred -u "$MK" 2>/dev/null; echo "enroll: could not unwrap current master key (bad anchor state?)" >&2; return 1; }
  # wrap the current master key under the new passphrase (to a .new staging file)
  printf '%s' "$newpp" | openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -in "$MK" -out "$KD/data.pass.enc.new" -pass stdin 2>/dev/null
  # verify the round-trip BEFORE committing
  mkhash="$(sha256sum < "$MK" | cut -d' ' -f1)"
  dechash="$(printf '%s' "$newpp" | openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in "$KD/data.pass.enc.new" -pass stdin 2>/dev/null | sha256sum | cut -d' ' -f1)"
  shred -u "$MK" 2>/dev/null
  [ -n "$mkhash" ] && [ "$mkhash" = "$dechash" ] || { rm -f "$KD/data.pass.enc.new"; echo "enroll: verify FAILED — anchor unchanged" >&2; return 1; }
  # COMMIT atomically: passphrase blob in place, anchor flipped, old factory anchors removed
  mv "$KD/data.pass.enc.new" "$KD/data.pass.enc"; chmod 600 "$KD/data.pass.enc"
  echo passphrase > "$ANCHOR_STATE"
  rm -f "$KD/data.key" "$KD/data.tpm.cred" "$KD/data.tang.jwe"
  echo "enroll: passphrase enrolled — data volume now unlocks ONLY with the customer passphrase" >&2
}

case "${1:-detect}" in
  detect) detect ;;
  wrap)   wrap "${2:?usage: key-anchor.sh wrap <keyfile>}" ;;
  unwrap) unwrap ;;
  enroll-passphrase) enroll_passphrase ;;
  *) echo "usage: key-anchor.sh {detect|wrap <keyfile>|unwrap|enroll-passphrase}" >&2; exit 2 ;;
esac
