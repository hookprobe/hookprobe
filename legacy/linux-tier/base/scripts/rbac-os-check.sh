#!/bin/sh
# rbac-os-check.sh — verify the OS-level RBAC separation (ADR 0008): only the ADMIN has an OS account;
# operators are dashboard-only (never in /etc/passwd); the disk-key anchor + SSH are admin-only.
# This script NEVER auto-modifies accounts — it only ever inspects state and reports/gates.
#
# HARD GATES on a RELEASE image (mode != debug) — a non-zero exit fails whatever calls this script
# (a release verification gate, and, since ADR 0028, the `hookprobe-rbac-check.service` boot unit +
# a dedicated greenboot `required.d/` check on the bootc/UEFI tier, where a hard-fail verdict is a
# real `bootc rollback` trigger, not just a report nobody has to notice):
#   §1  ANY non-admin OS login account exists at all — promoted from audit-only to a hard gate
#       (ADR 0028): a non-admin OS account is not a lesser finding than a default password, it is a
#       direct violation of this ADR's own load-bearing claim ("operators get no OS account, ever")
#       on a RELEASE artifact.
#   §3  SSH allows password/root login on a release image (ADR 0008 E4b).
#   §4  default/debug credential accounts (ADR 0008 F1) — a backend security audit (2026-07-07,
#       F1/F2) found this script silently PASSED an image that still carried a default root
#       password plus a personal debug identity/password pair (it fell back to treating the
#       lowest real UID as THE admin and never inspected password hashes). Sanitization must be
#       provable by this check, not assumed from a comment. (ADR 0045, 2026-07-25: that personal
#       debug identity was retired; the sole dev/test login is now the neutral hookprobe/hookprobe
#       admin, elevated from the existing hookprobe service account — never a second account.)
# §2 (disk-key anchor mode) stays audit-only — a hygiene signal, not the core RBAC separation claim.
#
# Writes a posture report to the encrypted data volume for QSECBIT/the dashboard; logs loudly on drift.
set -u
REPORT=/var/lib/hookprobe/rbac-os-check.json
# Build mode marker (written by mkosi.postinst / make-pi4-image.sh's HOOKPROBE_DEBUG_ACCESS gate).
# Fail-closed: if the marker is missing (older image, or provisioned outside our build path) treat
# it as a RELEASE image — never skip the credential hard-gate just because we can't prove debug.
MODE="$(cat /etc/hookprobe/build-mode 2>/dev/null || echo release)"

# Known default/debug credential hash (SHA-512 crypt, $6$...) — the ONLY password hash
# mkosi.postinst / make-pi4-image.sh ever bake (root and the elevated hookprobe login share it),
# and only when HOOKPROBE_DEBUG_ACCESS=1. Finding it on a release image means the artifact shipped
# a hardcoded backdoor.
DEBUG_HASHES="$(openssl passwd -6 -salt qEkJ33cMtCvXHNnx hookprobe 2>/dev/null)"  # ADR 0045 public dev login hookprobe/hookprobe, DERIVED (no literal hash in the tree)
case "$DEBUG_HASHES" in '$6$'*) ;; *) echo "rbac-os-check: FATAL: cannot derive the known dev hash (openssl missing); failing closed" >&2; exit 1 ;; esac

# The single OS admin: provisioning/wizard writes /etc/hookprobe/admin-user; fall back to the lowest
# real UID (1000) so a dev image without a wizard run still audits cleanly. NOTE: this fallback does
# NOT exempt a debug-elevated login account from the credential hard-gate below — that check is
# identity/hash based, independent of whichever account this heuristic happens to call "admin".
ADMIN="$(cat /etc/hookprobe/admin-user 2>/dev/null || awk -F: '$3==1000{print $1; exit}' /etc/passwd)"

# 1. Any non-system login account (UID 1000..65533, real shell) that is NOT the admin → VIOLATION:
#    operators must be dashboard-only, never an OS login.
extra="$(awk -F: -v a="$ADMIN" '$3>=1000 && $3<65534 && $1!=a && $7!~/(nologin|false)$/{print $1}' /etc/passwd | tr '\n' ' ' | sed 's/ *$//')"
# 2. disk-key anchor must be root-only 0700.
keymode="$(stat -c '%a %U' /etc/hookprobe/keys 2>/dev/null || echo missing)"
# 3. SSH exposure — password/root login is DEBUG-only; must be off in signed release images (E4b).
ssh_state="$(sshd -T 2>/dev/null | awk '/^(passwordauthentication|permitrootlogin)/{printf "%s=%s ",$1,$2}')"

viol=0
hard_fail=0
if [ -n "$extra" ]; then
  if [ "$MODE" = debug ]; then
    echo "rbac-os-check: VIOLATION — non-admin OS login account(s): $extra (operators MUST be dashboard-only, ADR 0008) — debug build, not a hard gate"
  else
    echo "rbac-os-check: VIOLATION — non-admin OS login account(s): $extra on a RELEASE image (operators MUST be dashboard-only, ADR 0008 + ADR 0028) — HARD GATE"
    hard_fail=1
  fi
  viol=1
fi
case "$keymode" in "700 root") ;; missing) : ;; *) echo "rbac-os-check: WARN — /etc/hookprobe/keys is '$keymode' (want '700 root')"; viol=1 ;; esac
case "$ssh_state" in
  *"passwordauthentication=yes"*|*"permitrootlogin=yes"*)
    if [ "$MODE" = debug ]; then
      echo "rbac-os-check: NOTE — SSH allows password/root login (expected: debug build, HOOKPROBE_DEBUG_ACCESS=1)"
    else
      echo "rbac-os-check: VIOLATION — SSH allows password/root login on a RELEASE image (ADR 0008 E4b) — sshd must be publickey-only, no root login"
      viol=1; hard_fail=1
    fi
    ;;
esac

# 4. Default/debug credential accounts — HARD GATE on release images (mode != debug). Four checks:
#    (a) the legacy pre-ADR-0045 personal debug identity 'andrei' present at all, regardless of
#        what its password hash now is (it could have been rotated but the account itself is
#        still a leftover backdoor identity).
#    (b) the 'hookprobe' service account still carries a login shell (the debug-mode elevation,
#        ADR 0045, not reverted).
#    (c) ANY sudo-capable account (root, hookprobe, or a member of the 'sudo' group) whose
#        /etc/shadow hash matches the known default/debug hash verbatim.
#    (d) the broad guardrail: ANY OS account at all carrying an active (non-locked) password hash
#        — a release image must ship zero password-bearing login accounts, full stop, independent
#        of whether we recognize the specific hash.
if [ "$MODE" != debug ]; then
  if awk -F: '$1=="andrei"{f=1} END{exit !f}' /etc/passwd 2>/dev/null; then
    echo "rbac-os-check: VIOLATION — legacy debug identity 'andrei' present on a RELEASE image (default-credential backdoor, ADR 0008 F1)"
    viol=1; hard_fail=1
  fi
  if awk -F: '$1=="hookprobe" && $7!~/(nologin|false)$/{f=1} END{exit !f}' /etc/passwd 2>/dev/null; then
    echo "rbac-os-check: VIOLATION — 'hookprobe' carries a login shell on a RELEASE image (debug-mode elevation not reverted, ADR 0045) — HARD GATE"
    viol=1; hard_fail=1
  fi
  sudo_members="$(awk -F: '$1=="sudo"{print $4}' /etc/group 2>/dev/null | tr ',' ' ')"
  for u in $(printf '%s\n' "root hookprobe $sudo_members" | tr ' ' '\n' | sort -u); do
    [ -n "$u" ] || continue
    uhash="$(awk -F: -v u="$u" '$1==u{print $2}' /etc/shadow 2>/dev/null)"
    [ -n "$uhash" ] || continue
    if printf '%s\n' "$DEBUG_HASHES" | grep -F -x -q "$uhash"; then
      echo "rbac-os-check: VIOLATION — sudo-capable account '$u' carries a known default/debug password hash on a RELEASE image (ADR 0008 F1)"
      viol=1; hard_fail=1
    fi
  done
  active="$(awk -F: '$2!="" && $2!="*" && $2!~/^!/{print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')"
  if [ -n "$active" ]; then
    echo "rbac-os-check: VIOLATION — account(s) with an active (non-locked) password hash on a RELEASE image: $active — a release artifact must ship ZERO password-bearing login accounts (ADR 0045) — HARD GATE"
    viol=1; hard_fail=1
  fi
fi

mkdir -p "$(dirname "$REPORT")" 2>/dev/null || true
printf '{"mode":"%s","admin":"%s","extra_os_logins":"%s","keydir":"%s","ssh":"%s","violation":%d,"hard_fail":%d}\n' \
  "$MODE" "$ADMIN" "$extra" "$keymode" "$(echo "$ssh_state" | sed 's/ *$//')" "$viol" "$hard_fail" > "$REPORT" 2>/dev/null || true
[ "$viol" = 0 ] && echo "rbac-os-check: OK — OS is admin-only ('$ADMIN'), keys root-0700, operators dashboard-only, no default-credential accounts (mode=$MODE)"
# Only §2 (disk-key mode) stays permanently audit-only. §1/§3/§4 are hard gates on a RELEASE image
# (see the file header) — non-zero exit fails whatever calls this script: a release verification
# gate, the `hookprobe-rbac-check.service` boot unit, and (ADR 0028) a dedicated greenboot check.
[ "$hard_fail" = 1 ] && exit 1
exit 0
