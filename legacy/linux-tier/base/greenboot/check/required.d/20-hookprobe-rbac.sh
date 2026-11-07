#!/usr/bin/env bash
# =============================================================================
# greenboot REQUIRED health check — RBAC OS-separation gate (ADR 0008 + ADR 0028).
# =============================================================================
# greenboot runs every script in /etc/greenboot/check/required.d/ on each boot; a
# non-zero exit here marks the boot unhealthy, exactly like 10-hookprobe-soc.sh's
# SOC-health verdict. This is a SEPARATE, additive check — it does not modify or
# duplicate that script's logic, it just gives `rbac-os-check.sh`'s own hard-fail
# verdict (ADR 0008's admin/operator OS separation: no non-admin OS login account,
# no default/debug credentials, no password/root SSH on a release image) the SAME
# real consequence the SOC-health check already has.
#
# HONESTY (same split 10-hookprobe-soc.sh documents, ADR 0019 D2/D3): what happens
# on a FAIL verdict depends on the tier.
#   - UEFI tier, bootc-managed deployment (ADR 0019 D2, Phase 1+): a FAIL verdict
#     here IS a trigger for a REAL `bootc rollback` to the previous deployment —
#     an RBAC-separation regression (e.g. a leftover debug account baked into a
#     release image) is now caught and reverted automatically, not just logged.
#   - rpi-native tier (today's shipping mkosi/Pi image): greenboot itself is not
#     installed/wired on this tier (see base/greenboot/README.md) — this script
#     has no effect there. `hookprobe-rbac-check.service` (boot-time, both tiers)
#     already runs the SAME check and fails loudly in the journal; folding that
#     into `selftest-boot.sh`'s own aggregate PASS/FAIL line is a separate, small,
#     deliberately-not-done-here follow-up (ADR 0028's Honest limits) so as not to
#     touch that actively-evolving file's own SOC-engine-liveness gate.
#
# `rbac-os-check.sh` is itself idempotent and READ-ONLY (never auto-modifies
# accounts) — safe to re-run here exactly as it runs at boot via its own service.
#
# Baked to /etc/greenboot/check/required.d/ by the Containerfile (same COPY as
# 10-hookprobe-soc.sh).
# =============================================================================
set -uo pipefail

RBAC_CHECK="${HOOKPROBE_RBAC_CHECK:-/usr/lib/hookprobe/rbac-os-check.sh}"

if [ ! -x "$RBAC_CHECK" ]; then
  echo "boot-health(rbac): $RBAC_CHECK missing or not executable — treating as unhealthy (an image that can't prove its own RBAC posture is not a passing one)."
  exit 1
fi

"$RBAC_CHECK"
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "boot-health(rbac): rbac-os-check.sh hard-failed (exit $rc) — ADR 0008/0028 RBAC separation violated on what this build considers a RELEASE image."
fi
exit "$rc"
