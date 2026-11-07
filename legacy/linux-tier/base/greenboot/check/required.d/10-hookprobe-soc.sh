#!/usr/bin/env bash
# =============================================================================
# greenboot REQUIRED health check — the OS boot-health gate.
# =============================================================================
# greenboot runs every script in /etc/greenboot/check/required.d/ on each boot.
# A non-zero exit here marks the boot unhealthy.
#
# HONESTY (ADR 0019 D2/D3 — the bootc/Debian substrate split; the "greenboot always
# triggers bootc rollback" line this file used to have was an overclaim ADR 0019
# F2/F3 caught): what happens next depends on the TIER, not on this script alone.
#   - UEFI tier, bootc-managed deployment (ADR 0019 D2, Phase 1+): a FAIL verdict
#     here IS the trigger greenboot's retry-exhaustion path uses to invoke a REAL
#     `bootc rollback` to the previous deployment. This is the case bootc's own
#     docs assume.
#   - rpi-native tier (today's shipping mkosi/Pi image, ADR 0019 F2): there is NO
#     second deployment slot and NO bootc at all — a FAIL verdict is honestly
#     logged as unhealthy but nothing rolls it back. That is a reflash-required
#     event until the A/B image-sync agent ships (ADR 0019 D3/Phase 3).
# This script reports which case applies (best-effort, via `bootc status`) so a
# reader of the boot log is never told a rollback happened when there was nothing
# to roll back to.
#
# The verdict itself ties together everything the device built at first boot:
#   manifest signature VERIFIED  →  module signatures VERIFIED  →  reconcile  →
#   self-test/heal  →  baseline SOC (napse, qsecbit) running + healthy.
#
# Baked to /etc/greenboot/check/required.d/ by the Containerfile.
# =============================================================================
set -euo pipefail

MANIFEST="${HOOKPROBE_MANIFEST:-/var/lib/hookprobe/manifest.json}"
MODULES="${HOOKPROBE_MODULES:-/usr/lib/hookprobe/modules}"
TRUST="${HOOKPROBE_TRUST:-/usr/share/hookprobe/trust}"

[ -f "$MANIFEST" ] || { echo "boot-health: no manifest at $MANIFEST (first boot not complete)"; exit 1; }

# Report which recovery mechanism actually applies to THIS deployment BEFORE the
# verdict runs (ADR 0019 D2/D3). `bootc status` only succeeds against a real
# bootc-managed root, so a bare `command -v bootc` is not enough — the binary
# could exist without the deployment being bootc-managed.
if command -v bootc >/dev/null 2>&1 && bootc status >/dev/null 2>&1; then
  echo "boot-health: bootc-managed deployment detected — a FAIL verdict here is the trigger for a REAL 'bootc rollback' (ADR 0019 D2, UEFI tier)."
else
  echo "boot-health: NOT a bootc-managed deployment (rpi-native/single-slot build) — a FAIL verdict is logged but NOT auto-rolled-back; no second slot exists yet. A/B image-sync is ADR 0019 Phase 3, pending. Recovery today = reflash."
fi

exec /usr/bin/hookprobe-supervisor "$MANIFEST" \
  --modules "$MODULES" \
  --trust "$TRUST" \
  --health-gate
