/**
 * fbkMock — Administration → Feedback & Diagnostics (ADR 0012 D5) Layer-0 mock data.
 *
 * Spec: docs/feedback-ux.md — the opt-in, off-by-default product-health beacon
 * consent screen. The live payload preview is generated from this mock device
 * state via `buildBeacon()` in FeedbackApp.tsx — never hand-written per field,
 * mirroring the doc's "same code path that assembles the real beacon" rule.
 *
 * Capability grants come from the signed Platform Manifest in a real build.
 */

// ── Capability grant (manifest-sourced in a real build) ──────────────────────

export interface Grants {
  /** Grants the /admin/feedback page itself. */
  feedback_beacon: boolean;
}

/** Layer-0 mock: granted, so the page and its states are demonstrable. */
export const GRANTS: Grants = {
  feedback_beacon: true,
};

// ── The beacon.json field set (ADR 0012 D5 §1) ───────────────────────────────

export interface BootVerdicts { healthy: number; unhealthy: number; rollbacks: number }
export interface HealthRollup { healed: number; failed: number; shed: number; reverted: number }

export interface BeaconPayload {
  schema:         string;
  beacon_id:      string;
  image_version:  string;
  device_class:   string;
  profile:        string;
  arch:           string;
  uptime_hours:   number;
  boot:           BootVerdicts;
  health:         HealthRollup;
  qsecbit_avg:    number;
  consent:        string;
  ts:             string;
}

/**
 * Static device values this device would report — everything except
 * `consent` and `ts`, which are assembled at render/export time so the
 * preview always reflects the current toggle state. Values mirror the
 * worked example in docs/feedback-ux.md §1 (rk3588 / edge-pro / arm64).
 */
export const DEVICE_BEACON_BASE: Omit<BeaconPayload, 'consent' | 'ts'> = {
  schema:        'hookprobe.beacon/1',
  beacon_id:     'b7f3d2…a91c',   // salted SHA-256, truncated for display — not reversible
  image_version: '2026.7.1',
  device_class:  'rk3588',
  profile:       'edge-pro',
  arch:          'arm64',
  uptime_hours:  412,
  boot:          { healthy: 37, unhealthy: 0, rollbacks: 0 },
  health:        { healed: 3, failed: 0, shed: 1, reverted: 0 },
  qsecbit_avg:   0.94,
};

export const CONSENT_TAG_ON  = 'product-health-beacon/opt-in';
export const CONSENT_TAG_OFF = 'none';

// ── Send/delivery mock state (enabled-healthy vs enabled-degraded) ───────────

export const ENABLED_SINCE   = '2026-07-03';
export const LAST_SENT_AT    = '2026-07-03 12:00 UTC';
export const NEXT_SEND_ETA   = '~24h';
export const BEACON_TS_LIVE  = '2026-07-03T12:00:00Z';

// ── The hard deny-list (docs/feedback-ux.md §1, "Never sent") ────────────────

export const DENY_LIST: string[] = [
  'IP addresses', 'Hostnames', 'MAC addresses', 'Flows / pcap',
  'Detections / alerts', 'IOCs', 'Rules', 'File paths', 'Configs',
  'Users', 'Customer data', 'Geolocation',
];

// ── Cloud-linked: the separate, already-consented tenant offload (ADR 0009) ──

export interface TenantOffload {
  status:       'active' | 'inactive';
  endpoint:     string;
  tenant:       string;
  consentedAt:  string;
  consentedBy:  string;
}

export const TENANT_OFFLOAD: TenantOffload = {
  status:      'active',
  endpoint:    'tenant-clickhouse (acme-mssp)',
  tenant:      'acme-mssp',
  consentedAt: '2026-05-11',
  consentedBy: 'admin@acme',
};
