/**
 * HookProbe OS V2 — Mock data store (Layer 0 / calm landing).
 *
 * Signals here are module-level so they are shared across the single Solid
 * island tree; no context provider needed.
 *
 * Typed against the Platform Manifest capability model — every stat
 * corresponds to a real manifest grant (dns_filtering, segmentation, wan …).
 *
 * WIRED to the real hookprobe-api read-API (ADR 0001) as of the evidence-graph
 * read-API build: `store/live.ts`'s `startLiveUpdates()` (called from
 * `App.tsx`'s `onMount`) overwrites `qsecbit`/`heartbeat`/`security` with real
 * data from `/api/qsecbit` + `/api/incidents` (+ live deltas via `/api/stream`)
 * whenever the API is reachable. `shield`/`network`/`connectivity`/`timeline`
 * have no ingest path into the evidence graph yet and stay on the mock values
 * below — see `store/live.ts`'s doc comment for the exact split.
 */

import { createSignal } from 'solid-js';

// ── Types ───────────────────────────────────────────────────────────────────

export type ProtectionStatus = 'protected' | 'needs-attention' | 'critical';
export type DeployMode        = 'standalone' | 'cloud-linked' | 'self-hosted';

export interface ShieldStats {
  /** Requires manifest: dns_filtering */
  adsBlocked:     number;
  malwareStopped: number;
  active:         boolean;
}

export interface NetworkStats {
  /** Requires manifest: segmentation, device_trust */
  devices: number;
  online:  number;
  zones:   number;
}

export interface ConnectivityStats {
  /** Requires manifest: wan, wifi_ap */
  online:    boolean;
  wanStatus: string;
  aps:       number;
  downMbps:  number;
  upMbps:    number;
}

export interface SecurityStats {
  /** Backed by AEGIS/NAPSE/QSecBit */
  openIncidents:      number;
  allContained:       boolean;
  autonomousActions:  number;
}

export interface TimelineStats {
  /** Requires evidence graph + Telemetry Fabric */
  retentionDays: number;
  storedGb:      number;
  exportReady:   boolean;
}

// ── Reactive signals ─────────────────────────────────────────────────────────

export const [qsecbit,         setQsecbit]         = createSignal<number>(92);
/** Derived from the live resilience % with the device's own bands (risk < 0.3 GREEN, < 0.7 AMBER,
 *  else RED — `mcstate.rs` `band`), so the pill can never say PROTECTED under attack. */
export const protectionStatus = (): ProtectionStatus => {
  const pct = qsecbit();
  return pct > 70 ? 'protected' : pct > 30 ? 'needs-attention' : 'critical';
};
// Default 'standalone' until the device says otherwise: TopBar reads the real mode from
// `/api/health` (heqk: `mode` = cloud-linked only while the MSSP session is Established).
export const [deployMode,      setDeployMode]       = createSignal<DeployMode>('standalone');
// Which engine answered /api/health ('' until known). On the heqk device only the SOC pipeline is
// live (detections/incidents/QSecBit); tiles without a device source say so instead of demo data.
export const [substrate,       setSubstrate]        = createSignal<string>('');
/** Device-reported facts for the home tiles (heqk `/api/health`); null until the device answers. */
export interface DeviceStats { hostsActive: number; detections: number; detectionsCap: number; oldestDetection: number; sealedCap: number }
export const [deviceStats,     setDeviceStats]      = createSignal<DeviceStats | null>(null);
export const [currentUser]                          = createSignal<string>('Admin');
export const [lastChecked,     setLastChecked]      = createSignal<string>('just now');

export const [shield]                               = createSignal<ShieldStats>({
  adsBlocked:     4_812,
  malwareStopped: 12,
  active:         true,
});

export const [network]                              = createSignal<NetworkStats>({
  devices: 24,
  online:  22,
  zones:   4,
});

export const [connectivity]                         = createSignal<ConnectivityStats>({
  online:    true,
  wanStatus: 'WAN healthy',
  aps:       2,
  downMbps:  487,
  upMbps:    51,
});

export const [security,        setSecurity]         = createSignal<SecurityStats>({
  openIncidents:     0,
  allContained:      true,
  autonomousActions: 3,
});

export const [timeline]                             = createSignal<TimelineStats>({
  retentionDays: 21,
  storedGb:      312,
  exportReady:   true,
});

// Heartbeat sparkline — 20 values in [60, 100] representing the last 40s.
// Values cluster around current QSecBit; the interval in App.tsx evolves them.
const INITIAL_HEARTBEAT: number[] = [
  74, 79, 83, 76, 81, 88, 91, 86, 90, 87,
  92, 88, 85, 91, 89, 93, 88, 90, 92, 92,
];
export const [heartbeat, setHeartbeat] = createSignal<number[]>(INITIAL_HEARTBEAT);

// ── UI state ─────────────────────────────────────────────────────────────────

export const [copilotOpen, setCopilotOpen] = createSignal<boolean>(false);
export const [copilotQuery, setCopilotQuery] = createSignal<string>('');
