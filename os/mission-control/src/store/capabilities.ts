/**
 * capabilities — the Platform Manifest's grants, as the UI sees them (FR-04, "capabilities, not
 * branches"). Code never asks "is this a Pi?"; it asks `cap('wifi_ap')` and renders, greys with a
 * reason, or hides (components/Gate.tsx).
 *
 * Source of truth, in order:
 *   1. The device: `GET /api/capabilities` → `{granted: string[], denied: {id: reason}}`, or a
 *      `capabilities: string[]` field on `/api/health` (store/health.ts feeds either in here).
 *   2. Until the device answers, a SAMPLE manifest (below). Every greyed reason rendered from it
 *      says so, so a sample grant is never mistaken for this device's real hardware.
 *
 * Anything neither granted nor denied is `unknown` → hidden (a control must never be a no-op).
 */
import { createSignal } from 'solid-js';

export type CapState = 'granted' | 'denied' | 'unknown';
export interface CapAnswer { state: CapState; reason: string }

/** What a typical single-NIC edge device grants — used only until the device reports its own. */
const SAMPLE_GRANTED = ['ids', 'dns_filtering', 'dns', 'dhcp', 'wan', 'wifi_ap', 'segmentation', 'device_trust'];

/** Operator-facing default reasons for a capability this device lacks (the device's own wins). */
const DEFAULT_REASONS: Record<string, string> = {
  openvswitch:   'Needs Open vSwitch, which this hardware does not provide.',
  multi_wan:     'Needs a second WAN port.',
  wifi_ap:       'This device has no Wi-Fi radio that can run an access point.',
  wifi7:         'Needs a Wi-Fi 7 radio.',
  edge_ai:       'Needs an on-device AI accelerator.',
  ids:           'The network sensor is not granted on this device.',
  dns_filtering: 'DNS filtering is not granted on this device.',
  segmentation:  'Zones need network segmentation, which is not granted on this device.',
  wan:           'This device is not acting as the internet gateway.',
  inline:        'Inline enforcement is not granted; this control runs alert-only.',
};

interface CapSet { granted: Set<string>; denied: Map<string, string>; source: 'device' | 'sample' }

const [caps, setCaps] = createSignal<CapSet>({
  granted: new Set(SAMPLE_GRANTED),
  denied: new Map(),
  source: 'sample',
});

/** 'device' once the device reported its manifest; 'sample' before that. */
export const capsSource = () => caps().source;

/** Feed the device's answer in (store/health.ts). An empty list is a real answer, not "unknown". */
export function setDeviceCapabilities(granted: string[], denied: Record<string, string> = {}): void {
  setCaps({ granted: new Set(granted), denied: new Map(Object.entries(denied)), source: 'device' });
}

/** Ask about one capability. `denied` always carries a reason (FR-04: greyed WITH a reason). */
export function cap(id: string): CapAnswer {
  const c = caps();
  if (c.granted.has(id)) return { state: 'granted', reason: '' };
  const sampleNote = c.source === 'sample' ? ' (Based on sample capabilities; this device has not reported its own yet.)' : '';
  const own = c.denied.get(id);
  if (own) return { state: 'denied', reason: own + sampleNote };
  if (DEFAULT_REASONS[id]) return { state: 'denied', reason: DEFAULT_REASONS[id] + sampleNote };
  return { state: 'unknown', reason: '' };
}

/** All of `ids` granted (a control that needs several grants). */
export function capAll(ids: string[]): CapAnswer {
  for (const id of ids) {
    const a = cap(id);
    if (a.state !== 'granted') return a;
  }
  return { state: 'granted', reason: '' };
}
