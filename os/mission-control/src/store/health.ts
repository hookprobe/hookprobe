/**
 * health — one `/api/health` read per page load, shared by the TopBar and the LeftRail: the
 * device's real deployment mode + which engine is serving. Keeps the defaults when the API is
 * unreachable or has no such field (never invents a mode).
 */
import { fetchJson } from './api';
import { createSignal } from 'solid-js';
import { setDeployMode, setSubstrate, setDeviceStats, type DeployMode } from './mock';
import { setDeviceCapabilities } from './capabilities';

const MODES: readonly DeployMode[] = ['standalone', 'cloud-linked', 'self-hosted'];
let once: Promise<void> | null = null;
let everOk = false;

/** True once the device answered before but has stopped answering: the top bar then says
 *  "degraded · enforcing last approved state" (FR-05). Never true on a box with no device at all. */
export const [degraded, setDegraded] = createSignal(false);
/** True after the first /api/health attempt finished (either way). */
export const [healthChecked, setHealthChecked] = createSignal(false);

interface Health {
  mode?: string;
  /** Platform Manifest grants, when the device reports them here (see store/capabilities.ts). */
  capabilities?: string[];
  substrate?: string;
  detections?: number;
  hosts_active?: number;
  detections_cap?: number;
  oldest_detection?: number;
  sealed_cap?: number;
  wan?: { up: boolean; ip: string; mode: string; ipv6: boolean; clients: number; pkts_out: number; pkts_in: number; dns_inspected: number; dns_blocked?: number; blocklist?: number };
}

async function readHealth(): Promise<void> {
  try {
    const h = await fetchJson<Health>('/api/health');
    everOk = true;
    setDegraded(false);
    if (h.substrate) setSubstrate(h.substrate);
    if (Array.isArray(h.capabilities)) setDeviceCapabilities(h.capabilities);
    if (h.mode && (MODES as readonly string[]).includes(h.mode)) setDeployMode(h.mode as DeployMode);
    if (typeof h.hosts_active === 'number' && typeof h.detections_cap === 'number') {
      setDeviceStats({
        hostsActive: h.hosts_active,
        detections: h.detections ?? 0,
        detectionsCap: h.detections_cap,
        oldestDetection: h.oldest_detection ?? 0,
        sealedCap: h.sealed_cap ?? 0,
        wan: h.wan ? { up: h.wan.up, ip: h.wan.ip, mode: h.wan.mode, ipv6: h.wan.ipv6, clients: h.wan.clients,
                       pktsOut: h.wan.pkts_out, pktsIn: h.wan.pkts_in, dnsInspected: h.wan.dns_inspected,
                       dnsBlocked: h.wan.dns_blocked ?? 0, blocklist: h.wan.blocklist ?? 0 } : null,
      });
    }
  } catch {
    /* offline / unauthenticated: keep the defaults (and the last values) */
    if (everOk) setDegraded(true);
  }
}

interface Capabilities { granted?: string[]; denied?: Record<string, string> }

/** `GET /api/capabilities` — the manifest's grants + reasons. Absent on older devices (404):
 *  then the sample manifest stays and every greyed reason says it is a sample. */
async function readCapabilities(): Promise<void> {
  try {
    const c = await fetchJson<Capabilities>('/api/capabilities');
    if (Array.isArray(c.granted)) setDeviceCapabilities(c.granted, c.denied ?? {});
  } catch { /* not served yet */ }
}

/** First read once per page; then a 30-s refresh so the counts stay current. */
export function loadHealth(): Promise<void> {
  if (!once) {
    once = readHealth().finally(() => setHealthChecked(true));
    void readCapabilities();
    setInterval(() => void readHealth(), 30_000);
  }
  return once;
}
