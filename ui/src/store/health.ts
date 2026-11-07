/**
 * health — one `/api/health` read per page load, shared by the TopBar and the LeftRail: the
 * device's real deployment mode + which engine is serving. Keeps the defaults when the API is
 * unreachable or has no such field (never invents a mode).
 */
import { fetchJson } from './api';
import { setDeployMode, setSubstrate, setDeviceStats } from './mock';
import type { DeployMode } from '../components/LeftRail';

const MODES: readonly DeployMode[] = ['standalone', 'cloud-linked', 'self-hosted'];
let once: Promise<void> | null = null;

interface Health {
  mode?: string;
  substrate?: string;
  detections?: number;
  hosts_active?: number;
  detections_cap?: number;
  oldest_detection?: number;
  sealed_cap?: number;
}

async function readHealth(): Promise<void> {
  try {
    const h = await fetchJson<Health>('/api/health');
    if (h.substrate) setSubstrate(h.substrate);
    if (h.mode && (MODES as readonly string[]).includes(h.mode)) setDeployMode(h.mode as DeployMode);
    if (typeof h.hosts_active === 'number' && typeof h.detections_cap === 'number') {
      setDeviceStats({
        hostsActive: h.hosts_active,
        detections: h.detections ?? 0,
        detectionsCap: h.detections_cap,
        oldestDetection: h.oldest_detection ?? 0,
        sealedCap: h.sealed_cap ?? 0,
      });
    }
  } catch {
    /* offline / unauthenticated: keep the defaults */
  }
}

/** First read once per page; then a 30-s refresh so the counts stay current. */
export function loadHealth(): Promise<void> {
  if (!once) {
    once = readHealth();
    setInterval(() => void readHealth(), 30_000);
  }
  return once;
}
