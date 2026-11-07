/**
 * health — one `/api/health` read per page load, shared by the TopBar and the LeftRail: the
 * device's real deployment mode + which engine is serving. Keeps the defaults when the API is
 * unreachable or has no such field (never invents a mode).
 */
import { fetchJson } from './api';
import { setDeployMode, setSubstrate } from './mock';
import type { DeployMode } from '../components/LeftRail';

const MODES: readonly DeployMode[] = ['standalone', 'cloud-linked', 'self-hosted'];
let once: Promise<void> | null = null;

export function loadHealth(): Promise<void> {
  once ??= (async () => {
    try {
      const h = await fetchJson<{ mode?: string; substrate?: string }>('/api/health');
      if (h.substrate) setSubstrate(h.substrate);
      if (h.mode && (MODES as readonly string[]).includes(h.mode)) setDeployMode(h.mode as DeployMode);
    } catch {
      /* offline / unauthenticated: keep the defaults */
    }
  })();
  return once;
}
