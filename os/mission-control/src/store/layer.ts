/**
 * layer — depth and scope, the two shell dials besides capability (requirements doc §Overview):
 *
 *   - Pro view (FR-03): Layer 0 (the five pillars) is the default for standalone devices, Layer 2
 *     (every workspace) for cloud-linked / self-hosted. The operator's own toggle wins and persists
 *     in this browser (per-viewer convenience only; RBAC pinning is a server concern).
 *   - Scope (FR-02/FR-05): device · site · fleet · tenant. Standalone has exactly one scope (this
 *     device), so the switcher is hidden there.
 */
import { createSignal } from 'solid-js';
import { deployMode } from './mock';

const KEY = 'hp.proView';

function readStored(): boolean | null {
  try {
    const v = localStorage.getItem(KEY);
    return v === null ? null : v === '1';
  } catch {
    return null; // private window / blocked storage: fall back to the mode default
  }
}

// Starts unknown on server AND client so hydration matches the pre-rendered HTML; AppShell calls
// loadProView() on mount, which then switches the rail reactively.
const [stored, setStored] = createSignal<boolean | null>(null);

/** Read the saved choice (once mounted, so hydration matches the static HTML first). */
export function loadProView(): void {
  setStored(readStored());
}

/** True when the Pro (Layer 2) rail and vocabulary are on. */
export const proView = (): boolean => stored() ?? deployMode() !== 'standalone';

export function setProView(on: boolean): void {
  setStored(on);
  try { localStorage.setItem(KEY, on ? '1' : '0'); } catch { /* not persisted; still applies now */ }
}

export type Scope = 'device' | 'site' | 'fleet' | 'tenant';
export const SCOPES: readonly Scope[] = ['device', 'site', 'fleet', 'tenant'];
export const [scope, setScope] = createSignal<Scope>('device');

/** Shell-wide overlays, shared so any screen can open the nav drawer or the copilot. */
export const [navOpen, setNavOpen] = createSignal(false);
