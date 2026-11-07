/**
 * TopBar — persistent global chrome (MissionControl.md §Global chrome).
 *
 * Contains: brand mark · ⌘K command bar trigger · Organism status pill ·
 *           mode badge · notifications · identity.
 *
 * Color: green pill = PROTECTED; pill turns amber/red if protectionStatus
 * changes — capability-gated per manifest. Standalone hides scope switcher.
 */

import { onMount, type Component } from 'solid-js';
import { qsecbit, protectionStatus, deployMode, setDeployMode, setSubstrate, currentUser } from '../store/mock';
import { fetchJson } from '../store/api';
import type { DeployMode } from './LeftRail';

const MODES: readonly DeployMode[] = ['standalone', 'cloud-linked', 'self-hosted'];

/** Read the device's real deployment mode; keep the default when the API has no `mode` field. */
async function loadMode(): Promise<void> {
  try {
    const h = await fetchJson<{ mode?: string; substrate?: string }>('/api/health');
    if (h.substrate) setSubstrate(h.substrate);
    if (h.mode && (MODES as readonly string[]).includes(h.mode)) setDeployMode(h.mode as DeployMode);
  } catch {
    /* offline / unauthenticated: the badge keeps its default rather than inventing a mode */
  }
}

interface Props {
  onOpenCopilot: () => void;
}

const TopBar: Component<Props> = (props) => {
  onMount(() => void loadMode());
  return (
  <header class="topbar">
    {/* Brand */}
    <div class="topbar-brand" aria-label="HookProbe OS">
      <div class="topbar-brand-dot" aria-hidden="true" />
      HOOKPROBE
    </div>

    <div class="topbar-spacer" />

    {/* ⌘K command bar trigger */}
    <button
      class="topbar-cmdbar"
      onClick={props.onOpenCopilot}
      aria-label="Open AI Copilot — ask anything (Ctrl+K)"
    >
      {/* Search icon */}
      <svg
        aria-hidden="true"
        width="14" height="14" viewBox="0 0 24 24"
        fill="none" stroke="currentColor" stroke-width="2"
        stroke-linecap="round" stroke-linejoin="round"
      >
        <circle cx="11" cy="11" r="8" />
        <path d="m21 21-4.35-4.35" />
      </svg>
      <span class="topbar-cmdbar-label">Ask anything…</span>
      <span class="topbar-cmdbar-kbd" aria-hidden="true">
        <kbd>⌘</kbd>
        <kbd>K</kbd>
      </span>
    </button>

    <div class="topbar-right">
      {/* Organism status pill — links to Mission Control root */}
      <button
        class={`organism-pill organism-pill--${protectionStatus()}`}
        onClick={() => { /* navigate to /mission */ }}
        aria-label={`Security status: ${protectionStatus()} — QSecBit score ${qsecbit()}`}
      >
        <div class="organism-pill-dot" aria-hidden="true" />
        <span aria-hidden="true">{qsecbit()}</span>
        <span>{protectionStatus() === 'protected' ? 'PROTECTED' : protectionStatus() === 'needs-attention' ? 'NEEDS ATTENTION' : 'UNDER ATTACK'}</span>
      </button>

      {/* Mode badge — standalone hides scope switcher per spec */}
      <span class="mode-badge" aria-label={`Deployment mode: ${deployMode()}`}>
        {deployMode()}
      </span>

      {/* Notifications */}
      <button class="notif-btn" aria-label="Notifications (0 pending)">
        <svg
          aria-hidden="true"
          width="16" height="16" viewBox="0 0 24 24"
          fill="none" stroke="currentColor" stroke-width="2"
          stroke-linecap="round" stroke-linejoin="round"
        >
          <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
          <path d="M13.73 21a2 2 0 0 1-3.46 0" />
        </svg>
      </button>

      {/* Identity */}
      <button class="identity-btn" aria-label={`Signed in as ${currentUser()}`}>
        <div class="identity-avatar" aria-hidden="true">
          {currentUser().charAt(0).toUpperCase()}
        </div>
        <span>{currentUser()}</span>
      </button>
    </div>
  </header>
  );
};

export default TopBar;
