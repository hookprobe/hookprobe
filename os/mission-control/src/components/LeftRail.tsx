/**
 * LeftRail — the persistent workspace navigation rail (global chrome).
 *
 * Spec: docs/architecture/MissionControl.md §Navigation map + §Global chrome.
 * The 13 workspaces + AI Copilot, mode-aware (Customers/Business gated to
 * cloud-linked). Organism status pill sits at the top → Mission Control.
 * Designed to ~/hookprobe-v2-dashboard.png (left rail, logo, active glow).
 */

import { type Component, For, Show, onMount } from 'solid-js';
import { qsecbit, protectionStatus, deployMode, substrate } from '../store/mock';
import { loadHealth } from '../store/health';
import { startLiveUpdates } from '../store/live';

export type DeployMode = 'standalone' | 'cloud-linked' | 'self-hosted';

interface NavItem { label: string; href: string; icon: string; modes?: DeployMode[]; badge?: string }

// Workspaces in nav-map order. `modes` (when present) gates visibility.
const NAV: NavItem[] = [
  { label: 'Mission Control', href: '/mission',          icon: '◎' },
  { label: 'Workspace',       href: '/workspace',        icon: '▤' },
  { label: 'Observe',         href: '/observe/events',   icon: '◉' },
  { label: 'Detect',          href: '/detect/feed',      icon: '◈' },
  { label: 'Investigate',     href: '/investigate/queue',icon: '⊚' },
  { label: 'Protect',         href: '/protect/firewall', icon: '⛨' },
  { label: 'Network / Gateway', href: '/network/map',    icon: '⊞' },
  { label: 'Automate',        href: '/automate/playbooks', icon: '⚙' },
  { label: 'Intelligence',    href: '/intelligence/cves',icon: '✦' },
  { label: 'Customers',       href: '/customers/managed',icon: '◫', modes: ['cloud-linked', 'self-hosted'] },
  { label: 'Business',        href: '/business/dashboard', icon: '$', modes: ['cloud-linked', 'self-hosted'] },
  { label: 'Knowledge',       href: '/knowledge/blog',   icon: '❏' },
  { label: 'Administration',  href: '/admin/identity',   icon: '⚿' },
  { label: 'System Setup',    href: '/setup',            icon: '◈', badge: 'NEW' },
];

interface Props {
  active: string;            // href prefix of the current workspace
  mode:   DeployMode;
  onOpenCopilot: () => void;
}

const LeftRail: Component<Props> = (props) => {
  // The device's own answer wins over the page's design-time default once /api/health replied.
  const mode = (): DeployMode => (substrate() ? deployMode() : props.mode);
  onMount(() => {
    void loadHealth();
    void startLiveUpdates(); // idempotent: the score/pill track the live device on every workspace
  });
  const visible = () => NAV.filter(n => !n.modes || n.modes.includes(mode()));
  const isActive = (href: string) => props.active.startsWith(href.split('/').slice(0, 2).join('/'));

  return (
    <aside class="dash-rail" aria-label="Workspaces">
      {/* Brand */}
      <a href="/mission" class="rail-brand">
        <span class="rail-brand-mark" aria-hidden="true">◣◢</span>
        <span class="rail-brand-name">HOOK<span class="rail-brand-accent">PROBE</span></span>
      </a>

      {/* Organism status pill → Mission Control */}
      <a href="/mission" class={`rail-organism rail-organism--${protectionStatus()}`} aria-label={`Organism status: ${protectionStatus()}, QSecBit ${qsecbit()}`}>
        <span class="rail-organism-dot" aria-hidden="true" />
        <span class="rail-organism-label">{protectionStatus() === 'protected' ? 'PROTECTED' : protectionStatus() === 'needs-attention' ? 'ATTENTION' : 'UNDER ATTACK'}</span>
        <span class="rail-organism-score">{qsecbit()}</span>
      </a>

      {/* Nav */}
      <nav class="rail-nav">
        <For each={visible()}>
          {(n) => (
            <a href={n.href} class={`rail-item${isActive(n.href) ? ' rail-item--active' : ''}`}>
              <span class="rail-item-icon" aria-hidden="true">{n.icon}</span>
              <span class="rail-item-label">{n.label}</span>
              <Show when={n.badge}><span class="rail-badge">{n.badge}</span></Show>
            </a>
          )}
        </For>
        <button class="rail-item rail-item--copilot" onClick={props.onOpenCopilot}>
          <span class="rail-item-icon" aria-hidden="true">⌘</span>
          <span class="rail-item-label">AI Copilot</span>
          <span class="rail-kbd" aria-hidden="true">⌘K</span>
        </button>
      </nav>

      {/* Identity + mode */}
      <div class="rail-foot">
        <div class="rail-identity">
          <span class="rail-avatar" aria-hidden="true">A</span>
          <div class="rail-identity-block">
            <span class="rail-identity-name">Admin</span>
            <span class="rail-identity-role">Super Admin</span>
          </div>
        </div>
        <div class={`rail-mode rail-mode--${mode()}`}>● {mode()}</div>
      </div>
    </aside>
  );
};

export default LeftRail;
