/**
 * AppRail — the shared, canonical left navigation rail.
 *
 * Nav is the MissionControl.md workspace set (§Navigation map) — the same on every
 * page. Visual matches ~/workspace.png: HOOKPROBE OS brand · nav · QSecBit score
 * card · Tenant · device (OS.HOOKPROBE.LOCAL) status. Pass `active` = the nav label.
 */

import { type Component, For } from 'solid-js';
import { QSIDEBAR } from '../store/missionMock';

interface Item { label: string; href: string; icon: string }
// Canonical workspaces, in nav-map order (docs/architecture/MissionControl.md §Navigation map).
const NAV: Item[] = [
  { label: 'Mission Control', href: '/mission',           icon: '◎' },
  { label: 'Workspace',       href: '/workspace',         icon: '▦' },
  { label: 'Observe',         href: '/observe/events',    icon: '◉' },
  { label: 'Detect',          href: '/detect/feed',       icon: '◈' },
  { label: 'Investigate',     href: '/investigate/queue', icon: '⊚' },
  { label: 'Protect',         href: '/protect/firewall',  icon: '⛨' },
  { label: 'Network / Gateway', href: '/network/map',     icon: '⊞' },
  { label: 'Automate',        href: '/automate/playbooks', icon: '⚙' },
  { label: 'Intelligence',    href: '/intelligence/cves', icon: '✦' },
  { label: 'Customers',       href: '/customers/managed', icon: '◫' },
  { label: 'Business',        href: '/business/dashboard', icon: '$' },
  { label: 'Knowledge',       href: '/knowledge/blog',    icon: '❏' },
  { label: 'Administration',  href: '/admin/identity',    icon: '⚿' },
  { label: 'AI Copilot',      href: '/mission',           icon: '⌘' },
];

// minimal area sparkline (self-contained so the rail has no chart deps)
function spark(data: number[], w: number, h: number) {
  const max = Math.max(...data), min = Math.min(...data), rng = max - min || 1;
  const p = data.map((v, i) => [2 + (i * (w - 4)) / (data.length - 1), h - 2 - ((v - min) / rng) * (h - 4)] as const);
  const l = p.map((q, i) => `${i ? 'L' : 'M'}${q[0].toFixed(1)},${q[1].toFixed(1)}`).join(' ');
  return { line: l, area: `${l} L${p[p.length - 1][0].toFixed(1)},${h} L${p[0][0].toFixed(1)},${h} Z` };
}

const AppRail: Component<{ active: string }> = (props) => {
  const s = spark(QSIDEBAR.spark, 150, 34);
  return (
    <aside class="rail2">
      <a class="rail2-brand" href="/mission">
        <span class="rail2-brand-mark">◣◢</span>
        <span class="rail2-brand-txt">HOOKPROBE OS<em>Autonomous SOC Platform</em></span>
      </a>

      <nav class="rail2-nav">
        <For each={NAV}>{n => (
          <a class={`rail2-item${n.label === props.active ? ' rail2-item--active' : ''}`} href={n.href}>
            <span class="rail2-icon">{n.icon}</span>{n.label}
          </a>
        )}</For>
      </nav>

      <div class="rail2-qcard">
        <span class="rail2-qcard-label">QSecBit Score</span>
        <span class="rail2-qcard-score">{QSIDEBAR.score}<em>/100</em></span>
        <svg viewBox="0 0 150 34" class="rail2-qcard-spark" preserveAspectRatio="none" aria-hidden="true">
          <defs><linearGradient id="railqsb" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="var(--hp-green)" stop-opacity="0.35" /><stop offset="1" stop-color="var(--hp-green)" stop-opacity="0" /></linearGradient></defs>
          <path d={s.area} fill="url(#railqsb)" /><path d={s.line} fill="none" stroke="var(--hp-green)" stroke-width="1.5" />
        </svg>
        <span class="rail2-qcard-posture">{QSIDEBAR.posture}</span>
      </div>

      <button class="rail2-tenant"><span><em>Tenant</em><b>HookProbe MSSP</b></span><span>▾</span></button>
      <div class="rail2-os"><span class="rail2-os-dot" /><span><b>OS.HOOKPROBE.LOCAL</b><em>v1.0.0-beta.1</em></span></div>
    </aside>
  );
};

export default AppRail;
