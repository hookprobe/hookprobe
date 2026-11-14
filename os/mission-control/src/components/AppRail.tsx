/**
 * AppRail — the Pro (Layer 2) rail: every workspace (requirements doc §Global shell; wireframe
 * ProRail). 13 workspaces in nav-map order (MissionControl.md §Navigation map), Customers only when
 * cloud-linked / self-hosted (FR-05). Below them: the QSecBit mini-card, the tenant (non-standalone)
 * and the device footer, then "Back to simple view".
 */
import { type Component, For, Show } from 'solid-js';
import { qsecbit, qsecbitShown, qsecbitGauge, heartbeat, deployMode, substrate } from '../store/mock';
import { degraded } from '../store/health';
import { setProView } from '../store/layer';
import Icon from './Icon';

interface Item { label: string; href: string; icon: string; match: string[]; linkedOnly?: boolean }

export const WORKSPACES: Item[] = [
  { label: 'Home',              href: '/',                  icon: 'home', match: ['/__home'] },
  { label: 'Mission Control',   href: '/mission',            icon: 'mission', match: ['/mission'] },
  { label: 'Workspace',         href: '/workspace',          icon: 'workspace', match: ['/workspace'] },
  { label: 'Observe',           href: '/observe/live',       icon: 'observe', match: ['/observe'] },
  { label: 'Detect',            href: '/detect/feed',        icon: 'detect', match: ['/detect'] },
  { label: 'Investigate',       href: '/investigate/queue',  icon: 'investigate', match: ['/investigate'] },
  { label: 'Protect',           href: '/protect/firewall',   icon: 'shield', match: ['/protect'] },
  { label: 'Network / Gateway', href: '/network/map',        icon: 'network', match: ['/network', '/setup'] },
  { label: 'Automate',          href: '/automate/playbooks', icon: 'automate', match: ['/automate'] },
  { label: 'Intelligence',      href: '/intelligence/cves',  icon: 'intel', match: ['/intelligence'] },
  { label: 'Customers',         href: '/customers/managed',  icon: 'customers', match: ['/customers'], linkedOnly: true },
  { label: 'Business',          href: '/business/dashboard', icon: 'business', match: ['/business'] },
  { label: 'Knowledge',         href: '/knowledge/blog',     icon: 'knowledge', match: ['/knowledge'] },
  { label: 'Administration',    href: '/admin/identity',     icon: 'admin', match: ['/admin'] },
];

export function workspaceActive(path: string, w: { match: string[] }): boolean {
  return w.match.some((m) => path === m || path.startsWith(m + '/'));
}

function spark(data: number[], w: number, h: number): string {
  if (data.length < 2) return '';
  const max = Math.max(...data), min = Math.min(...data), rng = max - min || 1;
  return data.map((v, i) => `${i ? 'L' : 'M'}${(2 + (i * (w - 4)) / (data.length - 1)).toFixed(1)},${(h - 2 - ((v - min) / rng) * (h - 4)).toFixed(1)}`).join(' ');
}

const AppRail: Component<{ path: string }> = (props) => {
  const items = () => WORKSPACES.filter((w) => !w.linkedOnly || deployMode() !== 'standalone');
  return (
    <nav class="shell-rail shell-rail--pro" aria-label="Workspaces">
      <a href="/mission" class="shell-rail-brand">
        <span class="shell-rail-mark" aria-hidden="true">◣◢</span>
        <span class="shell-rail-label shell-rail-name">HOOK<em>PROBE</em> OS</span>
      </a>
      <div class="shell-rail-items">
        <For each={items()}>{(w) => (
          <a href={w.href} class={`shell-rail-item${workspaceActive(props.path, w) ? ' is-active' : ''}`}
             aria-current={workspaceActive(props.path, w) ? 'page' : undefined} title={w.label}>
            <span class="shell-rail-icon"><Icon name={w.icon} /></span>
            <span class="shell-rail-label">{w.label}</span>
          </a>
        )}</For>
      </div>

      <div class="shell-rail-foot">
        <a href="/mission" class="shell-rail-qcard" aria-label={`QSecBit ${qsecbitShown()}, open Mission Control`}>
          <span class="shell-rail-qlabel shell-rail-label">QSecBit</span>
          <span class="shell-rail-qscore">{qsecbitShown()}</span>
          <svg class="shell-rail-label" viewBox="0 0 160 24" width="100%" height="24" preserveAspectRatio="none" aria-hidden="true">
            <path d={spark(heartbeat(), 160, 24)} fill="none" stroke="var(--hp-green)" stroke-width="1.5" />
          </svg>
        </a>
        <Show when={deployMode() !== 'standalone'}>
          <p class="shell-rail-tenant shell-rail-label"><em>Tenant</em>this organisation</p>
        </Show>
        <button class="shell-rail-back shell-rail-label" onClick={() => setProView(false)}>← Back to simple view</button>
        <p class="shell-rail-device shell-rail-label">
          <span class={`shell-rail-dot${degraded() ? ' is-degraded' : ''}`} aria-hidden="true" />
          os.hookprobe.local{substrate() ? '' : ' · preview'}
          <span class="sr-only">{degraded() ? ', degraded' : ', online'}</span>
        </p>
      </div>
    </nav>
  );
};

export default AppRail;
