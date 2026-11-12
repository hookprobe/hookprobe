/**
 * LeftRail — the Layer 0 rail: the five pillars for Sam and Dana (requirements doc §Layer 0;
 * wireframe "Home"). Pro view swaps it for AppRail. Same frame as AppRail so the shell never jumps:
 * 212 px with labels, 64 px icons at compact widths, an overlay drawer on tablet/phone.
 */
import { type Component, For } from 'solid-js';
import { proView, setProView } from '../store/layer';
import Icon from './Icon';

export type { DeployMode } from '../store/mock';

interface Pillar { label: string; href: string; icon: string; match: string[] }

const PILLARS: Pillar[] = [
  { label: 'Home',               href: '/',               icon: 'home', match: ['/'] },
  { label: 'Shield',             href: '/network/dns',    icon: 'shield', match: ['/network/dns'] },
  { label: 'My Network',         href: '/network/zones',  icon: 'network', match: ['/network/zones', '/network/map', '/network/devices'] },
  { label: 'Get Online',         href: '/network/wan',    icon: 'online', match: ['/network/wan', '/network/wifi', '/setup'] },
  { label: 'Timeline & Export',  href: '/observe/events', icon: 'timeline', match: ['/observe/events'] },
  { label: 'Settings',           href: '/admin/identity', icon: 'admin', match: ['/admin'] },
];

export function pillarActive(path: string, p: { match: string[] }): boolean {
  return p.match.some((m) => (m === '/' ? path === '/' : path === m || path.startsWith(m + '/')));
}

const LeftRail: Component<{ path: string }> = (props) => (
  <nav class="shell-rail" aria-label="Main">
    <a href="/" class="shell-rail-brand">
      <span class="shell-rail-mark" aria-hidden="true">◣◢</span>
      <span class="shell-rail-label shell-rail-name">HOOK<em>PROBE</em></span>
    </a>
    <div class="shell-rail-items">
      <For each={PILLARS}>{(p) => (
        <a href={p.href} class={`shell-rail-item${pillarActive(props.path, p) ? ' is-active' : ''}`}
           aria-current={pillarActive(props.path, p) ? 'page' : undefined} title={p.label}>
          <span class="shell-rail-icon"><Icon name={p.icon} /></span>
          <span class="shell-rail-label">{p.label}</span>
        </a>
      )}</For>
    </div>
    <div class="shell-rail-foot">
      <button class="shell-rail-item shell-rail-pro" role="switch" aria-checked={proView()} onClick={() => setProView(!proView())} title="Pro view">
        <span class="shell-rail-icon"><Icon name="pro" /></span>
        <span class="shell-rail-label">Pro view</span>
        <span class={`hp-switch shell-rail-label${proView() ? ' hp-switch--on' : ''}`} aria-hidden="true"><span /></span>
      </button>
    </div>
  </nav>
);

export { PILLARS };
export default LeftRail;
