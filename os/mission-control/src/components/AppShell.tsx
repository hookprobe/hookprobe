/**
 * AppShell — the one global shell on every route (FR-01; requirements doc §Global shell, wireframe
 * TopBar + ProRail + Home rail + phone bottom tabs).
 *
 *   ┌──────────── TopBar (56 px) ─────────────┐
 *   │ rail │ banners · page content            │   + Drawer / Copilot overlays
 *   └──────┴───────────────────────────────────┘   + bottom tabs under 768 px
 *
 * The rail is LeftRail (Layer 0, five pillars) or AppRail (Pro view, every workspace), chosen by
 * the Pro view toggle (store/layer.ts) — never by the page. Pages pass their own content as
 * children (each keeps its own <main>), plus `path` so the active item is right at first paint.
 * The rail and top bar never change between workspaces; only the content does.
 */
import { type Component, type JSX, Show, For, createSignal, onMount, onCleanup, createEffect } from 'solid-js';
import { copilotOpen, setCopilotOpen, copilotQuery, setCopilotQuery } from '../store/mock';
import { startLiveUpdates } from '../store/live';
import { loadHealth } from '../store/health';
import { proView, navOpen, setNavOpen, loadProView } from '../store/layer';
import TopBar from './TopBar';
import LeftRail, { PILLARS, pillarActive } from './LeftRail';
import AppRail, { workspaceActive } from './AppRail';
import CommandPalette from './CommandPalette';
import SampleDataNotice from './SampleDataNotice';
import Icon from './Icon';

interface Props {
  /** This route's path (e.g. "/detect/feed"); the live location wins once hydrated. */
  path?: string;
  children: JSX.Element;
}

export function normPath(p: string): string {
  const t = p.replace(/\/index\.html$/, '/').replace(/\.html$/, '').replace(/\/+$/, '');
  return t === '' ? '/' : t;
}

interface Tab { label: string; href: string; icon: string; match: string[] }
const PRO_TABS: Tab[] = [
  { label: 'Mission',     href: '/mission',            icon: 'mission', match: ['/mission'] },
  { label: 'Investigate', href: '/investigate/queue',  icon: 'investigate', match: ['/investigate'] },
  { label: 'Network',     href: '/network/map',        icon: 'network', match: ['/network'] },
  { label: 'Approvals',   href: '/automate/playbooks', icon: 'approvals', match: ['/automate'] },
];

const AppShell: Component<Props> = (props) => {
  const [path, setPath] = createSignal(normPath(props.path ?? '/'));

  onMount(() => {
    setPath(normPath(location.pathname));
    loadProView();
    void loadHealth();
    void startLiveUpdates(); // idempotent: the pill/score track the live device on every route

    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setCopilotOpen((v) => !v);
      } else if (e.key === 'Escape') {
        if (copilotOpen()) setCopilotOpen(false);
        else if (navOpen()) setNavOpen(false);
      }
    };
    window.addEventListener('keydown', onKey);
    onCleanup(() => window.removeEventListener('keydown', onKey));
  });

  // Moving focus into the nav drawer when it opens on tablet/phone.
  let railWrap: HTMLDivElement | undefined;
  createEffect(() => {
    if (navOpen()) queueMicrotask(() => railWrap?.querySelector<HTMLElement>('a, button')?.focus());
  });

  const tabs = (): Tab[] => (proView() ? PRO_TABS : PILLARS.slice(0, 4));
  const tabActive = (t: Tab) => (proView() ? workspaceActive(path(), t) : pillarActive(path(), t));

  return (
    <div class={`shell${proView() ? ' shell--pro' : ' shell--home'}`}>
      <a class="skip-link" href="#shell-content">Skip to content</a>
      <TopBar onOpenCopilot={() => setCopilotOpen(true)} />

      <div class="shell-body">
        <div class={`shell-rail-wrap${navOpen() ? ' is-open' : ''}`} ref={railWrap}
             onClick={(e) => { if ((e.target as HTMLElement).closest('a')) setNavOpen(false); }}>
          <Show when={proView()} fallback={<LeftRail path={path()} />}>
            <AppRail path={path()} />
          </Show>
        </div>
        <Show when={navOpen()}>
          <div class="shell-scrim" onClick={() => setNavOpen(false)} aria-hidden="true" />
        </Show>

        <div class="shell-content" id="shell-content">
          <SampleDataNotice />
          {props.children}
        </div>
      </div>

      {/* Phone (< 768 px): five bottom tabs; "More" opens every other workspace. */}
      <nav class="shell-tabs" aria-label="Quick">
        <For each={tabs()}>{(t) => (
          <a href={t.href} class={`shell-tab${tabActive(t) ? ' is-active' : ''}`} aria-current={tabActive(t) ? 'page' : undefined}>
            <span class="shell-tab-icon"><Icon name={t.icon} size={20} /></span>
            <span>{t.label}</span>
          </a>
        )}</For>
        <button class="shell-tab" onClick={() => setNavOpen(true)} aria-haspopup="dialog">
          <span class="shell-tab-icon"><Icon name="more" size={20} /></span>
          <span>More</span>
        </button>
      </nav>

      <CommandPalette
        open={copilotOpen()}
        query={copilotQuery()}
        onQuery={setCopilotQuery}
        onClose={() => { setCopilotOpen(false); setCopilotQuery(''); }}
      />
    </div>
  );
};

export default AppShell;
