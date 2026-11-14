/**
 * TopBar — the persistent 56 px global bar (requirements doc §Global shell; wireframe TopBar).
 *
 * Left → right: nav menu (tablet/phone only) · organism status pill (→ /mission) · scope switcher
 * (hidden in standalone) · command bar (⌘/Ctrl-K) · mode badge (+ "degraded, enforcing last
 * approved state") · notifications bell with count · identity menu (role, Pro view, sign out).
 * Identical on every route; only the content and side panel change.
 */
import { type Component, Show, For, createSignal, createEffect, onCleanup, onMount } from 'solid-js';
import { qsecbit, qsecbitShown, qsecbitGauge, protectionStatus, deployMode, currentUser, substrate, security } from '../store/mock';
import { loadHealth, degraded } from '../store/health';
import { proView, setProView, scope, setScope, SCOPES, setNavOpen } from '../store/layer';

interface Props {
  onOpenCopilot: () => void;
}

const WORD = { protected: 'Protected', 'needs-attention': 'Needs attention', critical: 'At risk' } as const;

const TopBar: Component<Props> = (props) => {
  onMount(() => void loadHealth());
  const [menu, setMenu] = createSignal(false);
  let menuWrap: HTMLDivElement | undefined;

  createEffect(() => {
    if (!menu()) return;
    const away = (e: Event) => { if (menuWrap && !menuWrap.contains(e.target as Node)) setMenu(false); };
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') setMenu(false); };
    document.addEventListener('pointerdown', away);
    document.addEventListener('keydown', esc);
    onCleanup(() => { document.removeEventListener('pointerdown', away); document.removeEventListener('keydown', esc); });
  });

  const pending = () => security().openIncidents;
  const standalone = () => deployMode() === 'standalone';

  return (
    <header class="topbar shell-topbar">
      <button class="tb-icon tb-menu" onClick={() => setNavOpen(true)} aria-label="Open navigation">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h16" /></svg>
      </button>

      <a
        href="/mission"
        class={`organism-pill organism-pill--${protectionStatus()}`}
        aria-label={`Security status: ${WORD[protectionStatus()]}, QSecBit ${qsecbitShown()}. Open Mission Control`}
      >
        <span class="organism-pill-dot" aria-hidden="true" />
        <span class="tb-mono">{qsecbitShown()}</span>
        <span>{WORD[protectionStatus()]}</span>
      </a>

      <Show when={!standalone()}>
        <label class="tb-scope">
          <span class="sr-only">Scope</span>
          <select value={scope()} onChange={(e) => setScope(e.currentTarget.value as typeof SCOPES[number])}>
            <For each={SCOPES}>{(s) => <option value={s}>Scope: {s[0].toUpperCase() + s.slice(1)}</option>}</For>
          </select>
        </label>
      </Show>

      <button class="topbar-cmdbar" onClick={props.onOpenCopilot} aria-label="Open AI Copilot: ask anything or say what you want (Ctrl+K)">
        <svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
        </svg>
        <span class="topbar-cmdbar-label">Ask anything or say what you want…</span>
        <span class="topbar-cmdbar-kbd" aria-hidden="true"><kbd>⌘</kbd><kbd>K</kbd></span>
      </button>

      <div class="topbar-spacer" />

      <span class={`mode-badge tb-mode${degraded() ? ' tb-mode--degraded' : ''}`} role="status">
        {deployMode()}
        <Show when={degraded()}> · degraded, enforcing last approved state</Show>
      </span>

      <a class="tb-icon notif-btn" href="/investigate/queue" aria-label={`Notifications, ${pending()} open`}>
        <svg aria-hidden="true" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
          <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" /><path d="M13.73 21a2 2 0 0 1-3.46 0" />
        </svg>
        <Show when={pending() > 0}><span class="tb-count" aria-hidden="true">{pending()}</span></Show>
      </a>

      <div class="tb-identity" ref={menuWrap}>
        <button class="identity-btn" aria-haspopup="menu" aria-expanded={menu()} onClick={() => setMenu(!menu())}>
          <span class="identity-avatar" aria-hidden="true">{currentUser().charAt(0).toUpperCase()}</span>
          <span class="tb-identity-name">{currentUser()}</span>
          <span aria-hidden="true">▾</span>
        </button>
        <Show when={menu()}>
          <div class="tb-menu-pop" role="menu" aria-label="Account">
            <p class="tb-menu-who"><b>{currentUser()}</b><span>{substrate() === 'heqk' ? 'Owner' : 'Admin'}</span></p>
            {/* Tablet/phone: scope + mode move in here (the bar is too narrow). */}
            <p class="tb-menu-mode">{deployMode()}{degraded() ? ' · degraded' : ''}</p>
            <button class="tb-menu-item" role="menuitemcheckbox" aria-checked={proView()} onClick={() => setProView(!proView())}>
              <span>Pro view</span>
              <span class={`hp-switch${proView() ? ' hp-switch--on' : ''}`} aria-hidden="true"><span /></span>
            </button>
            <Show when={substrate() === 'heqk'}>
              <button
                class="tb-menu-item"
                role="menuitem"
                onClick={async () => {
                  try { await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' }); } catch { /* go to login anyway */ }
                  location.href = '/login';
                }}
              >
                Sign out
              </button>
            </Show>
          </div>
        </Show>
      </div>
    </header>
  );
};

export default TopBar;
