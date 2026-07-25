/**
 * ShieldApp — Shield (Pillar 1: DNS / ad-blocker) Solid island.
 *
 * Route: /network/dns  (Astro static page, Solid client:load island)
 *
 * Spec references:
 *   - docs/v2-customer-experience.md §0 (Pillar 1 — Shield) + §progressive disclosure
 *   - docs/MissionControl.md §6b (Network / Gateway workspace)
 *   - V1: shared/dnsXai/engine.py (DomainCategory, WhitelistSource, ML ensemble),
 *         live as guardian-dnsxai DoH :5353
 *
 * Customer want #1: "DNS / ad-blocker they understand and control."
 *   - Plain-language verdict first; the big number is blocked-today.
 *   - 3-level protection dial (Relaxed / Balanced / Strict) = progressive disclosure.
 *   - Per-category breakdown (what's being blocked, threats in red).
 *   - Allow & Block lists they fully control — add/remove with a plan-as-diff.
 *
 * Every change opens the plan-as-diff strip before applying (app-wide mandate).
 * Terminal soul: each panel is a hookprobe@edge ~ <ctx> window.
 */

import {
  type Component, type Accessor,
  createSignal, createMemo, For, Show, batch,
} from 'solid-js';
import TopBar from './TopBar';
import CommandPalette from './CommandPalette';
import { setCopilotOpen, setCopilotQuery, copilotOpen, copilotQuery } from '../store/mock';
import {
  type BlockCategory, type ProtectionLevel, type ListEntry, type ShieldChange,
  CATEGORY_LABELS, SOURCE_LABELS, LEVEL_INFO,
  INITIAL_CATEGORIES, INITIAL_ALLOW, INITIAL_BLOCK, SHIELD_TOTALS,
  buildShieldChange,
} from '../store/dnsMock';

// ── Helpers ─────────────────────────────────────────────────────────────────

const LEVELS: ProtectionLevel[] = ['relaxed', 'balanced', 'strict'];

function sourceClass(s: ListEntry['source']): string {
  return s === 'system' ? 'src--system' : s === 'ml-learned' ? 'src--ml' : 'src--user';
}

// ── Terminal panel frame ──────────────────────────────────────────────────────

const TermPanel: Component<{ ctx: string; class?: string; children: any }> = (props) => (
  <section class={`hp-terminal shield-panel${props.class ? ` ${props.class}` : ''}`}>
    <div class="hp-terminal-bar">
      <span class="hp-dot red" aria-hidden="true" />
      <span class="hp-dot yellow" aria-hidden="true" />
      <span class="hp-dot green" aria-hidden="true" />
      <span class="hp-terminal-title">hookprobe@edge ~ {props.ctx}</span>
    </div>
    <div class="hp-terminal-body shield-panel-body">{props.children}</div>
  </section>
);

// ── Plan-as-diff strip (reuses the global .net-plan-strip styles) ─────────────

const PlanStrip: Component<{ change: ShieldChange; onApply: () => void; onCancel: () => void }> = (props) => {
  const [expanded, setExpanded] = createSignal(false);
  return (
    <div class="net-plan-strip" role="region" aria-label="Pending change — review before applying">
      <div class="plan-strip-inner">
        <div class="plan-strip-body">
          <div class="plan-strip-label">Pending change</div>
          <div class="plan-strip-summary">{props.change.summary}</div>
          <button class="plan-tech-toggle" onClick={() => setExpanded(v => !v)} aria-expanded={expanded()}>
            Technical details
            <svg aria-hidden="true" width="12" height="12" viewBox="0 0 24 24" fill="none"
              stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
              style={{ transform: expanded() ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }}>
              <path d="M6 9l6 6 6-6" />
            </svg>
          </button>
          <Show when={expanded()}>
            <div class="plan-tech-body" role="note">{props.change.technical}</div>
          </Show>
        </div>
        <div class="plan-strip-actions">
          <button class="plan-cancel-btn" onClick={props.onCancel}>Cancel</button>
          <button class="plan-apply-btn" onClick={props.onApply}>
            Apply
            <svg aria-hidden="true" width="13" height="13" viewBox="0 0 24 24" fill="none"
              stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M20 6 9 17l-5-5" />
            </svg>
          </button>
        </div>
      </div>
    </div>
  );
};

// ── List panel (Allow / Block) ────────────────────────────────────────────────

interface ListPanelProps {
  entries:   Accessor<ListEntry[]>;
  emptyHint: string;
  onAdd:     (domain: string) => void;
  onRemove:  (domain: string) => void;
  disabled:  Accessor<boolean>;
  inputLabel: string;
}

const ListBlock: Component<ListPanelProps> = (props) => {
  const [draft, setDraft] = createSignal('');
  const submit = () => {
    const d = draft().trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (d) { props.onAdd(d); setDraft(''); }
  };
  return (
    <>
      <Show when={props.entries().length > 0} fallback={<div class="shield-empty">{props.emptyHint}</div>}>
        <ul class="shield-list">
          <For each={props.entries()}>
            {(e) => (
              <li class="shield-list-row">
                <span class="shield-domain">{e.domain}</span>
                <span class={`shield-src ${sourceClass(e.source)}`} title={`Source: ${SOURCE_LABELS[e.source]}`}>
                  {e.source === 'system' && <span aria-hidden="true">🔒 </span>}
                  {SOURCE_LABELS[e.source]}
                </span>
                <Show when={e.source !== 'system'}>
                  <button
                    class="shield-remove"
                    onClick={() => props.onRemove(e.domain)}
                    disabled={props.disabled()}
                    aria-label={`Remove ${e.domain}`}
                  >×</button>
                </Show>
              </li>
            )}
          </For>
        </ul>
      </Show>
      <div class="shield-add-row">
        <span class="hp-prompt" aria-hidden="true">$</span>
        <input
          class="shield-add-input"
          type="text"
          placeholder="domain.com"
          value={draft()}
          onInput={(e) => setDraft(e.currentTarget.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') submit(); }}
          disabled={props.disabled()}
          aria-label={props.inputLabel}
          autocomplete="off"
          spellcheck={false}
        />
        <button class="shield-add-btn" onClick={submit} disabled={props.disabled() || !draft().trim()}>Add</button>
      </div>
    </>
  );
};

// ── ShieldApp (root island) ────────────────────────────────────────────────────

const ShieldApp: Component = () => {
  const [level,     setLevel]     = createSignal<ProtectionLevel>('balanced');
  const [allowList, setAllowList] = createSignal<ListEntry[]>(INITIAL_ALLOW);
  const [blockList, setBlockList] = createSignal<ListEntry[]>(INITIAL_BLOCK);
  const [pending,   setPending]   = createSignal<ShieldChange | null>(null);
  const [tab,       setTab]       = createSignal<'allow' | 'block'>('block');

  const categories = INITIAL_CATEGORIES;
  const maxCat = Math.max(...categories.map(c => c.blocked), 1);
  const hasPending = createMemo(() => pending() !== null);

  const malwareTotal = createMemo(() =>
    categories.filter(c => c.threat).reduce((s, c) => s + c.blocked, 0)
  );

  // ── Enqueue / apply (plan-as-diff) ───────────────────────────────────────
  function enqueue(c: ShieldChange) { setPending(c); }
  function cancel() { setPending(null); }

  function apply() {
    const ch = pending();
    if (!ch) return;
    batch(() => {
      switch (ch.kind) {
        case 'set-level':    if (ch.level) setLevel(ch.level); break;
        case 'add-allow':    setAllowList(p => [...p, { domain: ch.domain!, source: 'user', addedBy: 'You' }]); break;
        case 'remove-allow': setAllowList(p => p.filter(e => e.domain !== ch.domain)); break;
        case 'add-block':    setBlockList(p => [...p, { domain: ch.domain!, source: 'user', addedBy: 'You' }]); break;
        case 'remove-block': setBlockList(p => p.filter(e => e.domain !== ch.domain)); break;
      }
      setPending(null);
    });
  }

  function pickLevel(l: ProtectionLevel) {
    if (l === level() || hasPending()) return;
    enqueue(buildShieldChange('set-level', { level: l }));
  }

  return (
    <>
      <TopBar onOpenCopilot={() => setCopilotOpen(true)} />

      <main class="main-content net-page" style={{ 'max-width': '1100px' }}>

        {/* Page header */}
        <div class="net-page-header">
          <a href="/" class="net-back-link" aria-label="Back to Mission Control">
            <svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none"
              stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M19 12H5M12 19l-7-7 7-7" />
            </svg>
            Mission Control
          </a>
          <div class="net-page-title-row">
            <div>
              <h1 class="net-page-title">Shield</h1>
              <div class="net-page-subtitle">
                Blocking ads, trackers &amp; malware on every device · powered by dnsXai
              </div>
            </div>
          </div>
        </div>

        <div class="shield-grid">

          {/* Hero — blocked today + protection level */}
          <TermPanel ctx="shield" class="shield-hero">
            <div class="shield-hero-top">
              <div class="shield-hero-stat">
                <div class="shield-big hp-text-gradient">{SHIELD_TOTALS.blockedToday.toLocaleString()}</div>
                <div class="shield-verdict">
                  ads &amp; trackers blocked today
                  <Show when={malwareTotal() > 0}>
                    <span class="shield-verdict-threat"> · {malwareTotal()} malware/miner attempts stopped</span>
                  </Show>
                </div>
                <div class="shield-statline">
                  {SHIELD_TOTALS.queriesToday.toLocaleString()} queries · {(SHIELD_TOTALS.blockedToday / SHIELD_TOTALS.queriesToday * 100).toFixed(1)}% blocked · {SHIELD_TOTALS.avgInferenceMs}ms avg decision
                </div>
              </div>
            </div>

            <div class="shield-levels" role="group" aria-label="Protection level">
              <For each={LEVELS}>
                {(l) => (
                  <button
                    class={`shield-level-btn${level() === l ? ' shield-level-btn--active' : ''}`}
                    onClick={() => pickLevel(l)}
                    disabled={hasPending()}
                    aria-pressed={level() === l}
                  >
                    <span class="shield-level-name">{LEVEL_INFO[l].label}</span>
                    <span class="shield-level-blurb">{LEVEL_INFO[l].blurb}</span>
                  </button>
                )}
              </For>
            </div>
          </TermPanel>

          <div class="shield-two-col">

            {/* Category breakdown */}
            <TermPanel ctx="categories">
              <ul class="shield-cats">
                <For each={categories}>
                  {(c) => (
                    <li class={`shield-cat-row${c.threat ? ' shield-cat-row--threat' : ''}`}>
                      <span class="shield-cat-label">{c.label}</span>
                      <span class="shield-cat-bar" aria-hidden="true">
                        <span class="shield-cat-fill" style={{ width: `${(c.blocked / maxCat) * 100}%` }} />
                      </span>
                      <span class="shield-cat-count">{c.blocked.toLocaleString()}</span>
                    </li>
                  )}
                </For>
              </ul>
            </TermPanel>

            {/* Allow / Block lists */}
            <TermPanel ctx="lists">
              <div class="shield-tabs" role="tablist">
                <button
                  class={`shield-tab${tab() === 'block' ? ' shield-tab--active' : ''}`}
                  onClick={() => setTab('block')} role="tab" aria-selected={tab() === 'block'}
                >Block list <span class="shield-tab-count">{blockList().length}</span></button>
                <button
                  class={`shield-tab${tab() === 'allow' ? ' shield-tab--active' : ''}`}
                  onClick={() => setTab('allow')} role="tab" aria-selected={tab() === 'allow'}
                >Allow list <span class="shield-tab-count">{allowList().length}</span></button>
              </div>

              <Show when={tab() === 'block'}>
                <ListBlock
                  entries={blockList}
                  emptyHint="Nothing manually blocked — categories above are handled automatically."
                  inputLabel="Add a domain to block"
                  disabled={hasPending}
                  onAdd={(d) => enqueue(buildShieldChange('add-block', { domain: d }))}
                  onRemove={(d) => enqueue(buildShieldChange('remove-block', { domain: d }))}
                />
              </Show>
              <Show when={tab() === 'allow'}>
                <ListBlock
                  entries={allowList}
                  emptyHint="Nothing manually allowed yet."
                  inputLabel="Add a domain to always allow"
                  disabled={hasPending}
                  onAdd={(d) => enqueue(buildShieldChange('add-allow', { domain: d }))}
                  onRemove={(d) => enqueue(buildShieldChange('remove-allow', { domain: d }))}
                />
              </Show>
            </TermPanel>
          </div>

          {/* Scope note */}
          <div class="shield-scope-note">
            Applies to all devices. Set per-bubble exceptions in{' '}
            <a href="/network/map">My Network →</a>
          </div>
        </div>

        {/* Footer hint */}
        <div class="net-footer-hint" aria-hidden="true">
          Add a domain to block or allow — every change shows a preview before it applies.
          <span class="net-footer-sep"> · </span>
          <button class="net-copilot-hint" onClick={() => setCopilotOpen(true)}>
            ⌘K — "unblock youtube on the kids' iPad"
          </button>
        </div>

      </main>

      {/* Plan-as-diff strip */}
      <Show when={pending()}>
        {(ch) => <PlanStrip change={ch()} onApply={apply} onCancel={cancel} />}
      </Show>

      {/* AI Copilot overlay */}
      <CommandPalette
        open={copilotOpen()}
        query={copilotQuery()}
        onQuery={setCopilotQuery}
        onClose={() => { setCopilotOpen(false); setCopilotQuery(''); }}
      />
    </>
  );
};

export default ShieldApp;
