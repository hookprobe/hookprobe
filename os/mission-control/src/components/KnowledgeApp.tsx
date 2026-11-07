/**
 * KnowledgeApp — Knowledge (§11): the growth engine.
 *
 * Spec: docs/architecture/MissionControl.md §11. Blog CMS, SEO AI, keyword research,
 * page/video generator, runbooks, SOP, wiki, AI Writer. Content and security
 * knowledge share the same AI layer and evidence graph — a post-incident
 * write-up, a runbook, and a blog article are different lenses on the same
 * material. Drives marketing/SEO from inside the platform.
 *
 * Capability-gated on `knowledge` in a real build (manifest grants checked
 * against the signed Platform Manifest). Cyber-industrial terminal soul.
 */

import { type Component, For, Show, createSignal } from 'solid-js';
import LeftRail from './LeftRail';
import CommandPalette from './CommandPalette';
import { setCopilotOpen, setCopilotQuery, copilotOpen, copilotQuery } from '../store/mock';
import type { Tone } from '../store/missionMock';
import {
  type ContentStatus,
  KPIS, CONTENT_ITEMS, SEO_KEYWORDS, AI_SUGGESTIONS,
} from '../store/knwMock';

// ── Helpers ──────────────────────────────────────────────────────────────────

function toneVar(t: Tone): string {
  return {
    green:  'var(--hp-green)',
    amber:  'var(--hp-amber)',
    red:    'var(--hp-red)',
    blue:   'var(--hp-cyan)',
    cyan:   'var(--hp-cyan)',
    purple: 'var(--hp-purple)',
    orange: 'var(--hp-orange)',
    grey:   'var(--hp-grey)',
  }[t];
}

function statusTone(s: ContentStatus): Tone {
  return s === 'published' ? 'green' : s === 'review' ? 'blue' : 'amber';
}

function seoColor(score: number): string {
  return score >= 80 ? 'var(--hp-green)' : score >= 60 ? 'var(--hp-amber)' : 'var(--hp-red)';
}

// ── Shared Panel (mirrors DetectApp Panel) ────────────────────────────────────

const Panel: Component<{ ctx: string; title: string; span?: string; children: any }> = (p) => (
  <section class="hp-terminal mc-panel" style={p.span ? { 'grid-column': p.span } : undefined}>
    <div class="hp-terminal-bar">
      <span class="hp-dot red"    aria-hidden="true" />
      <span class="hp-dot yellow" aria-hidden="true" />
      <span class="hp-dot green"  aria-hidden="true" />
      <span class="mc-panel-title">{p.title}</span>
      <span class="hp-terminal-title">hookprobe@edge ~ {p.ctx}</span>
    </div>
    <div class="hp-terminal-body mc-panel-body">{p.children}</div>
  </section>
);

// ── KnowledgeApp ──────────────────────────────────────────────────────────────

const KnowledgeApp: Component = () => {
  const [writerInput,  setWriterInput]  = createSignal('');
  const [writerOutput, setWriterOutput] = createSignal<string | null>(null);

  function handleGenerate() {
    const q = writerInput().trim();
    if (!q) return;
    setWriterOutput(
      `> Generating: "${q}"…\n\n` +
      `AEGIS AI writer queued. Output will appear here once the BYO LLM endpoint\n` +
      `responds. Connect a model at Administration → AI Models → AEGIS endpoint.`
    );
  }

  function useSuggestion(prompt: string) {
    setWriterInput(prompt);
    setWriterOutput(null);
  }

  return (
    <div class="dash-layout">
      <LeftRail active="/knowledge" mode="cloud-linked" onOpenCopilot={() => setCopilotOpen(true)} />

      <main class="dash-main">
        <header class="mc-header">
          <div>
            <h1 class="mc-h1">KNOWLEDGE</h1>
            <div class="mc-sub">
              Growth engine — Blog CMS · SEO AI · Keyword Research · Runbooks · Wiki · AI Writer
            </div>
          </div>
          <div class="mc-header-actions">
            <button class="mc-chip" onClick={() => setCopilotOpen(true)}>
              ⌘ "draft a ransomware runbook"
            </button>
            <span class="mc-mode-badge">● knowledge granted</span>
          </div>
        </header>

        <div class="mc-grid">

          {/* KPI row — 5 columns, full width */}
          <div class="mc-cell--kpis knw-kpis">
            <For each={KPIS}>
              {(k) => (
                <div class="mc-kpi" style={{ '--tone': toneVar(k.tone) }}>
                  <div class="mc-kpi-label">{k.label}</div>
                  <div class="mc-kpi-value">{k.value}</div>
                </div>
              )}
            </For>
          </div>

          {/* Content list (posts / runbooks / docs / wiki / SOPs) */}
          <Panel ctx="cms" title="CONTENT" span="span 7">
            <ul class="knw-content">
              <For each={CONTENT_ITEMS}>
                {(item) => (
                  <li class="knw-content-row">
                    <span class="knw-type-badge" data-type={item.type}>{item.type}</span>
                    <div class="knw-content-body">
                      <div class="knw-content-title">{item.title}</div>
                      <div class="knw-content-meta">{item.author} · {item.updatedAt}</div>
                    </div>
                    <span
                      class="knw-status-badge"
                      style={{ color: toneVar(statusTone(item.status)) }}
                    >{item.status}</span>
                    <span
                      class="knw-seo-score"
                      style={{ color: seoColor(item.seoScore) }}
                      title={`SEO score: ${item.seoScore}/100`}
                    >{item.seoScore}</span>
                    <a class="det-link" href="/knowledge/blog" aria-label="Open content">↗</a>
                  </li>
                )}
              </For>
            </ul>
          </Panel>

          {/* SEO keywords */}
          <Panel ctx="seo" title="SEO KEYWORDS" span="span 5">
            <ul class="knw-kw">
              <For each={SEO_KEYWORDS}>
                {(kw) => (
                  <li class="knw-kw-row">
                    <div class="knw-kw-body">
                      <div class="knw-kw-term">{kw.keyword}</div>
                      <div class="knw-kw-vol">{kw.volume}</div>
                    </div>
                    <span class={`knw-kw-diff knw-diff--${kw.difficulty}`}>{kw.difficulty}</span>
                    <span class="knw-kw-rank">
                      #{kw.rank ?? '—'}
                      <span class={`knw-kw-delta${kw.delta < 0 ? ' knw-delta--up' : kw.delta > 0 ? ' knw-delta--down' : ''}`}>
                        {kw.delta < 0 ? `▲${Math.abs(kw.delta)}` : kw.delta > 0 ? `▼${kw.delta}` : '—'}
                      </span>
                    </span>
                  </li>
                )}
              </For>
            </ul>
          </Panel>

          {/* AI Writer — full-width terminal prompt */}
          <Panel ctx="ai-writer" title="AI WRITER" span="span 12">
            <div class="knw-writer">
              <div class="knw-writer-suggestions">
                <span class="knw-suggestions-label">Suggestions:</span>
                <For each={AI_SUGGESTIONS}>
                  {(s) => (
                    <button
                      class="knw-suggestion"
                      onClick={() => useSuggestion(s.prompt)}
                      title={s.prompt}
                    >
                      {s.prompt}
                    </button>
                  )}
                </For>
              </div>

              <div class="knw-writer-input-row">
                <span class="hp-prompt" aria-hidden="true">$</span>
                <input
                  class="knw-writer-input"
                  type="text"
                  placeholder="Generate a post-incident write-up, runbook, SEO article…"
                  value={writerInput()}
                  onInput={(e) => setWriterInput(e.currentTarget.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') handleGenerate(); }}
                  aria-label="AI Writer prompt"
                  spellcheck={false}
                  autocomplete="off"
                />
                <button class="knw-writer-run" onClick={handleGenerate}>
                  Generate ↵
                </button>
              </div>

              <Show when={writerOutput()}>
                <pre class="knw-writer-output">{writerOutput()}</pre>
              </Show>
            </div>
          </Panel>

        </div>
      </main>

      <CommandPalette
        open={copilotOpen()}
        query={copilotQuery()}
        onQuery={setCopilotQuery}
        onClose={() => { setCopilotOpen(false); setCopilotQuery(''); }}
      />
    </div>
  );
};

export default KnowledgeApp;
