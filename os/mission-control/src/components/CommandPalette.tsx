/**
 * CommandPalette — the AI Copilot overlay (⌘K / Ctrl+K), wired to the REAL AEGIS BYO-LLM planner
 * (ADR 0025, `crates/hookprobe-planner`) — ends the Layer-0 canned-response era for this surface.
 *
 * Spec (MissionControl.md §Global chrome):
 *   "State intent or ask anything; returns an answer with evidence, or a plan
 *    as a diff to approve."
 *
 * Spec (v2-customer-experience.md §2.2):
 *   "⌘K Copilot is the front door for anything not on screen — 'show me last
 *    night', 'block the camera', 'is my Apple TV ok'. Intent, not navigation."
 *
 * Design soul (hookprobe-com/astro-landing 404.astro): rendered as a literal
 * `hookprobe@edge $` terminal session — the prompt is the intent line, the
 * answer + why/confidence/evidence/model are terminal output.
 *
 * Honest states (never a fake response — the OS invariant "the AI planner is assistive... model
 * is the operator's choice" made visible in the UI):
 *   - `checking`      — `GET /api/planner/status` in flight (on open).
 *   - `not-configured`— no model configured -> a clear "Connect a model at Administration → AI
 *                       Models" prompt, never a canned/fake answer.
 *   - `unreachable`   — the planner SERVICE itself didn't answer (distinct from "not configured").
 *   - `idle`          — configured and ready; nothing submitted yet this session.
 *   - `loading`       — a `POST /api/planner/propose` call is in flight.
 *   - `answered`      — a real `PlannerResponse` (answer + why/confidence/evidence/model, and an
 *                       optional plan-as-diff with Approve/Reject).
 *   - `error`         — a real adapter/network error message from the planner (never fabricated).
 *
 * Solid pattern: <Show when={props.open}> fully unmounts the modal when closed,
 * clearing input focus and resetting scroll — cleaner than CSS hide.
 */

import { type Component, Show, For, createSignal, createEffect } from 'solid-js';
import {
  fetchPlannerStatus, proposeIntent, approveChange, PlannerApiError,
  type PlannerStatus, type PlannerResponse, type PlannerArtifactPreview,
} from '../store/plannerApi';

type Phase = 'checking' | 'not-configured' | 'unreachable' | 'idle' | 'loading' | 'answered' | 'error';

interface Props {
  open:    boolean;
  query:   string;
  onQuery: (q: string) => void;
  onClose: () => void;
}

const CommandPalette: Component<Props> = (props) => {
  const [phase, setPhase] = createSignal<Phase>('checking');
  const [status, setStatus] = createSignal<PlannerStatus | null>(null);
  const [submittedQuery, setSubmittedQuery] = createSignal('');
  const [response, setResponse] = createSignal<PlannerResponse | null>(null);
  const [errorMessage, setErrorMessage] = createSignal('');
  const [approveState, setApproveState] = createSignal<'idle' | 'staging' | 'staged' | 'error'>('idle');
  const [approveNote, setApproveNote] = createSignal('');

  // Check planner status once each time the palette opens — never assume yesterday's config still
  // holds (an operator may have just connected a model at Administration → AI Models).
  createEffect(() => {
    if (!props.open) return;
    setPhase('checking');
    setResponse(null);
    setApproveState('idle');
    void fetchPlannerStatus()
      .then((s) => {
        setStatus(s);
        setPhase(s.configured ? 'idle' : 'not-configured');
      })
      .catch(() => {
        setStatus(null);
        setPhase('unreachable');
      });
  });

  const submit = async () => {
    const q = props.query.trim();
    if (!q || phase() === 'loading') return;
    setSubmittedQuery(q);
    setPhase('loading');
    setErrorMessage('');
    setResponse(null);
    try {
      const resp = await proposeIntent(q);
      setResponse(resp);
      setPhase('answered');
    } catch (e) {
      setErrorMessage(e instanceof PlannerApiError ? e.message : e instanceof Error ? e.message : String(e));
      setPhase('error');
    }
  };

  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      void submit();
    }
  };

  const approve = async (artifacts: PlannerArtifactPreview[]) => {
    setApproveState('staging');
    try {
      const result = await approveChange(artifacts);
      setApproveNote(`Staged ${result.artifact_count} file(s) for review at ${result.staged_dir}. ${result.note}`);
      setApproveState('staged');
    } catch (e) {
      setApproveNote(e instanceof PlannerApiError ? e.message : e instanceof Error ? e.message : String(e));
      setApproveState('error');
    }
  };

  const reject = () => {
    setResponse((r) => (r ? { ...r, change: null } : r));
    setApproveNote('Proposal discarded — nothing was staged or applied.');
    setApproveState('idle');
  };

  const onBackdropPointerDown = (e: PointerEvent) => {
    if ((e.target as HTMLElement).classList.contains('cmdpalette-backdrop')) {
      props.onClose();
    }
  };

  return (
    <Show when={props.open}>
      {/* Backdrop — click outside to close */}
      <div
        class="cmdpalette-backdrop"
        onPointerDown={onBackdropPointerDown}
        role="dialog"
        aria-modal="true"
        aria-label="AI Copilot"
      >
        <div class="cmdpalette-modal hp-terminal">

          {/* Terminal title bar — hookprobe@edge ~ copilot */}
          <div class="hp-terminal-bar">
            <span class="hp-dot red" aria-hidden="true" />
            <span class="hp-dot yellow" aria-hidden="true" />
            <span class="hp-dot green" aria-hidden="true" />
            <span class="hp-terminal-title">hookprobe@edge ~ copilot</span>
            <button
              class="cmdpalette-esc-btn"
              onClick={props.onClose}
              aria-label="Close command palette (Escape)"
            >
              ESC
            </button>
          </div>

          <div class="cmd-term-body">

            {/* The intent line — a literal shell prompt. Enter submits. */}
            <div class="cmd-prompt-row">
              <span class="hp-prompt" aria-hidden="true">hookprobe@edge $</span>
              <input
                class="cmd-term-input"
                type="text"
                placeholder="state intent or ask anything…"
                value={props.query}
                onInput={(e) => props.onQuery(e.currentTarget.value)}
                onKeyDown={onKeyDown}
                ref={(el) => { if (el) setTimeout(() => el.focus(), 40); }}
                aria-label="Ask HookProbe AI Copilot"
                autocomplete="off"
                spellcheck={false}
                disabled={phase() === 'checking' || phase() === 'not-configured' || phase() === 'unreachable'}
              />
            </div>

            {/* Terminal output */}
            <div class="cmd-output" role="region" aria-label="AI Copilot response">

              <Show when={phase() === 'checking'}>
                <div class="cmd-answer cmd-answer--muted">Checking for a configured AI model…</div>
              </Show>

              {/* Honest no-config state — never a fake canned answer. */}
              <Show when={phase() === 'not-configured'}>
                <div class="cmd-honest-panel">
                  <div class="cmd-honest-title">No AI model connected</div>
                  <p class="cmd-honest-body">
                    {status()?.message ?? 'Connect a model at Administration → AI Models.'}
                  </p>
                  <p class="cmd-honest-hint">
                    Point at any OpenAI-compatible endpoint — a hosted API, or a local
                    Ollama/llama.cpp/vLLM server for air-gapped sites. Everything else on this
                    device keeps working with no model configured.
                  </p>
                  <a class="cmd-honest-link" href="/administration/ai-models">Open Administration → AI Models →</a>
                </div>
              </Show>

              <Show when={phase() === 'unreachable'}>
                <div class="cmd-honest-panel cmd-honest-panel--error">
                  <div class="cmd-honest-title">Copilot service unreachable</div>
                  <p class="cmd-honest-body">
                    Could not reach the planner service. This is separate from whether a model is
                    configured — check that `hookprobe-planner` is running.
                  </p>
                </div>
              </Show>

              <Show when={phase() === 'idle'}>
                <div class="cmd-answer cmd-answer--muted">
                  Model: {status()?.model} · ready. Try: "block the camera" · "what happened last
                  night?" · "is my Apple TV ok?"
                </div>
              </Show>

              <Show when={phase() === 'loading'}>
                <div class="cmd-echo"><span class="hp-prompt" aria-hidden="true">$</span> {submittedQuery()}</div>
                <div class="cmd-answer cmd-answer--muted">Thinking…</div>
              </Show>

              <Show when={phase() === 'error'}>
                <div class="cmd-echo"><span class="hp-prompt" aria-hidden="true">$</span> {submittedQuery()}</div>
                <div class="cmd-honest-panel cmd-honest-panel--error">
                  <div class="cmd-honest-title">Model error</div>
                  <p class="cmd-honest-body">{errorMessage()}</p>
                </div>
              </Show>

              <Show when={phase() === 'answered' && response()}>
                {(resp) => (
                  <>
                    <div class="cmd-echo"><span class="hp-prompt" aria-hidden="true">$</span> {submittedQuery()}</div>
                    <div class="cmd-answer">{resp().answer}</div>

                    {/* why · confidence · evidence · model (MissionControl.md §AI explanation panel) */}
                    <div class="cmd-meta">
                      <div class="cmd-meta-line"><span class="k"># why</span>{resp().explanation.why}</div>
                      <div class="cmd-meta-line"><span class="k"># confidence</span>{Math.round(resp().explanation.confidence)}%</div>
                      <div class="cmd-meta-line"><span class="k"># model</span>{resp().explanation.model}</div>
                    </div>

                    <For each={resp().warnings}>
                      {(w) => <div class="cmd-warning">⚠ {w}</div>}
                    </For>

                    {/* The plan-as-diff — deterministically computed by aegis::reconcile_network,
                        never model-authored. Approve stages it for review; Reject discards it.
                        Neither button ever applies anything to a live path (see plannerApi.ts doc). */}
                    <Show when={resp().change}>
                      {(change) => (
                        <div class="cmd-diff-panel">
                          <div class="cmd-diff-title">Proposed change (plan-as-diff)</div>
                          <div class="cmd-diff-lines">
                            <For each={change().diff}>
                              {(line) => (
                                <div class={`cmd-diff-line cmd-diff-line--${line.kind}`}>
                                  <span class="cmd-diff-marker" aria-hidden="true">
                                    {line.kind === 'added' ? '+' : line.kind === 'removed' ? '−' : ' '}
                                  </span>
                                  {line.text}
                                </div>
                              )}
                            </For>
                          </div>
                          <For each={change().warnings}>
                            {(w) => <div class="cmd-warning">⚠ {w}</div>}
                          </For>
                          <div class="cmd-diff-actions">
                            <button
                              class="cmd-diff-btn cmd-diff-btn--approve"
                              disabled={approveState() === 'staging'}
                              onClick={() => void approve(change().artifacts)}
                            >
                              {approveState() === 'staging' ? 'Staging…' : 'Approve → stage for review'}
                            </button>
                            <button class="cmd-diff-btn cmd-diff-btn--reject" onClick={reject}>
                              Reject
                            </button>
                          </div>
                          <Show when={approveState() === 'staged' || approveState() === 'error'}>
                            <div class={approveState() === 'error' ? 'cmd-warning' : 'cmd-answer cmd-answer--muted'}>
                              {approveNote()}
                            </div>
                          </Show>
                        </div>
                      )}
                    </Show>
                  </>
                )}
              </Show>

              <div class="cmd-cursor" aria-hidden="true">
                <span class="hp-prompt">$</span> <span class="hp-blink">_</span>
              </div>

            </div>
          </div>

          {/* Footer hints */}
          <div class="cmdpalette-footer" aria-hidden="true">
            <span><kbd>↩</kbd> ask</span>
            <span><kbd>Esc</kbd> close</span>
            <span>Try: "block the camera" · "what happened last night?" · "is my Apple TV ok?"</span>
          </div>

        </div>
      </div>
    </Show>
  );
};

export default CommandPalette;
