/**
 * PlanDiff — the one plan-as-diff viewer with Approve / Reject (FR-08; MissionControl.md "intent bar
 * produces a plan as a diff the reconciler applies & verifies"). Used by the Copilot, incident
 * stories, the Automate approval queue and first-run setup.
 *
 * Honest three-step outcome — the UI never claims more than the device reported:
 *   Approve → **Staged** (the planner accepted it for the reconciler; nothing is live yet)
 *           → **Applying** (the reconciler reported it is running)
 *           → **Applied and verified** (only once AEGIS reports success)
 *   Any failure → **Failed** with the reason and a Retry. Reject discards; nothing is staged.
 *
 * `onApprove` stages the plan and returns its id. `watch` (optional) follows that id and reports
 * the reconciler's progress; without it the plan honestly stays at Staged.
 */
import { type Component, For, Show, createSignal, onCleanup } from 'solid-js';

export interface DiffLine { kind: 'added' | 'removed' | 'unchanged' | 'changed'; text: string }

/** `volatile` = applied and read back, but the device cannot keep it across a restart: never shown as verified. */
export type ApplyUpdate = { state: 'applying' } | { state: 'verified'; detail?: string } | { state: 'volatile'; detail: string } | { state: 'failed'; detail: string };

interface Props {
  lines: DiffLine[];
  title?: string;
  warnings?: string[];
  onApprove: () => Promise<{ id: string; note?: string }>;
  onReject?: () => void;
  /** Follow a staged plan; call `update` as the reconciler reports; return a stop function. */
  watch?: (id: string, update: (u: ApplyUpdate) => void) => () => void;
  approveLabel?: string;
}

type Phase = 'idle' | 'staging' | 'staged' | 'applying' | 'verified' | 'volatile' | 'failed' | 'rejected';

const MARK: Record<DiffLine['kind'], string> = { added: '+', removed: '−', changed: '~', unchanged: ' ' };

const PlanDiff: Component<Props> = (props) => {
  const [phase, setPhase] = createSignal<Phase>('idle');
  const [note, setNote] = createSignal('');
  /** Whether staging succeeded before a failure (so the step list shows where it stopped). */
  const [wasStaged, setWasStaged] = createSignal(false);
  let stop: (() => void) | undefined;
  onCleanup(() => stop?.());

  const approve = async () => {
    stop?.();
    setPhase('staging');
    setNote('');
    setWasStaged(false);
    try {
      const { id, note: n } = await props.onApprove();
      setWasStaged(true);
      setPhase('staged');
      setNote(n ?? '');
      if (props.watch) {
        stop = props.watch(id, (u) => {
          setPhase(u.state);
          if (u.state === 'failed' || u.state === 'volatile') setNote(u.detail);
          else if (u.state === 'verified' && u.detail) setNote(u.detail);
        });
      }
    } catch (e) {
      setPhase('failed');
      setNote(e instanceof Error ? e.message : String(e));
    }
  };

  const reject = () => {
    stop?.();
    setPhase('rejected');
    setNote('Plan discarded. Nothing was staged or applied.');
    props.onReject?.();
  };

  const busy = () => phase() === 'staging' || phase() === 'staged' || phase() === 'applying';
  const done = () => phase() === 'verified' || phase() === 'volatile' || phase() === 'rejected';

  return (
    <section class={`plan-diff plan-diff--${phase()}`} aria-label={props.title ?? 'Proposed plan'}>
      <p class="plan-diff-label">{props.title ?? 'Proposed plan'}</p>
      <div class="plan-diff-lines" role="list">
        <For each={props.lines}>{(l) => (
          <div class={`plan-diff-line plan-diff-line--${l.kind}`} role="listitem">
            <span class="plan-diff-mark" aria-hidden="true">{MARK[l.kind]}</span>
            <span class="sr-only">{l.kind === 'unchanged' ? '' : l.kind + ': '}</span>
            {l.text}
          </div>
        )}</For>
      </div>
      <For each={props.warnings ?? []}>{(w) => <p class="plan-diff-warn" role="note">⚠ {w}</p>}</For>

      {/* Progress: one step list, so the current state is never colour-only. */}
      <Show when={phase() !== 'idle' && phase() !== 'rejected'}>
        <ol class="plan-steps" aria-label="Plan progress">
          <li class={stepClass(phase(), 'staged', wasStaged())}>Staged</li>
          <li class={stepClass(phase(), 'applying', wasStaged())}>Applying</li>
          <li class={stepClass(phase(), 'verified', wasStaged())}>{phase() === 'volatile' ? 'Not kept across restart' : 'Applied and verified'}</li>
        </ol>
      </Show>

      <p class="plan-diff-status" role="status" aria-live="polite">
        {phase() === 'staging' && 'Sending the plan…'}
        {phase() === 'staged' && (props.watch
          ? 'Staged. Waiting for the reconciler to start.'
          : 'Staged. Nothing is live yet; this updates when the reconciler applies it.')}
        {phase() === 'applying' && 'Applying. The reconciler is making the change.'}
        {phase() === 'verified' && '✓ Applied and verified.'}
        {phase() === 'volatile' && 'Applied, but not kept across a restart.'}
        {phase() === 'failed' && 'Failed. Nothing new was applied.'}
        {note() && ` ${note()}`}
      </p>

      <Show when={!done()}>
        <div class="plan-diff-actions">
          <Show when={phase() === 'failed'} fallback={
            <button class="hp-btn hp-btn--primary" disabled={busy()} onClick={() => void approve()}>
              {phase() === 'staging' ? 'Staging…' : props.approveLabel ?? 'Approve plan'}
            </button>
          }>
            <button class="hp-btn hp-btn--primary" onClick={() => void approve()}>Retry</button>
          </Show>
          <button class="hp-btn" disabled={phase() === 'staging' || phase() === 'applying'} onClick={reject}>Reject</button>
        </div>
      </Show>
    </section>
  );
};

const ORDER: Phase[] = ['staged', 'applying', 'verified'];
function stepClass(p: Phase, step: Phase, staged: boolean): string {
  if (p === 'volatile') return step === 'verified' ? 'plan-step plan-step--warn' : 'plan-step plan-step--done';
  if (p === 'failed') {
    // Staging failed → "Staged" failed; staged but the reconciler failed → "Applying" failed.
    const failedAt = staged ? 'applying' : 'staged';
    if (step === failedAt) return 'plan-step plan-step--failed';
    return ORDER.indexOf(step) < ORDER.indexOf(failedAt) ? 'plan-step plan-step--done' : 'plan-step';
  }
  const cur = ORDER.indexOf(p === 'staging' ? 'staged' : p);
  const i = ORDER.indexOf(step);
  return `plan-step${i < cur || p === 'verified' ? ' plan-step--done' : i === cur ? ' plan-step--now' : ''}`;
}

export default PlanDiff;
