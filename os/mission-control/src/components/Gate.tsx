/**
 * Gate — the one capability-gated control wrapper (FR-04; MissionControl.md "capabilities, not
 * branches"). Wrap any control that needs a manifest grant:
 *
 *   <Gate cap="openvswitch"><button …>Edit segmentation</button></Gate>
 *   <Gate cap={['wan', 'multi_wan']} hide>…</Gate>
 *
 * granted → the children, untouched · denied → the children greyed out and inert, with the reason
 * written next to them (never a dead or no-op control) · denied + `hide`, or unknown → nothing.
 * granted + `notBuilt` → greyed out like denied, with that reason: the device has the capability but
 * Mission Control has no screen for it yet, so the control must not look usable.
 * The server still enforces every grant: hiding here is presentation only (NFR-08).
 */
import { type Component, type JSX, Show } from 'solid-js';
import { cap, capAll } from '../store/capabilities';

interface Props {
  cap: string | string[];
  /** Hide instead of greying out when denied (e.g. whole sections that make no sense here). */
  hide?: boolean;
  /** Render the reason inline (default) or only as a tooltip (dense toolbars). */
  reason?: 'inline' | 'tooltip';
  /** The control's screen is not built yet: even when granted, grey it out with this reason (AB-12). */
  notBuilt?: string;
  children: JSX.Element;
}

const Gate: Component<Props> = (props) => {
  const raw = () => (Array.isArray(props.cap) ? capAll(props.cap) : cap(props.cap));
  const answer = () => {
    const a = raw();
    return a.state === 'granted' && props.notBuilt ? { state: 'denied' as const, reason: props.notBuilt } : a;
  };
  return (
    <Show when={answer().state !== 'unknown' && !(raw().state === 'denied' && props.hide)}>
      <Show when={answer().state === 'denied'} fallback={props.children}>
        <span class="gate gate--off" title={answer().reason}>
          {/* inert: no focus, no clicks, skipped by assistive tech — the reason below explains why */}
          <span class="gate-body" ref={(el) => el.setAttribute('inert', '')} aria-hidden="true">
            {props.children}
          </span>
          <Show when={props.reason !== 'tooltip'}>
            <span class="gate-reason" role="note">{answer().reason}</span>
          </Show>
          <Show when={props.reason === 'tooltip'}>
            <span class="sr-only">{answer().reason}</span>
          </Show>
        </span>
      </Show>
    </Show>
  );
};

export default Gate;
