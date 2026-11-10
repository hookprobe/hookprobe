/**
 * Gate — the one capability-gated control wrapper (FR-04; MissionControl.md "capabilities, not
 * branches"). Wrap any control that needs a manifest grant:
 *
 *   <Gate cap="openvswitch"><button …>Edit segmentation</button></Gate>
 *   <Gate cap={['wan', 'multi_wan']} hide>…</Gate>
 *
 * granted → the children, untouched · denied → the children greyed out and inert, with the reason
 * written next to them (never a dead or no-op control) · denied + `hide`, or unknown → nothing.
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
  children: JSX.Element;
}

const Gate: Component<Props> = (props) => {
  const answer = () => (Array.isArray(props.cap) ? capAll(props.cap) : cap(props.cap));
  return (
    <Show when={answer().state !== 'unknown' && !(answer().state === 'denied' && props.hide)}>
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
