/**
 * PageHeader — the Layer 0 screen header (wireframes: Shield, My Network, Get Online, Timeline):
 * title, one plain-language status line, primary actions on the right, and an optional segmented
 * switch whose segments are real routes (e.g. Zones / Map / List).
 */
import { type Component, type JSX, For, Show } from 'solid-js';

interface Segment { label: string; href: string; active: boolean }

interface Props {
  title: string;
  status: JSX.Element;
  actions?: JSX.Element;
  segments?: Segment[];
  segmentsLabel?: string;
}

const PageHeader: Component<Props> = (props) => (
  <header class="l0-head">
    <div class="l0-head-text">
      <h1 class="l0-title">{props.title}</h1>
      <p class="l0-status">{props.status}</p>
    </div>
    <div class="l0-head-actions">
      <Show when={props.segments}>
        <nav class="l0-seg" aria-label={props.segmentsLabel ?? 'View'}>
          <For each={props.segments}>{(s) => (
            <a href={s.href} class={`l0-seg-item${s.active ? ' is-active' : ''}`} aria-current={s.active ? 'page' : undefined}>{s.label}</a>
          )}</For>
        </nav>
      </Show>
      {props.actions}
    </div>
  </header>
);

export default PageHeader;
