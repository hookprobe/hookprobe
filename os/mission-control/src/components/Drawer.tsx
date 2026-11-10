/**
 * Drawer — the one shared right side panel (requirements doc §Global shell): the AI explanation
 * panel, record detail drawers and the Copilot conversation all open here.
 *
 * 400 px overlay on desktop/compact, a full-height 80 % sheet on tablet, full width on phones.
 * Esc closes it; focus moves into it on open and back to the opener on close.
 */
import { type Component, type JSX, Show, createEffect, onCleanup } from 'solid-js';

interface Props {
  open: boolean;
  title: string;
  onClose: () => void;
  /** Small mono breadcrumb under the title (e.g. the evidence-graph path). */
  crumb?: string;
  children: JSX.Element;
  /** Pinned bottom row (primary actions sit in the bottom third on phones). */
  footer?: JSX.Element;
}

const Drawer: Component<Props> = (props) => {
  let panel: HTMLElement | undefined;
  let opener: Element | null = null;

  createEffect(() => {
    if (!props.open) return;
    opener = document.activeElement;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.stopPropagation(); props.onClose(); }
    };
    document.addEventListener('keydown', onKey);
    queueMicrotask(() => panel?.querySelector<HTMLElement>('.drawer-close')?.focus());
    onCleanup(() => {
      document.removeEventListener('keydown', onKey);
      if (opener instanceof HTMLElement) opener.focus();
    });
  });

  return (
    <Show when={props.open}>
      <div class="drawer-scrim" onClick={() => props.onClose()} aria-hidden="true" />
      <aside class="drawer" role="dialog" aria-label={props.title} ref={panel}>
        <header class="drawer-head">
          <h2 class="drawer-title">{props.title}</h2>
          <button class="drawer-close" onClick={() => props.onClose()} aria-label="Close panel">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" /></svg>
          </button>
        </header>
        <Show when={props.crumb}><p class="drawer-crumb">{props.crumb}</p></Show>
        <div class="drawer-body">{props.children}</div>
        <Show when={props.footer}><footer class="drawer-foot">{props.footer}</footer></Show>
      </aside>
    </Show>
  );
};

export default Drawer;
