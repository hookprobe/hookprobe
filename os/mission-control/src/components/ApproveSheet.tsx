/**
 * ApproveSheet — the modal behind `approve()` (store/approve.ts). One per page (AppShell, SetupApp).
 * role="dialog" + aria-modal, focus moves to the first field and is trapped inside, Esc cancels, focus returns to the
 * element that opened it. Secrets are masked; the passphrase needs a matching repeat.
 */
import { type Component, Show, createEffect, createSignal, onCleanup, onMount } from 'solid-js';
import { approveRequest, settleApprove } from '../store/approve';

const ApproveSheet: Component = () => {
  const [reason, setReason] = createSignal('');
  const [key, setKey] = createSignal('');
  const [pass, setPass] = createSignal('');
  const [pass2, setPass2] = createSignal('');
  let box: HTMLDivElement | undefined;
  let opener: Element | null = null;

  createEffect(() => {
    const r = approveRequest();
    if (!r) return;
    opener = document.activeElement;
    setReason(r.reason?.default ?? ''); setKey(''); setPass(''); setPass2('');
    queueMicrotask(() => (box?.querySelector('input, button') as HTMLElement | null)?.focus());
  });

  const problem = () => {
    const r = approveRequest();
    if (!r) return '';
    if (r.reason && reason().trim().length < 3) return 'Give a reason of at least 3 characters.';
    if (r.key && !key()) return 'Enter the device password.';
    if (r.passphrase) {
      if (pass().length < r.passphrase.min) return `The passphrase needs at least ${r.passphrase.min} characters.`;
      if (pass() !== pass2()) return 'The passphrases differ.';
    }
    return '';
  };
  const close = (ok: boolean) => {
    const back = opener as HTMLElement | null;
    if (ok && !problem()) settleApprove({ reason: reason().trim(), key: key(), passphrase: pass() });
    else if (!ok) settleApprove(null);
    else return;
    setKey(''); setPass(''); setPass2('');
    queueMicrotask(() => back?.focus?.());
  };
  const onKey = (e: KeyboardEvent) => {
    if (!approveRequest()) return;
    if (e.key === 'Escape') { e.preventDefault(); close(false); return; }
    if (e.key !== 'Tab' || !box) return;
    const f = [...box.querySelectorAll<HTMLElement>('input, button:not([disabled]), a[href]')];
    if (!f.length) return;
    const first = f[0], last = f[f.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  };
  onMount(() => {
    document.addEventListener('keydown', onKey);
    onCleanup(() => document.removeEventListener('keydown', onKey));
  });

  return (
    <Show when={approveRequest()}>{(r) => (
      <div class="approve-scrim" onClick={(e) => { if (e.target === e.currentTarget) close(false); }}>
        <div class="approve-sheet" ref={box} role="dialog" aria-modal="true" aria-labelledby="approve-title" aria-describedby="approve-body">
          <h2 id="approve-title" class="approve-title">{r().title}</h2>
          <Show when={r().body}><p id="approve-body" class="approve-body">{r().body}</p></Show>
          <form class="approve-form" onSubmit={(e) => { e.preventDefault(); close(true); }}>
            <Show when={r().reason}>
              <label class="approve-field">Reason (kept in the journal)
                <input class="approve-input" value={reason()} onInput={(e) => setReason(e.currentTarget.value)} autocomplete="off" />
              </label>
            </Show>
            <Show when={r().key}>
              <label class="approve-field">{r().key!.label ?? 'Device password (on the device’s label)'}
                <input class="approve-input" type="password" value={key()} onInput={(e) => setKey(e.currentTarget.value)} autocomplete="current-password" spellcheck={false} />
              </label>
            </Show>
            <Show when={r().passphrase}>
              <label class="approve-field">{r().passphrase!.label ?? 'Passphrase'} (at least {r().passphrase!.min} characters)
                <input class="approve-input" type="password" value={pass()} onInput={(e) => setPass(e.currentTarget.value)} autocomplete="new-password" />
              </label>
              <label class="approve-field">Repeat it
                <input class="approve-input" type="password" value={pass2()} onInput={(e) => setPass2(e.currentTarget.value)} autocomplete="new-password" />
              </label>
            </Show>
            <Show when={problem() && (reason() || key() || pass())}><p class="approve-problem" role="status">{problem()}</p></Show>
            <div class="approve-actions">
              <button type="button" class="hp-btn" onClick={() => close(false)}>Cancel</button>
              <button type="submit" class={`hp-btn ${r().destructive ? 'approve-danger' : 'hp-btn--primary'}`} disabled={!!problem()}>{r().confirm}</button>
            </div>
          </form>
        </div>
      </div>
    )}</Show>
  );
};

export default ApproveSheet;
