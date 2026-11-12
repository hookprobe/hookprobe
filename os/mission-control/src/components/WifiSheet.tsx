/**
 * WifiSheet — Layer 0 "Change password" for the home Wi-Fi (wireframe GetOnline: the Wi-Fi card's own button,
 * not the three-tab advanced editor). One form: name, new password, the PPPoE password when the internet in force
 * has one (never served, so it is typed again), the device password. It signs a bundle with every section in force
 * (store/bundle.ts) and the device applies it live as a trial; the Keep banner (ConfigBanners) finishes it.
 */
import { type Component, Show, createSignal, onCleanup, onMount } from 'solid-js';
import { refreshConfig } from '../store/configState';
import { refreshAnchor } from '../store/anchor';
import { refreshUploads } from '../store/packUpload';
import { loadOwnerKey } from '../store/signing';
import { checkWifi } from '../store/configBuild';
import { wifiBlock, wifiNow, needsPppoePass, wifiSections, sendBundle } from '../store/bundle';

const WifiSheet: Component<{ onClose: () => void; preview?: boolean }> = (props) => {
  const [ssid, setSsid] = createSignal('');
  const [psk, setPsk] = createSignal('');
  const [show, setShow] = createSignal(false);
  const [pppoe, setPppoe] = createSignal('');
  const [key, setKey] = createSignal('');
  const [busy, setBusy] = createSignal(false);
  const [done, setDone] = createSignal<{ text: string; confirm: boolean } | null>(null);
  const [err, setErr] = createSignal('');
  let box: HTMLDivElement | undefined;
  const opener = document.activeElement as HTMLElement | null;

  const form = () => ({ ...wifiNow(), ssid: ssid(), psk: psk() });
  const block = () => (props.preview ? 'Preview: no device is connected.' : wifiBlock());
  const problems = () => [...checkWifi(form()), ...(needsPppoePass() && !pppoe() ? ['Type your internet (PPPoE) password again.'] : []), ...(!key() ? ['Enter the device password.'] : [])];

  const close = () => { props.onClose(); queueMicrotask(() => opener?.focus?.()); };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'Escape' && !busy()) { e.preventDefault(); close(); return; }
    if (e.key !== 'Tab' || !box) return;
    const f = [...box.querySelectorAll<HTMLElement>('input, button:not([disabled]), a[href]')];
    if (!f.length) return;
    if (e.shiftKey && document.activeElement === f[0]) { e.preventDefault(); f[f.length - 1].focus(); }
    else if (!e.shiftKey && document.activeElement === f[f.length - 1]) { e.preventDefault(); f[0].focus(); }
  };
  onMount(async () => {
    document.addEventListener('keydown', onKey);
    onCleanup(() => document.removeEventListener('keydown', onKey));
    if (!props.preview) await Promise.all([refreshConfig(), refreshAnchor(), refreshUploads(), loadOwnerKey()]);
    setSsid(wifiNow().ssid);
    (box?.querySelector('input[type=password], a[href], button') as HTMLElement | null)?.focus();
  });

  const send = async () => {
    if (problems().length || block()) return;
    setBusy(true); setErr('');
    try {
      const r = await sendBundle(wifiSections(form(), pppoe()), key());
      setDone({ text: r.text, confirm: !!r.needsConfirm });
      setPsk(''); setPppoe(''); setKey('');
      void refreshConfig();
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  };

  return (
    <div class="approve-scrim" onClick={(e) => { if (e.target === e.currentTarget && !busy()) close(); }}>
      <div class="approve-sheet" ref={box} role="dialog" aria-modal="true" aria-labelledby="wifi-sheet-title">
        <h2 id="wifi-sheet-title" class="approve-title">{done() ? 'Wi-Fi changed' : 'Change Wi-Fi password'}</h2>
        <Show when={!done()} fallback={
          <>
            <p class="approve-body" role="status">{done()!.confirm
              ? 'The device is switching to the new Wi-Fi now. Devices drop off and join again with the new password. Reconnect this phone or computer, open Mission Control and press Keep within 5 minutes, or the old Wi-Fi comes back by itself.'
              : 'The device is switching to the new Wi-Fi now. It keeps the change by itself once everything works, or switches back on its own.'}</p>
            <p class="pcard-note" style={{ margin: 0 }}>{done()!.text}</p>
            <div class="approve-actions"><button type="button" class="hp-btn hp-btn--primary" onClick={close}>Done</button></div>
          </>
        }>
          <Show when={!block()} fallback={
            <>
              <p class="approve-body" role="note">{block()}</p>
              <div class="approve-actions">
                <button type="button" class="hp-btn" onClick={close}>Close</button>
                <Show when={!props.preview}><a class="hp-btn hp-btn--primary" href={/signing key/.test(block()) ? '/admin/identity' : '/network/wifi'}>{/signing key/.test(block()) ? 'Set up your signing key' : 'Open the advanced editor'}</a></Show>
              </div>
            </>
          }>
            <p class="approve-body">If this phone or computer uses this Wi-Fi, it disconnects for a moment: join again with the new password.</p>
            <form class="approve-form" onSubmit={(e) => { e.preventDefault(); void send(); }}>
              <label class="approve-field">Wi-Fi name
                <input class="approve-input" value={ssid()} onInput={(e) => setSsid(e.currentTarget.value)} autocomplete="off" spellcheck={false} />
              </label>
              <label class="approve-field">New Wi-Fi password (8–63 characters)
                <input class="approve-input" type={show() ? 'text' : 'password'} value={psk()} onInput={(e) => setPsk(e.currentTarget.value)} autocomplete="new-password" spellcheck={false} />
              </label>
              <label class="approve-check"><input type="checkbox" checked={show()} onChange={(e) => setShow(e.currentTarget.checked)} /> Show password</label>
              <Show when={needsPppoePass()}>
                <label class="approve-field">Internet (PPPoE) password, from your provider
                  <input class="approve-input" type="password" value={pppoe()} onInput={(e) => setPppoe(e.currentTarget.value)} autocomplete="off" />
                </label>
                <p class="pcard-note" style={{ margin: 0 }}>Your internet settings are sent again unchanged. The device never shows this password back, so type it once more.</p>
              </Show>
              <label class="approve-field">Device password (on the device’s label)
                <input class="approve-input" type="password" value={key()} onInput={(e) => setKey(e.currentTarget.value)} autocomplete="current-password" spellcheck={false} />
              </label>
              <Show when={(psk() || ssid() !== wifiNow().ssid) && problems().length}><p class="approve-problem" role="status">{problems()[0]}</p></Show>
              <Show when={err()}><p class="approve-problem" role="alert">Not changed: {err()}</p></Show>
              <p class="pcard-note" style={{ margin: 0 }}>Signed with your signing key. Your firewall and other settings stay as they are.</p>
              <div class="approve-actions">
                <button type="button" class="hp-btn" onClick={close} disabled={busy()}>Cancel</button>
                <button type="submit" class="hp-btn hp-btn--primary" disabled={busy() || problems().length > 0}>{busy() ? 'Sending…' : 'Change password'}</button>
              </div>
            </form>
          </Show>
        </Show>
      </div>
    </div>
  );
};

export default WifiSheet;
