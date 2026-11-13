/**
 * QrSheet — "Share QR" for the home Wi-Fi (wireframe GetOnline: the Wi-Fi card's second button). The device never
 * shows the password back, so the code is built here, in this browser, from the password you type (or the one you
 * just set in WifiSheet); nothing is sent anywhere. Dark modules on white with a quiet zone, so phones scan it in the
 * dark theme too.
 */
import { type Component, Show, createMemo, createSignal, onCleanup, onMount } from 'solid-js';
import { qrMatrix, wifiQrText } from '../store/qr';

const QrSheet: Component<{ ssid: string; security: string; psk?: string; onClose: () => void }> = (props) => {
  const [ssid, setSsid] = createSignal(props.ssid);
  const [psk, setPsk] = createSignal(props.psk ?? '');
  let box: HTMLDivElement | undefined;
  const opener = document.activeElement as HTMLElement | null;

  // one path: a 1×1 square per dark module, offset by the 4-module quiet zone
  const qr = createMemo(() => {
    if (!ssid() || psk().length < 8) return null;
    try {
      const m = qrMatrix(wifiQrText(ssid(), psk(), props.security));
      let d = '';
      m.forEach((row, y) => row.forEach((c, x) => { if (c) d += `M${x + 4} ${y + 4}h1v1h-1z`; }));
      return { d, n: m.length + 8 };
    } catch { return null; }
  });

  const close = () => { props.onClose(); queueMicrotask(() => opener?.focus?.()); };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'Escape') { e.preventDefault(); close(); return; }
    if (e.key !== 'Tab' || !box) return;
    const f = [...box.querySelectorAll<HTMLElement>('input, button')];
    if (e.shiftKey && document.activeElement === f[0]) { e.preventDefault(); f[f.length - 1].focus(); }
    else if (!e.shiftKey && document.activeElement === f[f.length - 1]) { e.preventDefault(); f[0].focus(); }
  };
  onMount(() => {
    document.addEventListener('keydown', onKey);
    onCleanup(() => document.removeEventListener('keydown', onKey));
    (box?.querySelector(props.psk ? 'button' : 'input[type=password]') as HTMLElement | null)?.focus();
  });

  return (
    <div class="approve-scrim" onClick={(e) => { if (e.target === e.currentTarget) close(); }}>
      <div class="approve-sheet" ref={box} role="dialog" aria-modal="true" aria-labelledby="qr-sheet-title">
        <h2 id="qr-sheet-title" class="approve-title">Share Wi-Fi with a QR code</h2>
        <p class="approve-body">Guests point their phone camera at the code to join. It is made in this browser; the password is not sent anywhere.</p>
        <Show when={!props.psk}>
          <label class="approve-field">Wi-Fi name
            <input class="approve-input" value={ssid()} onInput={(e) => setSsid(e.currentTarget.value)} autocomplete="off" spellcheck={false} />
          </label>
          <label class="approve-field">Wi-Fi password (the device never shows it, so type it here)
            <input class="approve-input" type="password" value={psk()} onInput={(e) => setPsk(e.currentTarget.value)} autocomplete="off" spellcheck={false} />
          </label>
        </Show>
        <Show when={qr()} fallback={<p class="pcard-note" style={{ margin: 0 }}>{ssid() ? 'The code appears once the password is at least 8 characters.' : 'Enter the Wi-Fi name.'}</p>}>
          <svg class="qr-code" viewBox={`0 0 ${qr()!.n} ${qr()!.n}`} role="img" aria-label={`QR code to join ${ssid()}`} shape-rendering="crispEdges">
            <rect width={qr()!.n} height={qr()!.n} fill="#fff" />
            <path d={qr()!.d} fill="#000" />
          </svg>
          <p class="pcard-note" style={{ margin: 0, 'text-align': 'center' }}>{ssid()}</p>
        </Show>
        <div class="approve-actions"><button type="button" class="hp-btn hp-btn--primary" onClick={close}>Done</button></div>
      </div>
    </div>
  );
};

export default QrSheet;
