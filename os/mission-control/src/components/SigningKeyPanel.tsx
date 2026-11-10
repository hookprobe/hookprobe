/**
 * SigningKeyPanel — the owner's signing key in this browser (ADR 0058 D4; wireframe "Setup step: create
 * your signing key"). Create or import (PKCS#8 PEM, e.g. from `policy-sign.py keygen`), download the
 * backup, see the public key, and whether the device trusts it (its pinned trust anchor fingerprint =
 * the first 4 bytes of the operator public key).
 */
import { type Component, Show, createSignal, onMount } from 'solid-js';
import { ownerKey, loadOwnerKey, checkSigning, signingSupported, generateOwnerKey, importOwnerKeyPem, exportOwnerKeyPem, deleteOwnerKey, download } from '../store/signing';
import { networkView } from '../store/networkLive';

const SigningKeyPanel: Component<{ compact?: boolean }> = (props) => {
  const [msg, setMsg] = createSignal('');
  const [pem, setPem] = createSignal('');
  const [importing, setImporting] = createSignal(false);
  onMount(() => { void checkSigning(); void loadOwnerKey(); });

  const fp = () => ownerKey()?.pubHex.slice(0, 8) ?? '';
  const anchor = () => networkView()?.trust_anchor;
  const trust = () => {
    const a = anchor();
    if (!ownerKey() || !a) return null;
    if (a.state.startsWith('standalone')) return { ok: false, text: 'This device has no operator key (standalone): it accepts unsigned files and does not check this key.' };
    // Compare the whole 32-byte key when the device reports it; older images give only the 4-byte fingerprint.
    const same = a.public_key ? a.public_key.toLowerCase() === ownerKey()!.pubHex : a.key.toLowerCase() === fp();
    return same
      ? { ok: true, text: `The device trusts this key (${a.public_key ? 'full public key matches' : `pinned operator key ${a.key}…`}).` }
      : { ok: false, text: `The device trusts a different key (${a.key}…). Files signed here will be refused until this key is enrolled (ADR 0058) or you import the device's operator key.` };
  };

  const run = async (f: () => Promise<unknown>, ok: string) => {
    setMsg('');
    try { await f(); setMsg(ok); } catch (e) { setMsg(e instanceof Error ? e.message : String(e)); }
  };

  return (
    <div class="pcard" aria-label="Signing key">
      <p class="l0-label">Your signing key</p>
      <Show when={signingSupported() !== false} fallback={
        <p class="gate-reason">This browser cannot create Ed25519 signatures. Use a current Chrome, Edge, Firefox or Safari.</p>
      }>
        <Show when={ownerKey()} fallback={
          <>
            <Show when={!props.compact}>
              <p class="l0-card-sub">Big changes — your internet login, Wi-Fi or firewall — only apply when you sign them with this key. It stays in this browser; the device keeps only the public half.</p>
            </Show>
            <div class="l0-card-foot">
              <button class="hp-btn hp-btn--primary" onClick={() => void run(generateOwnerKey, 'Key created. Download the backup now and keep it offline.')}>Create a key in this browser</button>
              <button class="hp-btn" onClick={() => setImporting(!importing())}>Import an existing key</button>
            </div>
          </>
        }>
          <span class="prow"><span>Public key</span><span style={{ 'white-space': 'normal', 'overflow-wrap': 'anywhere', 'text-align': 'right' }}>{ownerKey()!.pubHex}</span></span>
          <span class="prow"><span>Fingerprint</span><span>{fp()}…</span></span>
          <span class="prow"><span>Origin</span><span>{ownerKey()!.source === 'generated' ? 'created in this browser' : 'imported'} · {new Date(ownerKey()!.created).toLocaleDateString()}</span></span>
          <Show when={trust()}>
            <p class={trust()!.ok ? 'go-state--up' : 'plan-diff-warn'} role="status" style={{ margin: 0 }}>{trust()!.ok ? '✓ ' : '⚠ '}{trust()!.text}</p>
          </Show>
          <div class="l0-card-foot">
            <button class="hp-btn" onClick={() => void run(async () => download('owner-signing-key.pem', await exportOwnerKeyPem(), 'application/x-pem-file'), 'Backup downloaded. It works with policy-sign.py too.')}>Download backup (PEM)</button>
            <Show when={!props.compact}>
              <button class="hp-btn" onClick={() => setImporting(!importing())}>Replace with another key</button>
              <button class="hp-btn" onClick={() => { if (window.confirm('Remove the signing key from this browser? Keep a backup first.')) void run(deleteOwnerKey, 'Removed from this browser.'); }}>Remove from this browser</button>
            </Show>
          </div>
        </Show>
        <Show when={importing()}>
          <label class="l0-card-sub" style={{ display: 'flex', 'flex-direction': 'column', gap: '4px' }}>Paste a PKCS#8 private key (PEM)
            <textarea rows={5} value={pem()} onInput={(e) => setPem(e.currentTarget.value)} spellcheck={false}
              style={{ font: '12px var(--hp-font-mono)', padding: '8px', background: 'var(--hp-surface)', color: 'var(--hp-text-primary)', border: '1px solid var(--hp-border)', 'border-radius': 'var(--hp-radius)' }} />
          </label>
          <div class="l0-card-foot"><button class="hp-btn hp-btn--primary" disabled={!pem().includes('PRIVATE KEY')}
            onClick={() => void run(async () => { await importOwnerKeyPem(pem()); setPem(''); setImporting(false); }, 'Key imported.')}>Import</button></div>
        </Show>
        <p class="pcard-note">Passkeys and hardware security keys sign in a format the device does not check yet (ADR 0058), so the key lives in this browser.</p>
      </Show>
      <Show when={msg()}><p class="pro-sub" role="status" style={{ margin: 0 }}>{msg()}</p></Show>
    </div>
  );
};

export default SigningKeyPanel;
