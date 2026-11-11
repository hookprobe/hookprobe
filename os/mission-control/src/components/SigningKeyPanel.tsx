/**
 * SigningKeyPanel — the owner's signing key in this browser (ADR 0058 D3/D4; wireframe "Setup step: create
 * your signing key").
 *
 *   create   needs a backup passphrase; the key is stored NON-extractable and the passphrase-wrapped
 *            backup (encrypted PKCS#8) downloads once, right then — the only copy that leaves the browser
 *   import   an encrypted backup (+ passphrase) or a plain PKCS#8 PEM from `policy-sign.py keygen`
 *   trust    GET /api/anchor when served (vendor key, enrolled owner key), else /api/network's trust anchor
 *   enroll   one-shot: makes this key the device's owner key (proof "HQENR1"||key, owner-key re-auth);
 *            afterwards WAN / WIFI / POLICY uploads must be signed by it
 *   rotate   a new key, authorised by the current one ("HQROT1"||new||gen), new backup, then swapped in
 * The private key and the passphrase never reach the device.
 */
import { type Component, For, Show, createSignal, onMount } from 'solid-js';
import { ownerKey, loadOwnerKey, checkSigning, signingSupported, generateOwnerKey, importOwnerKeyPem, exportOwnerKeyBackup, deleteOwnerKey, download, enrollProof, prepareRotation, MIN_PASSPHRASE } from '../store/signing';
import { isEncryptedPem } from '../store/keyBackup';
import { anchorView, anchorState, refreshAnchor, enroll, rotate } from '../store/anchor';
import { networkView } from '../store/networkLive';

const input = { font: 'inherit', 'font-size': '16px', 'min-height': '44px', padding: '0 12px', background: 'var(--hp-surface)', color: 'var(--hp-text-primary)', border: '1px solid var(--hp-border)', 'border-radius': 'var(--hp-radius)', width: '100%', 'box-sizing': 'border-box' } as const;
const LOSS = 'If you lose both this browser’s key and the backup, getting control back needs physical access to the device: re-flashing its boot card. A factory reset does not remove an enrolled owner key.';

const SigningKeyPanel: Component<{ compact?: boolean }> = (props) => {
  const [msg, setMsg] = createSignal('');
  const [pem, setPem] = createSignal('');
  const [pass, setPass] = createSignal('');
  const [pass2, setPass2] = createSignal('');
  const [importing, setImporting] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  onMount(() => { void checkSigning(); void loadOwnerKey(); void refreshAnchor(); });

  const fp = () => ownerKey()?.pubHex.slice(0, 8) ?? '';
  const passOk = () => pass().length >= MIN_PASSPHRASE && pass() === pass2();
  const run = async (f: () => Promise<unknown>, ok: string) => {
    setMsg(''); setBusy(true);
    try { await f(); setMsg(ok); } catch (e) { setMsg(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); }
  };
  const askOwnerKey = () => window.prompt('This is a permanent change. Enter the device owner key (from its label):', '') ?? '';

  /** What the device trusts for signed configuration, compared in full where the device reports it. */
  const trust = () => {
    const me = ownerKey()?.pubHex;
    if (!me) return null;
    const a = anchorView();
    if (a) {
      if (a.owner_key) return a.owner_key === me
        ? { ok: true, text: 'This is the device’s owner key: it signs your internet, Wi-Fi and firewall settings.' }
        : { ok: false, text: `The device has a different owner key (${a.owner_key.slice(0, 8)}…). Import that key's backup to sign for it.` };
      if (a.vendor_key) return a.vendor_key === me
        ? { ok: true, text: 'This is the image’s operator key: the device accepts files signed with it.' }
        : { ok: false, text: `The device verifies files with the image's operator key (${a.vendor_key.slice(0, 8)}…), not this one. Make this key the owner key below.` };
      return { ok: false, text: 'This device has no operator key (standalone): it accepts unsigned boot files. Make this key the owner key below.' };
    }
    const t = networkView()?.trust_anchor;
    if (!t) return null;
    if (t.state.startsWith('standalone')) return { ok: false, text: 'This device has no operator key (standalone): it accepts unsigned files and does not check this key.' };
    const same = t.public_key ? t.public_key.toLowerCase() === me : t.key.toLowerCase() === fp();
    return same ? { ok: true, text: `The device trusts this key (${t.public_key ? 'full public key matches' : `pinned operator key ${t.key}…`}).` }
      : { ok: false, text: `The device trusts a different key (${t.key}…). Files signed here will be refused.` };
  };

  const create = () => run(async () => {
    const { backup } = await generateOwnerKey(pass());
    download('owner-signing-key.pem', backup, 'application/x-pem-file');
    setPass(''); setPass2('');
  }, 'Key created. Its backup (encrypted with your passphrase) downloaded: keep it offline. ' + LOSS);

  const doEnroll = () => run(async () => {
    if (!window.confirm('Make this key the device’s owner key?\n\nThis is one-shot. Afterwards the device refuses internet, Wi-Fi and firewall uploads that are unsigned or signed only with the image’s key. The factory files on its boot card keep working. Changing the owner key later needs this key (rotate) or re-flashing the device; a factory reset keeps it.')) throw new Error('Cancelled.');
    const k = askOwnerKey(); if (!k) throw new Error('Cancelled: the owner key is required.');
    const p = await enrollProof();
    const r = await enroll({ public_key: p.publicKey, proof: p.proof, owner_key: k });
    if (!r.ok) throw new Error(`The device refused: ${r.refused}`);
  }, 'Enrolled: this is now the device’s owner key.');

  const doRotate = () => run(async () => {
    const a = anchorView()!;
    const gen = a.owner_generation + 1;
    const k = askOwnerKey(); if (!k) throw new Error('Cancelled: the owner key is required.');
    const r0 = await prepareRotation(gen, pass());
    const r = await rotate({ public_key: r0.publicKey, proof: r0.proof, generation: String(gen), signature: r0.signature, owner_key: k });
    if (!r.ok) throw new Error(`The device refused (your current key is unchanged): ${r.refused}`);
    await r0.commit();
    download('owner-signing-key.pem', r0.backup, 'application/x-pem-file');
    setPass(''); setPass2('');
  }, 'Rotated: the device now trusts the new key, which replaced the old one here. Its encrypted backup downloaded. ' + LOSS);

  const PassFields = () => (
    <>
      <label class="l0-card-sub" style={{ display: 'flex', 'flex-direction': 'column', gap: '4px' }}>Backup passphrase (at least {MIN_PASSPHRASE} characters)
        <input style={input} type="password" value={pass()} onInput={(e) => setPass(e.currentTarget.value)} autocomplete="new-password" /></label>
      <label class="l0-card-sub" style={{ display: 'flex', 'flex-direction': 'column', gap: '4px' }}>Repeat it
        <input style={input} type="password" value={pass2()} onInput={(e) => setPass2(e.currentTarget.value)} autocomplete="new-password" /></label>
      <Show when={pass2() && pass() !== pass2()}><p class="plan-diff-warn" style={{ margin: 0 }}>The passphrases differ.</p></Show>
    </>
  );

  return (
    <div class="pcard" aria-label="Signing key">
      <p class="l0-label">Your signing key</p>
      <Show when={signingSupported() !== false} fallback={
        <p class="gate-reason">This browser cannot create Ed25519 signatures. Use a current Chrome, Edge, Firefox or Safari.</p>
      }>
        <Show when={ownerKey()} fallback={
          <>
            <Show when={!props.compact}>
              <p class="l0-card-sub">Big changes — your internet login, Wi-Fi or firewall — only apply when you sign them with this key. It stays in this browser and cannot be read back out; the device keeps only the public half.</p>
            </Show>
            <PassFields />
            <p class="pcard-note">The passphrase encrypts the one backup file you download now. It is never sent anywhere. {LOSS}</p>
            <div class="l0-card-foot">
              <button class="hp-btn hp-btn--primary" disabled={!passOk() || busy()} onClick={() => void create()}>Create key and download backup</button>
              <button class="hp-btn" onClick={() => setImporting(!importing())}>Import a backup</button>
            </div>
          </>
        }>
          <span class="prow"><span>Public key</span><span style={{ 'white-space': 'normal', 'overflow-wrap': 'anywhere', 'text-align': 'right' }}>{ownerKey()!.pubHex}</span></span>
          <span class="prow"><span>Fingerprint</span><span>{fp()}…</span></span>
          <span class="prow"><span>Origin</span><span>{ownerKey()!.source === 'generated' ? 'created in this browser' : 'imported'} · {new Date(ownerKey()!.created).toLocaleDateString()}</span></span>
          <Show when={trust()}>
            <p class={trust()!.ok ? 'go-state--up' : 'plan-diff-warn'} role="status" style={{ margin: 0 }}>{trust()!.ok ? '✓ ' : '⚠ '}{trust()!.text}</p>
          </Show>

          <Show when={!props.compact && anchorView()}>
            <div aria-label="Owner key on the device" style={{ display: 'grid', gap: '8px' }}>
              <span class="prow"><span>Device verifies settings with</span><span>{anchorView()!.config_files_verified_by}</span></span>
              <Show when={anchorView()!.floors}>
                <For each={(['wan', 'wifi', 'policy'] as const).filter((k) => anchorView()!.floors![k] !== undefined)}>{(k) => {
                  const f = () => { const v = anchorView()!.floors![k]!; return typeof v === 'number' ? { current: null, floor: v } : v; };
                  return (
                    <span class="prow"><span>{k === 'wan' ? 'Internet' : k === 'wifi' ? 'Wi-Fi' : 'Firewall'} settings</span>
                      <span>{f().current !== null ? `generation ${f().current} · ` : ''}older than {f().floor + 1} refused</span></span>
                  );
                }}</For>
              </Show>
              <Show when={anchorView()!.can === 'enroll' && anchorView()!.vendor_key !== ownerKey()!.pubHex}>
                <p class="l0-card-sub">Make this the device's owner key: from then on only files signed with it change the internet, Wi-Fi or firewall settings. One-shot; the factory files on the boot card keep working.</p>
                <div class="l0-card-foot"><button class="hp-btn hp-btn--primary" disabled={busy()} onClick={() => void doEnroll()}>Make this the owner key</button></div>
              </Show>
              <Show when={anchorView()!.can === 'rotate' && anchorView()!.owner_key === ownerKey()!.pubHex}>
                <p class="l0-card-sub">Rotate: make a new owner key, authorised by this one (generation {anchorView()!.owner_generation} → {anchorView()!.owner_generation + 1}). The new key gets its own encrypted backup.</p>
                <PassFields />
                <div class="l0-card-foot"><button class="hp-btn" disabled={!passOk() || busy()} onClick={() => void doRotate()}>Rotate the owner key</button></div>
              </Show>
            </div>
          </Show>
          <Show when={!props.compact && anchorState() === 'absent'}>
            <p class="pcard-note">This device cannot enroll an owner key yet (ADR 0058); it verifies files with the image's operator key.</p>
          </Show>

          <div class="l0-card-foot">
            <Show when={ownerKey()!.exportable}>
              <button class="hp-btn" disabled={busy()} onClick={() => {
                const p = window.prompt(`Passphrase to encrypt the backup (at least ${MIN_PASSPHRASE} characters):`, '') ?? '';
                void run(async () => download('owner-signing-key.pem', await exportOwnerKeyBackup(p), 'application/x-pem-file'), 'Encrypted backup downloaded.');
              }}>Download encrypted backup</button>
            </Show>
            <Show when={!props.compact}>
              <button class="hp-btn" onClick={() => setImporting(!importing())}>Replace with another key</button>
              <button class="hp-btn" onClick={() => { if (window.confirm('Remove the signing key from this browser? Without its backup it is gone for good.')) void run(deleteOwnerKey, 'Removed from this browser.'); }}>Remove from this browser</button>
            </Show>
          </div>
        </Show>
        <Show when={importing()}>
          <label class="l0-card-sub" style={{ display: 'flex', 'flex-direction': 'column', gap: '4px' }}>Paste the backup (PEM)
            <textarea rows={5} value={pem()} onInput={(e) => setPem(e.currentTarget.value)} spellcheck={false}
              style={{ font: '12px var(--hp-font-mono)', padding: '8px', background: 'var(--hp-surface)', color: 'var(--hp-text-primary)', border: '1px solid var(--hp-border)', 'border-radius': 'var(--hp-radius)' }} />
          </label>
          <Show when={isEncryptedPem(pem())}>
            <label class="l0-card-sub" style={{ display: 'flex', 'flex-direction': 'column', gap: '4px' }}>Backup passphrase
              <input style={input} type="password" value={pass()} onInput={(e) => setPass(e.currentTarget.value)} autocomplete="current-password" /></label>
          </Show>
          <div class="l0-card-foot"><button class="hp-btn hp-btn--primary" disabled={!pem().includes('PRIVATE KEY') || busy()}
            onClick={() => void run(async () => { await importOwnerKeyPem(pem(), pass()); setPem(''); setPass(''); setImporting(false); }, 'Key imported. It stays in this browser and cannot be read back out.')}>Import</button></div>
        </Show>
        <p class="pcard-note">Passkeys and hardware security keys sign in a format the device does not check yet (ADR 0058), so the key lives in this browser.</p>
      </Show>
      <Show when={msg()}><p class="pro-sub" role="status" style={{ margin: 0 }}>{msg()}</p></Show>
    </div>
  );
};

export default SigningKeyPanel;
