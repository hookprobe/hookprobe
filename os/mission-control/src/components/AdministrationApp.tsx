/**
 * AdministrationApp — Administration (`/admin/identity`): identity, the device and its lifecycle
 * (wireframe "Administration"; requirements doc §12). A settings layout: section list + pane.
 *
 *   Edge node      the Platform Manifest's grants and denials (with reasons), health, retention
 *   Signed packs   ADR 0056 upload: container (X.SIG + X.TXT) → begin (owner key) → chunks →
 *                  device verification (digest, signature, anti-rollback) → activate (owner key)
 *   Identity       owner-key rotation (ends every session) and sign out
 *   AI models      the planner's real status; no model is claimed when none is configured
 *   Audit log      accepted and refused actions, refused owner writes, upload events
 *   Feedback       the product-health beacon page (off by default)
 *   Factory reset  typed ERASE + reason + owner key; the device erases owner data and restarts
 * With no device answering, sample values render under the Sample-data banner.
 */
import { type Component, For, Show, createSignal, onMount } from 'solid-js';
import { substrate, deviceStats } from '../store/mock';
import { healthChecked, degraded } from '../store/health';
import { capList } from '../store/capabilities';
import { actionsView, refreshActions, post } from '../store/actions';
import { ownerRules, refreshOwnerRules } from '../store/ownerRules';
import { uploadView, refreshUploads, uploadPack, rollbackPack, PACK_LABEL, CONNECTIVITY, type UploadStep } from '../store/packUpload';
import { fetchPlannerStatus, type PlannerStatus } from '../store/plannerApi';
import AppShell from './AppShell';
import { postSigned, MSG } from '../store/envelope';
import { approve, askOwnerKey } from '../store/approve';
import SigningKeyPanel from './SigningKeyPanel';
import RestartButton from './RestartButton';
import { startNetworkLive } from '../store/networkLive';

type Sec = 'edge' | 'packs' | 'signing' | 'identity' | 'ai' | 'audit' | 'feedback' | 'reset';
const SECTIONS: [Sec, string][] = [['edge', 'Edge node'], ['packs', 'Signed packs'], ['signing', 'Signing key'], ['identity', 'Identity and access'], ['ai', 'AI models'], ['audit', 'Audit log'], ['feedback', 'Feedback and diagnostics'], ['reset', 'Factory reset']];
const STEPS: [UploadStep, string][] = [['begin', 'Begin'], ['upload', 'Upload'], ['verify', 'Device verifies'], ['activate', 'Activate'], ['done', 'Active']];
const field = { font: 'inherit', 'font-size': '16px', 'min-height': '44px', padding: '0 12px', background: 'var(--hp-surface)', color: 'var(--hp-text-primary)', border: '1px solid var(--hp-border)', 'border-radius': 'var(--hp-radius)' } as const;

const AdministrationApp: Component = () => {
  const [sec, setSec] = createSignal<Sec>('edge');
  const [planner, setPlanner] = createSignal<PlannerStatus | null | 'unreachable'>(null);
  const [packType, setPackType] = createSignal('ioc');
  const [file, setFile] = createSignal<File | null>(null);
  const [step, setStep] = createSignal<UploadStep | null>(null);
  const [sent, setSent] = createSignal(0);
  const [msg, setMsg] = createSignal('');
  const [newKey, setNewKey] = createSignal('');
  const [newKey2, setNewKey2] = createSignal('');
  const [erase, setErase] = createSignal('');

  onMount(() => {
    void refreshActions(); void refreshOwnerRules(); void refreshUploads(); startNetworkLive();
    void fetchPlannerStatus().then(setPlanner).catch(() => setPlanner('unreachable'));
  });

  const sample = () => healthChecked() && !substrate();
  const caps = () => capList();
  const ds = () => deviceStats();

  const upload = async () => {
    const f = file(); if (!f) return;
    setMsg(''); setSent(0);
    try {
      const r = await uploadPack(packType(), f, () => askOwnerKey('Send this pack to the device?', 'It changes what the device enforces. The device checks the signature and that it is newer first.', 'Send'), (s, n) => { setStep(s); setSent(n); });
      setRolledStaged(r.staged); setMsg(r.text);
    } catch (e) {
      setStep(null);
      setMsg(e instanceof Error ? e.message : String(e));
      void refreshUploads(); // the refusal is in the device's own audit trail; show it
    }
  };

  const [rolledStaged, setRolledStaged] = createSignal(false);
  const rollback = async (type: string, gen: number) => {
    const conn = CONNECTIVITY.has(type);
    const target = uploadView()?.types.find((t) => t.type === type)?.rollback_to ?? undefined;
    if (!(await approve({ title: `Roll back ${PACK_LABEL[type] ?? type}?`, body: `From generation ${gen} to generation ${target}, the previous verified one kept on the device.${conn ? '\n\nThis re-applies the older connectivity settings: if they no longer match your internet line or Wi-Fi, the device may go offline until you fix them.' : ''}`, confirm: 'Roll back', destructive: true }))) return;
    setMsg('');
    try {
      // Signed with your signing key (R6 = D); the target generation must be one the device reports.
      const r = await rollbackPack(type, target);
      setRolledStaged(r.staged); setMsg(r.text);
    } catch (e) { setMsg(e instanceof Error ? e.message : String(e)); }
  };

  const rotate = async () => {
    const a = await approve({ title: 'Change the owner key?', body: 'Every session ends, including this one. Sign in again with the new key. If you lose it, only re-flashing OWNER.TXT gets you back in.', confirm: 'Change it', destructive: true, reason: {}, key: { label: 'Current owner key' } });
    if (!a) return;
    const cur = a.key, reason = a.reason;
    const r = await post<{ ok: boolean; refused?: string; note?: string }>('/api/owner-key', { owner_key: cur, new_owner_key: newKey(), reason: reason.trim(), permanent: 'true' });
    if (r.ok) { setMsg(r.note ?? 'Rotated. Sign in with the new key.'); setTimeout(() => { location.href = '/login'; }, 2500); }
    else setMsg(`Refused by the device: ${r.refused}`);
  };

  const reset = async () => {
    const a = await approve({ title: 'Factory reset this device?', body: 'Erases owner settings and restarts the device as shipped. Your enrolled signing key and signed boot files stay.', confirm: 'Erase and restart', destructive: true, reason: {} });
    if (!a) return;
    const reason = a.reason;
    // R6 = D: authorised by an HQMGMT1 envelope (msg 32) signed with your signing key, not the owner token.
    try {
      const r = await postSigned<{ ok: boolean; refused?: string; note?: string }>('/api/factory-reset', { confirm: 'ERASE', reason: reason.trim(), permanent: 'true' }, { msg: MSG.FACTORY_RESET });
      setMsg(r.ok ? (r.note ?? 'Factory reset sealed. The device restarts.') : `Refused by the device: ${r.refused}`);
    } catch (e) { setMsg(e instanceof Error ? e.message : String(e)); }
  };

  return (
    <AppShell path="/admin/identity">
      <main class="pro-main" aria-label="Administration">
        <div class="pro-head">
          <div>
            <h1 class="pro-title">Administration</h1>
            <p class="pro-sub">Identity, the device and its lifecycle{substrate() ? ' · live from this device' : ''}</p>
          </div>
        </div>
        <Show when={msg()}><p class="pro-sub" role="status">{msg()}</p></Show>

        <div class="obs-grid">
          <nav class="pcard obs-sources" aria-label="Settings">
            <For each={SECTIONS}>{([s, label]) => (
              <button class={`shell-rail-item${sec() === s ? ' is-active' : ''}`} aria-pressed={sec() === s} onClick={() => { setSec(s); setMsg(''); }}>{label}</button>
            )}</For>
          </nav>

          <section style={{ display: 'flex', 'flex-direction': 'column', gap: '16px', 'min-width': 0 }}>
            <Show when={sec() === 'edge'}>
              <div class="bento">
                <div class="pcard span-12">
                  <p class="l0-label">Platform manifest · {caps().source === 'device' ? 'reported by this device' : 'sample (the device has not reported its own)'}</p>
                  <div class="l0-chips">
                    <For each={caps().granted}>{(c) => <span class="inc-status" style={{ color: 'var(--hp-text-primary)' }}>✓ {c}</span>}</For>
                  </div>
                  <Show when={caps().denied.length > 0}>
                    <p class="l0-label" style={{ 'margin-top': '8px' }}>Not granted on this hardware</p>
                    <For each={caps().denied}>{([c, why]) => <span class="prow"><span><s>{c}</s></span><span style={{ 'font-family': 'var(--hp-font)', 'white-space': 'normal', 'text-align': 'right' }}>{why}</span></span>}</For>
                    <p class="pcard-note">Controls that need these show greyed with the reason everywhere in Mission Control.</p>
                  </Show>
                </div>
                <div class="pcard span-6">
                  <p class="l0-label">Device</p>
                  <span class="prow"><span>Operating system</span><span>{sample() ? 'HookProbe OS · heqk' : substrate() ? `HookProbe OS · ${substrate()}` : '—'}</span></span>
                  <span class="prow"><span>Status</span><span>{degraded() ? 'degraded · enforcing last approved state' : sample() ? 'online' : substrate() ? 'online' : '—'}</span></span>
                  <span class="prow"><span>Rules armed</span><span>{sample() ? '11' : ds()?.rulesActive ?? '—'}</span></span>
                  <span class="prow"><span>Clock</span><span>{sample() ? 'ntp' : ds()?.clock ?? '—'}</span></span>
                  <span class="prow"><span>Last restart</span><span>{sample() ? 'power-on' : ds()?.lastReset ?? '—'}</span></span>
                </div>
                <div class="pcard span-6">
                  <p class="l0-label">Storage and retention</p>
                  <span class="prow"><span>Detections kept</span><span>{sample() ? '214 of 256' : ds() ? `${ds()!.detections} of ${ds()!.detectionsCap}` : '—'}</span></span>
                  <span class="prow"><span>Kept across restart</span><span>{sample() ? 'newest 64' : ds() ? (ds()!.sealedCap > 0 ? `newest ${ds()!.sealedCap}` : 'none (memory only)') : '—'}</span></span>
                  <span class="prow"><span>Owner journal</span><span>{sample() ? 'persistent · 12 records' : ownerRules() ? (ownerRules()!.persistent ? `persistent · ${ownerRules()!.journal.records} records` : 'memory only (no data volume)') : '—'}</span></span>
                  <p class="pcard-note">To keep more, send events out from Timeline &amp; Export or an alert webhook.</p>
                </div>
              </div>
            </Show>

            <Show when={sec() === 'packs'}>
              <div class="pcard">
                <p class="l0-label">Packs on this device</p>
                <div class="l0-table-wrap"><table class="l0-table obs-table">
                  <thead><tr><th scope="col">Pack</th><th scope="col">Generation</th><th scope="col">Source</th><th scope="col">Takes effect</th><th scope="col">Max size</th><th scope="col"><span class="sr-only">Rollback</span></th></tr></thead>
                  <tbody>
                    <Show when={!sample()} fallback={<tr><td>{PACK_LABEL.ioc}</td><td>7</td><td>store</td><td>now</td><td>16 MB</td><td /></tr>}>
                      <For each={uploadView()?.types ?? []} fallback={<tr><td colSpan={6} class="l0-muted">Not reported.</td></tr>}>{(t) => (
                        <tr><td>{PACK_LABEL[t.type] ?? t.type}</td><td class="l0-num" style={{ 'font-weight': 400 }}>{t.generation || '—'}</td><td>{t.source === 'store' ? 'uploaded' : 'from the boot image'}</td>
                          <td>{t.applies === 'next_boot' ? 'at the next restart' : t.applies === 'now' ? 'now' : '—'}</td><td>{Math.round(t.cap / 1024)} KB</td>
                          <td><Show when={typeof t.rollback_to === 'number'}>
                            <button class="hp-btn" style={{ 'min-height': '44px' }} onClick={() => void rollback(t.type, t.generation)}>Roll back to {t.rollback_to}</button>
                          </Show></td></tr>
                      )}</For>
                    </Show>
                  </tbody>
                </table></div>
                <Show when={rolledStaged()}><div class="l0-card-foot"><RestartButton label="Restart to apply the rollback" /></div></Show>
                <Show when={uploadView() && !uploadView()!.store}><p class="gate-reason">This device has no artifact store (no data volume), so uploads are refused; packs come from the boot image.</p></Show>
              </div>
              <div class="pcard">
                <p class="l0-label">Upload a signed pack</p>
                <p class="l0-card-sub">Choose the pack type and the container you built offline (<code>cat X.SIG X.TXT</code>). The device checks the digest, your operator signature and that it is newer than the active one before anything changes.</p>
                <div class="l0-chips" role="group" aria-label="Pack type">
                  <For each={Object.keys(PACK_LABEL)}>{(t) => (
                    <button class={`l0-chip${packType() === t ? ' is-on' : ''}`} aria-pressed={packType() === t} onClick={() => setPackType(t)}>{PACK_LABEL[t]}</button>
                  )}</For>
                </div>
                <label class="l0-card-sub" style={{ display: 'flex', 'flex-direction': 'column', gap: '4px' }}>Container file
                  <input type="file" style={{ ...field, padding: '8px' }} onChange={(e) => setFile(e.currentTarget.files?.[0] ?? null)} /></label>
                <Show when={step()}>
                  <ol class="plan-steps" aria-label="Upload progress">
                    <For each={STEPS}>{([s, label]) => {
                      const i = STEPS.findIndex(([x]) => x === s), cur = STEPS.findIndex(([x]) => x === step());
                      return <li class={`plan-step${i < cur || step() === 'done' ? ' plan-step--done' : i === cur ? ' plan-step--now' : ''}`}>{label}{s === 'upload' && step() === 'upload' && file() ? ` ${Math.round((sent() / file()!.size) * 100)}%` : ''}</li>;
                    }}</For>
                  </ol>
                </Show>
                <div class="l0-card-foot">
                  <button class="hp-btn hp-btn--primary" disabled={sample() || !file() || (step() !== null && step() !== 'done')} onClick={() => void upload()}>Upload and verify</button>
                </div>
                <Show when={sample()}><p class="gate-reason">Preview: on a device this uploads, verifies and activates the pack (owner key twice).</p></Show>
              </div>
            </Show>

            <Show when={sec() === 'signing'}>
              <SigningKeyPanel />
              <div class="pcard">
                <p class="l0-label">What it signs</p>
                <p class="l0-card-sub">Internet (WAN.TXT), Wi-Fi (WIFI.TXT) and firewall and routes (POLICY.TXT). Build a change in Get Online → Advanced, review it, sign it here in the browser; the device verifies your signature before anything changes.</p>
                <div class="l0-card-foot"><a class="hp-btn" href="/network/wan/advanced">Open Advanced settings</a></div>
              </div>
            </Show>

            <Show when={sec() === 'identity'}>
              <div class="pcard">
                <p class="l0-label">Owner key</p>
                <p class="l0-card-sub">The owner key signs you in and approves every durable change. Rotating it ends every session; the device keeps only a salted verifier, never the key.</p>
                <label class="l0-card-sub" style={{ display: 'flex', 'flex-direction': 'column', gap: '4px' }}>New owner key (16–128 characters)
                  <input type="password" style={field} value={newKey()} onInput={(e) => setNewKey(e.currentTarget.value)} autocomplete="new-password" /></label>
                <label class="l0-card-sub" style={{ display: 'flex', 'flex-direction': 'column', gap: '4px' }}>Repeat the new owner key
                  <input type="password" style={field} value={newKey2()} onInput={(e) => setNewKey2(e.currentTarget.value)} autocomplete="new-password" /></label>
                <Show when={newKey2() && newKey() !== newKey2()}><p class="plan-diff-warn" style={{ margin: 0 }}>The new keys differ.</p></Show>
                <div class="l0-card-foot">
                  <button class="hp-btn hp-btn--primary" disabled={sample() || newKey().trim().length < 16 || newKey().length > 128 || newKey() !== newKey2()} onClick={() => void rotate()}>Rotate owner key</button>
                  <Show when={substrate() === 'heqk'}>
                    <button class="hp-btn" onClick={async () => { try { await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' }); } catch { /* go anyway */ } location.href = '/login'; }}>Sign out</button>
                  </Show>
                </div>
                <p class="pcard-note">Lost the key? Re-flash OWNER.TXT on the boot disk: it always wins over a rotated key.</p>
              </div>
            </Show>

            <Show when={sec() === 'ai'}>
              <div class="pcard">
                <p class="l0-label">AEGIS planner</p>
                <Show when={planner()} fallback={<p class="pcard-note">Checking…</p>}>
                  <Show when={planner() !== 'unreachable'} fallback={<p class="l0-card-sub">The planner service did not answer.</p>}>
                    <p class="l0-card-sub">{(planner() as PlannerStatus).configured ? `Connected: ${(planner() as PlannerStatus).model} at ${(planner() as PlannerStatus).endpoint}` : (planner() as PlannerStatus).message ?? 'No AI planner is configured.'}</p>
                  </Show>
                </Show>
                <p class="l0-card-sub">Without a model the deterministic reconciler still decides and enforces everything; the planner only explains and proposes plans you approve.</p>
                <span class="gate gate--off">
                  <span class="gate-body" ref={(el) => el.setAttribute('inert', '')} aria-hidden="true"><input style={field} placeholder="http://localhost:11434 (Ollama)" /></span>
                  <span class="gate-reason" role="note">This device has no on-device planner; connect one through a control plane (any OpenAI-compatible endpoint, or local Ollama / llama.cpp / vLLM).</span>
                </span>
              </div>
            </Show>

            <Show when={sec() === 'audit'}>
              <div class="pcard">
                <p class="l0-label">Actions (accepted and refused)</p>
                <Show when={(actionsView()?.audit.length ?? 0) > 0} fallback={<p class="pcard-note">{sample() ? 'isolate · Kitchen camera · accepted · "malware contact"' : 'No actions recorded since start-up.'}</p>}>
                  <For each={actionsView()!.audit.slice(0, 30)}>{(a) => <span class="prow"><span>{a.kind.replace('_', ' ')} · {a.target} · "{a.reason}"</span><span>{a.ok ? 'accepted' : `refused: ${a.result}`} · {a.session}</span></span>}</For>
                </Show>
              </div>
              <div class="pcard">
                <p class="l0-label">Refused owner changes</p>
                <Show when={(ownerRules()?.refused.length ?? 0) > 0} fallback={<p class="pcard-note">None.</p>}>
                  <For each={ownerRules()!.refused}>{(x) => <span class="prow"><span>{x.why}</span><span>session {x.session}</span></span>}</For>
                </Show>
              </div>
              <div class="pcard">
                <p class="l0-label">Pack uploads</p>
                <Show when={(uploadView()?.recent.length ?? 0) > 0} fallback={<p class="pcard-note">None.</p>}>
                  <For each={uploadView()!.recent}>{(e) => <span class="prow"><span>{e.step} · {PACK_LABEL[e.type] ?? e.type}{e.why ? ` · ${e.why}` : ''}</span><span>{e.ok ? 'ok' : 'refused'}{e.generation ? ` · gen ${e.generation}` : ''}</span></span>}</For>
                </Show>
              </div>
            </Show>

            <Show when={sec() === 'feedback'}>
              <div class="pcard">
                <p class="l0-label">Feedback and diagnostics</p>
                <p class="l0-card-sub">The product-health beacon is off by default and never carries security data. Its page shows exactly what would leave the device and exports a diagnostics file that works air-gapped.</p>
                <div class="l0-card-foot"><a class="hp-btn" href="/admin/feedback">Open feedback and diagnostics</a></div>
              </div>
            </Show>

            <Show when={sec() === 'edge'}>
              <div class="pcard" aria-label="Restart">
                <p class="l0-label">Restart</p>
                <p class="l0-card-sub">Restarts the device (about a minute without network). Signed settings you have staged apply on the way up. Needs a reason and your owner key.</p>
                <RestartButton sample={sample()} />
              </div>
            </Show>

            <Show when={sec() === 'reset'}>
              <div class="pcard" style={{ 'border-color': 'rgba(255,107,107,.45)' }}>
                <p class="l0-label" style={{ color: 'var(--hp-red)' }}>Factory reset</p>
                <p class="l0-card-sub">Erases owner settings (owner rules, a rotated sign-in key, alert hook, uploaded packs) and restarts the device as shipped. Sign in afterwards with the key on its label. Not touched: your signed boot files and an enrolled signing (owner) key — only re-flashing the device removes that.</p>
                <label class="l0-card-sub" style={{ display: 'flex', 'flex-direction': 'column', gap: '4px' }}>Type ERASE to confirm
                  <input style={field} value={erase()} onInput={(e) => setErase(e.currentTarget.value)} autocomplete="off" /></label>
                <div class="l0-card-foot">
                  <button class="hp-btn" style={{ 'border-color': 'var(--hp-red)', color: 'var(--hp-red)' }} disabled={sample() || erase() !== 'ERASE'} onClick={() => void reset()}>Erase this device</button>
                </div>
              </div>
            </Show>
          </section>
        </div>
      </main>
    </AppShell>
  );
};

export default AdministrationApp;
