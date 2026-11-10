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
import { uploadView, refreshUploads, uploadPack, PACK_LABEL, type UploadStep } from '../store/packUpload';
import { fetchPlannerStatus, type PlannerStatus } from '../store/plannerApi';
import AppShell from './AppShell';

type Sec = 'edge' | 'packs' | 'identity' | 'ai' | 'audit' | 'feedback' | 'reset';
const SECTIONS: [Sec, string][] = [['edge', 'Edge node'], ['packs', 'Signed packs'], ['identity', 'Identity and access'], ['ai', 'AI models'], ['audit', 'Audit log'], ['feedback', 'Feedback and diagnostics'], ['reset', 'Factory reset']];
const STEPS: [UploadStep, string][] = [['begin', 'Begin'], ['upload', 'Upload'], ['verify', 'Device verifies'], ['activate', 'Activate'], ['done', 'Active']];
const field = { font: 'inherit', 'min-height': '40px', padding: '0 12px', background: 'var(--hp-surface)', color: 'var(--hp-text-primary)', border: '1px solid var(--hp-border)', 'border-radius': 'var(--hp-radius)' } as const;

const AdministrationApp: Component = () => {
  const [sec, setSec] = createSignal<Sec>('edge');
  const [planner, setPlanner] = createSignal<PlannerStatus | null | 'unreachable'>(null);
  const [packType, setPackType] = createSignal('ioc');
  const [file, setFile] = createSignal<File | null>(null);
  const [step, setStep] = createSignal<UploadStep | null>(null);
  const [sent, setSent] = createSignal(0);
  const [msg, setMsg] = createSignal('');
  const [newKey, setNewKey] = createSignal('');
  const [erase, setErase] = createSignal('');

  onMount(() => {
    void refreshActions(); void refreshOwnerRules(); void refreshUploads();
    void fetchPlannerStatus().then(setPlanner).catch(() => setPlanner('unreachable'));
  });

  const sample = () => healthChecked() && !substrate();
  const caps = () => capList();
  const ds = () => deviceStats();

  const upload = async () => {
    const f = file(); if (!f) return;
    setMsg(''); setSent(0);
    try {
      const m = await uploadPack(packType(), f, () => window.prompt('This changes what the device enforces. Enter your owner key:', ''), (s, n) => { setStep(s); setSent(n); });
      setMsg(m);
    } catch (e) {
      setStep(null);
      setMsg(e instanceof Error ? e.message : String(e));
      void refreshUploads(); // the refusal is in the device's own audit trail; show it
    }
  };

  const rotate = async () => {
    const cur = window.prompt('Enter your CURRENT owner key:', '');
    if (!cur) return;
    const reason = window.prompt('Reason for rotating the owner key (kept in the journal):', '');
    if (!reason || reason.trim().length < 3) { setMsg('Cancelled: a reason is required.'); return; }
    const r = await post<{ ok: boolean; refused?: string; note?: string }>('/api/owner-key', { owner_key: cur, new_owner_key: newKey(), reason: reason.trim(), permanent: 'true' });
    if (r.ok) { setMsg(r.note ?? 'Rotated. Sign in with the new key.'); setTimeout(() => { location.href = '/login'; }, 2500); }
    else setMsg(`Refused by the device: ${r.refused}`);
  };

  const reset = async () => {
    const key = window.prompt('Factory reset erases every owner setting on this device. Enter your owner key:', '');
    if (!key) return;
    const reason = window.prompt('Reason for the factory reset (kept until the erase):', '');
    if (!reason || reason.trim().length < 3) { setMsg('Cancelled: a reason is required.'); return; }
    const r = await post<{ ok: boolean; refused?: string; note?: string }>('/api/factory-reset', { owner_key: key, confirm: 'ERASE', reason: reason.trim(), permanent: 'true' });
    setMsg(r.ok ? (r.note ?? 'Factory reset sealed. The device restarts.') : `Refused by the device: ${r.refused}`);
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
                  <thead><tr><th scope="col">Pack</th><th scope="col">Generation</th><th scope="col">Source</th><th scope="col">Max size</th></tr></thead>
                  <tbody>
                    <Show when={!sample()} fallback={<tr><td>{PACK_LABEL.ioc}</td><td>7</td><td>store</td><td>16 MB</td></tr>}>
                      <For each={uploadView()?.types ?? []} fallback={<tr><td colSpan={4} class="l0-muted">Not reported.</td></tr>}>{(t) => (
                        <tr><td>{PACK_LABEL[t.type] ?? t.type}</td><td class="l0-num" style={{ 'font-weight': 400 }}>{t.generation || '—'}</td><td>{t.source === 'store' ? 'uploaded' : 'from the boot image'}</td><td>{Math.round(t.cap / 1024)} KB</td></tr>
                      )}</For>
                    </Show>
                  </tbody>
                </table></div>
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

            <Show when={sec() === 'identity'}>
              <div class="pcard">
                <p class="l0-label">Owner key</p>
                <p class="l0-card-sub">The owner key signs you in and approves every durable change. Rotating it ends every session; the device keeps only a salted verifier, never the key.</p>
                <label class="l0-card-sub" style={{ display: 'flex', 'flex-direction': 'column', gap: '4px' }}>New owner key (16–128 characters)
                  <input type="password" style={field} value={newKey()} onInput={(e) => setNewKey(e.currentTarget.value)} autocomplete="new-password" /></label>
                <div class="l0-card-foot">
                  <button class="hp-btn hp-btn--primary" disabled={sample() || newKey().trim().length < 16 || newKey().length > 128} onClick={() => void rotate()}>Rotate owner key</button>
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

            <Show when={sec() === 'reset'}>
              <div class="pcard" style={{ 'border-color': 'rgba(255,107,107,.45)' }}>
                <p class="l0-label" style={{ color: 'var(--hp-red)' }}>Factory reset</p>
                <p class="l0-card-sub">Erases every owner setting (owner rules, owner key, alert hook, uploaded packs) and restarts the device as shipped. Sign in afterwards with the key on its label. Your signed boot files are not touched.</p>
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
