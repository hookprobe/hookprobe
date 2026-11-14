/**
 * AutomateApp — Automate (`/automate/playbooks`): playbooks as pipelines, autonomy per stage
 * (wireframe "Automate"; requirements doc §7).
 *
 * On a device: the built-in response pipeline heqk actually runs (ADR 0023), stage by stage with live
 * counts — Detect (detections) · Validate (incidents) · Contain (who it acts against now + actions
 * in force, all self-reverting) · Notify (the alert webhook) · Recover (actions expire on their own)
 * · Verify (QSecBit). Autonomy is shown as it is: containment is automatic and self-reverting;
 * every durable change waits for the owner (owner key). The alert webhook is configurable here (a
 * durable owner write). Custom playbooks are greyed: the device does not run a playbook engine.
 * With no device answering, the wireframe's sample playbooks render under the Sample-data banner.
 */
import { type Component, For, Show, createMemo, createSignal, onCleanup, onMount } from 'solid-js';
import { substrate, qsecbit } from '../store/mock';
import { healthChecked } from '../store/health';
import { detections, startDetectLive } from '../store/detectLive';
import { incidents, startInvestigateLive } from '../store/investigateLive';
import { actionsView, refreshActions } from '../store/actions';
import { enforcement, refreshProtect } from '../store/protectLive';
import { alertHook, refreshAlertHook, saveAlertHook, SEVERITY, type AlertHookSettings } from '../store/alertHook';
import AppShell from './AppShell';
import Drawer from './Drawer';

interface Stage { name: string; state: 'active' | 'idle' | 'done' | 'waiting'; auto: boolean; count: string; why: string }

const SAMPLE_BOOKS = [
  { name: 'Credential stuffing', meta: 'Ran 3× this week · last 22:14' },
  { name: 'Compromised IoT device', meta: 'Ran 1× · last 13:05' },
  { name: 'New unknown device', meta: 'Ran 4× · last 10:40' },
];
/** One pipeline per sample playbook (they all showed the credential-stuffing one). Containment follows enforcement
 *  separation: block or isolate only on confirmed evidence, time-bounded, and approval for anything durable. */
const SAMPLE_STAGES: Stage[][] = [
  [
    { name: 'Detect', state: 'done', auto: true, count: '1', why: 'NAPSE rule "Admin brute force" fired: more than 5 failed logins per minute from one source.' },
    { name: 'Validate', state: 'done', auto: true, count: '2 feeds', why: 'HYDRA confirms the source IPs appear on 2 credential-stuffing feeds.' },
    { name: 'Contain', state: 'waiting', auto: false, count: '12 IPs', why: 'AEGIS proposes rate-limiting the admin page and blocking the 12 source IPs. Blocking needs your approval.' },
    { name: 'Notify', state: 'idle', auto: true, count: '—', why: 'Send a notification to the admin with the evidence.' },
    { name: 'Recover', state: 'idle', auto: true, count: '—', why: 'Lift the rate limit after 1 hour of quiet.' },
    { name: 'Verify', state: 'idle', auto: true, count: '—', why: 'Check no legitimate logins were blocked.' },
    { name: 'Close', state: 'idle', auto: true, count: '—', why: 'Write the incident summary and close.' },
  ],
  [
    { name: 'Detect', state: 'done', auto: true, count: '2', why: 'The kitchen camera resolved a known C2 domain and then scanned the LAN (INC-0142).' },
    { name: 'Validate', state: 'done', auto: true, count: '1 IOC', why: 'HYDRA matches the domain to the signed IOC pack: confirmed, not a guess.' },
    { name: 'Contain', state: 'done', auto: true, count: '1 device', why: 'Confirmed C2 contact: the camera was isolated for 1 hour (DHCP and DNS keep working); it ends by itself.' },
    { name: 'Notify', state: 'done', auto: true, count: '1', why: 'The owner was notified with the evidence and the story.' },
    { name: 'Recover', state: 'waiting', auto: false, count: '—', why: 'Release the camera after a firmware update, or keep it isolated: your choice.' },
    { name: 'Verify', state: 'idle', auto: true, count: '—', why: 'Watch the camera for 24 hours after release.' },
    { name: 'Close', state: 'idle', auto: true, count: '—', why: 'Write the incident summary and close.' },
  ],
  [
    { name: 'Detect', state: 'done', auto: true, count: '1', why: 'A new device joined without a known fingerprint ("Unknown phone").' },
    { name: 'Validate', state: 'done', auto: true, count: '—', why: 'No threat-intel match and no suspicious traffic: observed only.' },
    { name: 'Contain', state: 'waiting', auto: false, count: '1 device', why: 'AEGIS suggests the Guests zone (internet only). A zone move is durable, so it needs your approval.' },
    { name: 'Notify', state: 'idle', auto: true, count: '—', why: 'Tell the owner a new device joined.' },
    { name: 'Recover', state: 'idle', auto: true, count: '—', why: 'Nothing to undo unless you move it back.' },
    { name: 'Verify', state: 'idle', auto: true, count: '—', why: 'Confirm the device works on the Guests zone.' },
    { name: 'Close', state: 'idle', auto: true, count: '—', why: 'Close once the owner has decided.' },
  ],
];

const field = { font: 'inherit', 'font-size': '16px', 'min-height': '44px', padding: '0 12px', background: 'var(--hp-surface)', color: 'var(--hp-text-primary)', border: '1px solid var(--hp-border)', 'border-radius': 'var(--hp-radius)' } as const;

const AutomateApp: Component = () => {
  const [book, setBook] = createSignal(0);
  const [stage, setStage] = createSignal(0);
  const [hookOpen, setHookOpen] = createSignal(false);
  const [msg, setMsg] = createSignal('');
  const [form, setForm] = createSignal<AlertHookSettings>({ ip: '', port: 80, format: 'ntfy', path: '/hookprobe', secret: '', min_severity: 'high' });

  onMount(() => {
    startDetectLive(); startInvestigateLive();
    const tick = () => { void refreshActions(); void refreshProtect(); void refreshAlertHook(); };
    tick();
    const t = setInterval(tick, 15_000);
    onCleanup(() => clearInterval(t));
  });

  const sample = () => healthChecked() && !substrate();
  const openInc = () => incidents().filter((i) => i.status !== 'resolved' && i.status !== 'closed').length;
  const acting = () => (enforcement()?.count ?? 0) + (actionsView()?.active.length ?? 0);
  const hook = () => alertHook();

  const liveStages = createMemo<Stage[]>(() => [
    { name: 'Detect', state: detections().length ? 'done' : 'idle', auto: true, count: String(detections().length), why: 'Every frame is checked both ways against the signed rule set; each match is recorded as a detection.' },
    { name: 'Validate', state: incidents().length ? 'done' : 'idle', auto: true, count: `${incidents().length} incident${incidents().length === 1 ? '' : 's'}`, why: 'Detections are correlated per source into incidents with a deterministic explanation. No AI model decides.' },
    { name: 'Contain', state: acting() ? 'active' : 'idle', auto: true, count: `${acting()} in force`, why: 'Only a confirmed scan, a malformed frame, an L1/L2 flood or resource exhaustion is acted on, and every action reverts on its own. A legitimate connection always passes.' },
    { name: 'Notify', state: hook()?.configured ? (hook()!.sent ? 'done' : 'idle') : 'idle', auto: true, count: hook()?.configured ? `${hook()!.sent} sent` : 'off', why: hook()?.configured ? `Alerts at or above ${SEVERITY[hook()!.min_severity ?? 2]} go to ${hook()!.target} (${hook()!.format}), at most ${hook()!.max_per_hour} an hour.` : 'No alert destination is set. Add one to get alerts on your phone or in your own system.' },
    { name: 'Recover', state: (actionsView()?.active.length ?? 0) ? 'active' : 'idle', auto: true, count: 'automatic', why: 'Every protective action has a time limit and ends by itself; nothing needs undoing by hand.' },
    { name: 'Verify', state: 'done', auto: true, count: `QSecBit ${qsecbit()}`, why: 'The resilience score is recomputed continuously over the recent risk window.' },
    { name: 'Close', state: openInc() ? 'waiting' : 'done', auto: false, count: `${openInc()} open`, why: 'Incidents stay open until you acknowledge them in Investigate.' },
  ]);
  const stages = () => (sample() ? SAMPLE_STAGES[book()] ?? SAMPLE_STAGES[0] : liveStages());
  const sel = () => stages()[stage()] ?? stages()[0];
  const tone = (s: Stage['state']) => (s === 'done' ? 'var(--hp-green)' : s === 'active' ? 'var(--hp-cyan)' : s === 'waiting' ? 'var(--hp-amber)' : 'var(--hp-text-muted)');
  const validHook = () => /^\d{1,3}(\.\d{1,3}){3}$/.test(form().ip) && form().port > 0 && form().port < 65536 && form().secret.length >= 16;

  return (
    <AppShell path="/automate/playbooks">
      <main class="pro-main" aria-label="Automate">
        <div class="pro-head">
          <div>
            <h1 class="pro-title">Automate</h1>
            <p class="pro-sub">Playbooks as pipelines. Autonomy is set per stage{substrate() ? ' · live from this device' : ''}</p>
          </div>
          <span class="gate gate--off" title="Custom playbooks need the automation engine">
            <span class="gate-body" ref={(el) => el.setAttribute('inert', '')} aria-hidden="true"><button class="hp-btn">+ New playbook</button></span>
            <span class="gate-reason" role="note">This device runs its built-in response only; custom playbooks need the automation engine.</span>
          </span>
        </div>
        <Show when={msg()}><p class="pro-sub" role="status">{msg()}</p></Show>

        <div class="auto-grid">
          <nav class="pcard obs-sources" aria-label="Playbooks">
            <p class="l0-label" style={{ padding: '0 8px 6px' }}>Playbooks</p>
            <Show when={sample()} fallback={
              <button class="shell-rail-item is-active" aria-pressed="true" style={{ 'flex-direction': 'column', 'align-items': 'flex-start', gap: '2px', 'min-height': '52px' }}>
                <span>Built-in response</span><span class="pcard-note">ADR 0023 · always on</span>
              </button>
            }>
              <For each={SAMPLE_BOOKS}>{(b, i) => (
                <button class={`shell-rail-item${book() === i() ? ' is-active' : ''}`} aria-pressed={book() === i()} onClick={() => { setBook(i()); setStage(0); }}
                  style={{ 'flex-direction': 'column', 'align-items': 'flex-start', gap: '2px', 'min-height': '52px' }}>
                  <span>{b.name}</span><span class="pcard-note">{b.meta}</span>
                </button>
              )}</For>
            </Show>
          </nav>

          <section class="pcard" aria-label="Pipeline" style={{ 'min-width': 0 }}>
            <h2 style={{ margin: 0, 'font-size': '18px' }}>{sample() ? SAMPLE_BOOKS[book()].name : 'Built-in response'}</h2>
            <div role="list" aria-label="Stages" style={{ display: 'grid', 'grid-template-columns': 'repeat(auto-fill, minmax(120px, 1fr))', gap: '8px' }}>
              <For each={stages()}>{(s, i) => (
                <button class="pcard" role="listitem" aria-pressed={stage() === i()} onClick={() => setStage(i())}
                  style={{ padding: '12px', gap: '4px', 'text-align': 'left', 'border-color': stage() === i() ? 'var(--hp-cyan)' : undefined }}>
                  <span style={{ 'font-size': '11px', color: tone(s.state) }}>● {s.state}</span>
                  <span style={{ 'font-weight': 600 }}>{s.name}</span>
                  <span class="pcard-note">{s.count}</span>
                  <span class="inc-status" style={{ 'align-self': 'flex-start', 'border-style': s.auto ? 'solid' : 'dashed' }}>{s.auto ? 'auto' : 'needs you'}</span>
                </button>
              )}</For>
            </div>
            <div style={{ display: 'flex', 'flex-direction': 'column', gap: '6px' }}>
              <p class="l0-label">Stage · {sel().name}</p>
              <p style={{ margin: 0 }}>{sel().why}</p>
              <span class="gate gate--off">
                <span class="gate-body" ref={(el) => el.setAttribute('inert', '')} aria-hidden="true"><button class="hp-btn">{sel().auto ? 'Runs automatically · switch to approval' : 'Needs approval · switch to automatic'}</button></span>
                <span class="gate-reason" role="note">{sample() ? 'Preview: on a device with the automation engine this sets the stage’s autonomy.' : 'Autonomy of the built-in response is fixed by policy (ADR 0023).'}</span>
              </span>
            </div>
          </section>

          <aside style={{ display: 'flex', 'flex-direction': 'column', gap: '16px' }}>
            <section class="pcard" aria-label="Approval queue">
              <p class="l0-label">Approval queue · {sample() ? 1 : 0}</p>
              <Show when={sample()} fallback={<p class="pcard-note">Nothing waiting. Durable changes are approved where you make them, with your device password or signing key.</p>}>
                <span>Block 12 credential-stuffing IPs</span>
                <span class="pcard-note">Requested by: Credential stuffing · Contain · on 2 threat feeds · expires in 24 h</span>
                <div class="plan-diff-lines"><div class="plan-diff-line plan-diff-line--added"><span class="plan-diff-mark">+</span>block 12 source IPs on the admin page (24 h)</div></div>
                <span class="gate gate--off">
                  <span class="gate-body" ref={(el) => el.setAttribute('inert', '')} aria-hidden="true"><span class="l0-card-foot"><button class="hp-btn hp-btn--primary">Approve</button><button class="hp-btn">Reject</button></span></span>
                  <span class="gate-reason" role="note">Preview: on a device with the automation engine you approve or reject here.</span>
                </span>
              </Show>
            </section>
            <section class="pcard" aria-label="Notifications">
              <p class="l0-label">Notifications</p>
              <Show when={!sample()} fallback={<p class="l0-card-sub">ntfy · 10.0.0.20:8080 · high and above · 14 sent</p>}>
                <Show when={hook()} fallback={<p class="pcard-note">Checking…</p>}>
                  <p class="l0-card-sub">{hook()!.configured ? `${hook()!.format} · ${hook()!.target}${hook()!.path ?? ''} · ${SEVERITY[hook()!.min_severity ?? 2]} and above` : 'No alert destination.'}</p>
                  <p class="pcard-note">{hook()!.sent} sent · {hook()!.failed} failed · {hook()!.held_back} held back (limit {hook()!.max_per_hour}/hour)</p>
                </Show>
              </Show>
              <div class="l0-card-foot">
                <button class="hp-btn" disabled={sample()} onClick={() => setHookOpen(true)}>{hook()?.configured ? 'Change' : 'Set up alerts'}</button>
                <Show when={hook()?.configured}><button class="hp-btn" onClick={async () => setMsg(await saveAlertHook(null))}>Remove</button></Show>
              </div>
            </section>
          </aside>
        </div>
      </main>

      <Drawer open={hookOpen()} title="Alert destination" onClose={() => setHookOpen(false)}
        footer={<button class="hp-btn hp-btn--primary" disabled={!validHook()} onClick={async () => { setMsg(await saveAlertHook(form())); setHookOpen(false); }}>Save (device password)</button>}>
        <p class="l0-card-sub">The device sends an alert for each new incident at or above the chosen severity, signed with your secret.</p>
        <div class="l0-chips" role="group" aria-label="Format">
          <For each={['ntfy', 'gotify', 'json'] as const}>{(f) => (
            <button class={`l0-chip${form().format === f ? ' is-on' : ''}`} aria-pressed={form().format === f} onClick={() => setForm({ ...form(), format: f })}>{f}</button>
          )}</For>
        </div>
        <label class="l0-card-sub" style={{ display: 'flex', 'flex-direction': 'column', gap: '4px' }}>Server address (IPv4)
          <input style={field} value={form().ip} onInput={(e) => setForm({ ...form(), ip: e.currentTarget.value.trim() })} placeholder="10.0.0.20" /></label>
        <label class="l0-card-sub" style={{ display: 'flex', 'flex-direction': 'column', gap: '4px' }}>Port
          <input style={field} type="number" value={form().port} onInput={(e) => setForm({ ...form(), port: Number(e.currentTarget.value) })} /></label>
        <label class="l0-card-sub" style={{ display: 'flex', 'flex-direction': 'column', gap: '4px' }}>Path
          <input style={field} value={form().path} onInput={(e) => setForm({ ...form(), path: e.currentTarget.value })} /></label>
        <label class="l0-card-sub" style={{ display: 'flex', 'flex-direction': 'column', gap: '4px' }}>Secret (at least 16 characters)
          <input style={field} type="password" value={form().secret} onInput={(e) => setForm({ ...form(), secret: e.currentTarget.value })} autocomplete="new-password" /></label>
        <div class="l0-chips" role="group" aria-label="Minimum severity">
          <For each={['critical', 'high', 'medium', 'low'] as const}>{(s) => (
            <button class={`l0-chip${form().min_severity === s ? ' is-on' : ''}`} aria-pressed={form().min_severity === s} onClick={() => setForm({ ...form(), min_severity: s })}>{s}</button>
          )}</For>
        </div>
        <p class="pcard-note">Saving is a permanent change: the device asks for a reason and your device password, then reports the destination back.</p>
      </Drawer>
    </AppShell>
  );
};

export default AutomateApp;
