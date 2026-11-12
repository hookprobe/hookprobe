/**
 * ProtectApp — Protect (`/protect/firewall`): response and posture (wireframe "Protect";
 * requirements doc §6). Built on what heqk actually enforces:
 *
 *   header        the device's own enforcement policy (ADR 0023: observe by default)
 *   Rules         ADR 0055 owner rules (effective / shadowed by a pinned signed line); add a domain
 *                 block / allow or remove a rule through the plan-as-diff flow (dry run → owner key
 *                 → read-back verify)
 *   Enforcement   who the device acts against right now (/api/enforcement, all self-reverting) and
 *                 the time-bounded actions in force (/api/actions) with End now
 *   Policies      the signed IOC pack and DEVICES.TXT, recent refused writes, inline segmentation
 *                 (gated on `openvswitch`)
 *
 * Per-segment fail-open / fail-closed controls are not shown: the device does not report its fail
 * mode, and a control that cannot be read back must not be offered.
 */
import { type Component, For, Show, createSignal, onCleanup, onMount } from 'solid-js';
import { substrate } from '../store/mock';
import { healthChecked } from '../store/health';
import { actionsView, refreshActions, revokeAction } from '../store/actions';
import { ownerRules, refreshOwnerRules, KIND_LABEL, type OwnerChange, type OwnerKind } from '../store/ownerRules';
import { enforcement, intel, refreshProtect } from '../store/protectLive';
import AppShell from './AppShell';
import Drawer from './Drawer';
import Gate from './Gate';
import OwnerChangePlan from './OwnerChangePlan';
import PlanDiff from './PlanDiff';

type Tab = 'rules' | 'enforcement' | 'policies';
const STATE: Record<string, string> = { watching: 'Watching', rate_limited: 'Rate-limited', quarantined: 'Quarantined' };

const SAMPLE_RULES = [
  { seq: 1, kind: 'shield_block', target: 'bad-site.example', value: 'block', effective: true, shadowed_by: null },
  { seq: 2, kind: 'device_policy', target: '02:00:00:00:00:42', value: 'quarantine', effective: true, shadowed_by: null },
  { seq: 3, kind: 'shield_allow', target: 'bank.example', value: 'allow', effective: true, shadowed_by: null },
];

const ProtectApp: Component = () => {
  const [tab, setTab] = createSignal<Tab>('rules');
  const [change, setChange] = createSignal<OwnerChange | null>(null);
  const [adding, setAdding] = createSignal(false);
  const [newKind, setNewKind] = createSignal<OwnerKind>('shield_block');
  const [newDomain, setNewDomain] = createSignal('');
  const [msg, setMsg] = createSignal('');

  onMount(() => {
    const tick = () => { void refreshProtect(); void refreshActions(); void refreshOwnerRules(); };
    tick();
    const t = setInterval(tick, 10_000);
    onCleanup(() => clearInterval(t));
  });

  const sample = () => healthChecked() && !substrate();
  const rules = () => (sample() ? SAMPLE_RULES : ownerRules()?.rules ?? []);
  const sources = () => (sample()
    ? [{ ip: '203.0.113.9', state: 'rate_limited' as const, reason: 'port scan', distinct_ports: 41, established: 0, expires_in_s: 540 }]
    : enforcement()?.sources ?? []);
  const active = () => (sample()
    ? [{ id: 1, kind: 'isolate', target: 'Kitchen camera', expires_in_s: 2400 }]
    : actionsView()?.active ?? []);
  const policy = () => (sample()
    ? 'observe by default; only a confirmed scan, a malformed frame, an L1/L2 flood or resource exhaustion is acted on, and every action self-reverts (ADR 0023)'
    : enforcement()?.policy ?? '');
  const validDomain = () => /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(newDomain().trim());

  const closeDrawer = () => { setChange(null); setAdding(false); setNewDomain(''); void refreshOwnerRules(); };

  return (
    <AppShell path="/protect/firewall">
      <main class="pro-main" aria-label="Protect">
        <div class="pro-head">
          <div>
            <h1 class="pro-title">Protect</h1>
            <p class="pro-sub">Response and posture{substrate() ? ' · live from this device' : ''}</p>
          </div>
          <div class="l0-head-actions">
            <button class="hp-btn hp-btn--primary" onClick={() => setAdding(true)}>+ Rule</button>
          </div>
        </div>

        <Show when={policy()}>
          <div class="pcard" style={{ 'flex-direction': 'row', 'align-items': 'center', gap: '12px', 'flex-wrap': 'wrap' }}>
            <span class="l0-label">Enforcement policy</span>
            <span class="l0-card-sub" style={{ flex: '1 1 320px' }}>{policy().charAt(0).toUpperCase() + policy().slice(1)}. A legitimate connection always passes.</span>
          </div>
        </Show>

        <div class="tabs" role="tablist" aria-label="Protect views">
          <For each={[['rules', 'Rules'], ['enforcement', 'Enforcement & isolation'], ['policies', 'Policies']] as [Tab, string][]}>{([t, label]) => (
            <button class="tab" role="tab" aria-selected={tab() === t} onClick={() => setTab(t)}>{label}</button>
          )}</For>
        </div>
        <Show when={msg()}><p class="pro-sub" role="status">{msg()}</p></Show>

        <Show when={tab() === 'rules'}>
          <div class="l0-table-wrap">
            <table class="l0-table obs-table">
              <thead><tr><th scope="col">#</th><th scope="col">Rule</th><th scope="col">Target</th><th scope="col">Result</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead>
              <tbody>
                <Show when={rules().length > 0} fallback={<tr><td colSpan={5} class="l0-muted">No owner rules. The signed baseline applies as shipped.</td></tr>}>
                  <For each={rules()}>{(r) => (
                    <tr>
                      <td class="l0-num" style={{ 'font-weight': 400 }}>{r.seq}</td>
                      <td>{KIND_LABEL[r.kind] ?? r.kind}{r.kind === 'device_policy' || r.kind === 'shield_profile' ? ` → ${r.value}` : ''}</td>
                      <td style={{ 'overflow-wrap': 'anywhere' }}>{r.target}</td>
                      <td>{r.effective ? <span class="go-state--up">Effective</span> : <span class="go-state--down">Shadowed by {r.shadowed_by}</span>}</td>
                      <td><button class="hp-btn" disabled={sample()} onClick={() => setChange({ op: 'remove', kind: r.kind as OwnerKind, target: r.target })}>Remove</button></td>
                    </tr>
                  )}</For>
                </Show>
              </tbody>
            </table>
          </div>
          <p class="pcard-note">
            Owner rules sit on top of the signed baseline and are kept in the device's sealed journal
            {sample() ? '.' : ownerRules() ? (ownerRules()!.persistent ? ` (${ownerRules()!.journal.records} records).` : ' — this device has no persistent journal, so they last until restart.') : '.'}
            {' '}A rule pinned by a signed DEVICES.TXT line is recorded but does not take effect.
          </p>
        </Show>

        <Show when={tab() === 'enforcement'}>
          <div class="bento">
            <section class="pcard span-6" aria-label="Acting against now">
              <p class="l0-label">Acting against now · {sources().length}</p>
              <Show when={sources().length > 0} fallback={<p class="pcard-note">Nobody. The device is observing.</p>}>
                <For each={sources()}>{(s) => (
                  <span class="prow"><span>{s.ip} · {s.reason} ({s.distinct_ports} ports)</span><span>{STATE[s.state] ?? s.state} · {Math.ceil(s.expires_in_s / 60)} min</span></span>
                )}</For>
              </Show>
              <p class="pcard-note">Every entry reverts on its own; nothing here needs to be undone by hand.</p>
            </section>
            <section class="pcard span-6" aria-label="Actions in force">
              <p class="l0-label">Isolation and other actions in force · {active().length}</p>
              <Show when={active().length > 0} fallback={<p class="pcard-note">No temporary actions in force.</p>}>
                <For each={active()}>{(a) => (
                  <span class="prow" style={{ 'align-items': 'center' }}>
                    <span>{a.kind.replace('_', ' ')} · {a.target}</span>
                    <span style={{ display: 'flex', gap: '8px', 'align-items': 'center' }}>
                      {a.expires_in_s ? `${Math.ceil(a.expires_in_s / 60)} min left` : 'in force'}
                      <button class="hp-btn" style={{ 'min-height': '32px' }} disabled={sample()}
                        onClick={async () => { const r = await revokeAction(a.id); setMsg(r.ok ? `Ended ${a.kind.replace('_', ' ')} on ${a.target}.` : `Refused: ${r.refused}`); }}>End now</button>
                    </span>
                  </span>
                )}</For>
              </Show>
            </section>
          </div>
        </Show>

        <Show when={tab() === 'policies'}>
          <div class="bento">
            <section class="pcard span-6" aria-label="Threat intelligence pack">
              <p class="l0-label">Threat-intel pack</p>
              <Show when={!sample()} fallback={<p class="l0-card-sub">IOC.TXT · signed · generation 7 · 12,400 addresses · 3,210 domains · detect-only</p>}>
                <Show when={intel()} fallback={<p class="pcard-note">Not reported.</p>}>
                  <p class="l0-card-sub">{intel()!.ioc.file === 'loaded' ? `${intel()!.ioc.signed ? 'Signed' : 'Unsigned'} · generation ${intel()!.ioc.generation} · ${intel()!.ioc.ipv4_prefixes.toLocaleString()} address ranges · ${intel()!.ioc.domains.toLocaleString()} domains · ${intel()!.ioc.mode}` : `No pack ${intel()!.ioc.file === 'refused' ? '(refused: bad signature)' : 'loaded'}`}</p>
                </Show>
              </Show>
            </section>
            <section class="pcard span-6" aria-label="Device policy file">
              <p class="l0-label">Device policy (DEVICES.TXT)</p>
              <Show when={!sample()} fallback={<p class="l0-card-sub">Signed · generation 3 · 14 devices · 1 quarantined</p>}>
                <Show when={intel()} fallback={<p class="pcard-note">Not reported.</p>}>
                  <p class="l0-card-sub">{intel()!.devices.file === 'loaded' ? `${intel()!.devices.signed ? 'Signed' : 'Unsigned'} · generation ${intel()!.devices.generation} · ${intel()!.devices.entries} devices · internet-only ${intel()!.devices.denied.internet_only} · local-only ${intel()!.devices.denied.lan_only} · quarantined ${intel()!.devices.denied.quarantine}` : 'No device policy file loaded: every device has full access unless an owner rule says otherwise.'}</p>
                </Show>
              </Show>
            </section>
            <section class="pcard span-6" aria-label="Refused writes">
              <p class="l0-label">Recently refused changes</p>
              <Show when={(ownerRules()?.refused.length ?? 0) > 0} fallback={<p class="pcard-note">None.</p>}>
                <For each={ownerRules()!.refused.slice(0, 8)}>{(x) => <span class="prow"><span>{x.why}</span><span>session {x.session}</span></span>}</For>
              </Show>
            </section>
            <section class="pcard span-6" aria-label="Inline segmentation">
              <p class="l0-label">Inline segmentation (VLAN / OVS)</p>
              <p class="l0-card-sub">Zones are enforced in the device itself. Switch-level segmentation needs Open vSwitch.</p>
              <Gate cap="openvswitch"><button class="hp-btn">Configure segmentation</button></Gate>
            </section>
          </div>
        </Show>
      </main>

      <Drawer open={!!change() || adding()} title={adding() ? 'New rule' : change()?.op === 'remove' ? 'Remove rule' : 'Change'} onClose={closeDrawer}>
        <Show when={adding() && !change()}>
          <div class="l0-chips" role="group" aria-label="Rule type">
            <For each={['shield_block', 'shield_allow'] as OwnerKind[]}>{(k) => (
              <button class={`l0-chip${newKind() === k ? ' is-on' : ''}`} aria-pressed={newKind() === k} onClick={() => setNewKind(k)}>{KIND_LABEL[k]}</button>
            )}</For>
          </div>
          <label class="l0-card-sub" style={{ display: 'flex', 'flex-direction': 'column', gap: '4px' }}>
            Domain
            <input value={newDomain()} onInput={(e) => setNewDomain(e.currentTarget.value)} placeholder="example.com"
              style={{ font: 'inherit', 'font-size': '16px', 'min-height': '44px', padding: '0 12px', background: 'var(--hp-surface)', color: 'var(--hp-text-primary)', border: '1px solid var(--hp-border)', 'border-radius': 'var(--hp-radius)' }} />
          </label>
          <Show when={sample()} fallback={
            <button class="hp-btn hp-btn--primary" disabled={!validDomain()}
              onClick={() => setChange({ op: 'set', kind: newKind(), target: newDomain().trim().toLowerCase(), value: newKind() === 'shield_block' ? 'block' : 'allow' })}>Preview the change</button>
          }>
            <PlanDiff lines={[{ kind: 'added', text: `${KIND_LABEL[newKind()]} · ${newDomain() || 'example.com'}` }]}
              onApprove={() => Promise.reject(new Error('Preview: no device is connected to apply this.'))} />
          </Show>
        </Show>
        <Show keyed when={change()}>{(c) => (
          <OwnerChangePlan change={c} title={c.op === 'remove' ? 'Remove this owner rule' : 'Proposed rule'} onDone={closeDrawer} />
        )}</Show>
        <p class="pcard-note">Rules for malicious domains are refused by the device: a confirmed threat-intel or malware entry always wins over an allow.</p>
      </Drawer>
    </AppShell>
  );
};

export default ProtectApp;
