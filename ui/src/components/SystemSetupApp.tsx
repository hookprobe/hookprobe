/**
 * SystemSetupApp — the first-run Setup wizard (System Setup lens).
 *
 * Realizes ADR 0010 (zero-touch provisioning) inside the Mission Control shell —
 * the setup portal is a Provisioning *lens*, not a separate app (one-system).
 * Designed to ~/os.hookprobe.local: a 7-step rail · the active step form · a live
 * setup summary · a device status strip. "Launch" is a plan-as-diff the reconciler
 * applies + verifies; the handoff polls WAN-readiness then redirects (mock here).
 *
 * Spec: docs/MissionControl.md §12 (Administration → Provisioning, "First run").
 */

import { type Component, For, Show, Switch, Match, createMemo } from 'solid-js';
import LeftRail from './LeftRail';
import {
  STEPS, DEVICE, TIMEZONES, WAN_OPTIONS, pwStrength, planDiff, stepStatus,
  step, setStep, model, patch, deploying, setDeploying, wanReady, setWanReady,
} from '../store/setupMock';

const last = () => STEPS.length - 1;

// ── small field helpers ───────────────────────────────────────────────────────
const Field: Component<{ label: string; hint?: string; children: any }> = (p) => (
  <label class="set-field">
    <span class="set-field-label">{p.label}{p.hint && <span class="set-field-hint" title={p.hint}> ⓘ</span>}</span>
    {p.children}
  </label>
);

const Toggle: Component<{ label: string; sub?: string; checked: boolean; onChange: (v: boolean) => void }> = (p) => (
  <button type="button" class={`set-toggle${p.checked ? ' set-toggle--on' : ''}`} onClick={() => p.onChange(!p.checked)}>
    <span class="set-toggle-knob" />
    <span class="set-toggle-text"><b>{p.label}</b>{p.sub && <em>{p.sub}</em>}</span>
  </button>
);

const SystemSetupApp: Component = () => {
  const m = model;
  const pw = createMemo(() => pwStrength(m().adminPassword));
  const cur = () => STEPS[step()];

  const next = () => { if (step() < last()) setStep(step() + 1); };
  const back = () => { if (step() > 0) setStep(step() - 1); };

  // Launch → the booster-drop handoff: commit intent → reconcile → poll WAN-ready → redirect.
  const launch = () => {
    setDeploying(true); setWanReady(false);
    // mock the ~10s AP-before-WAN window we measured on hardware, then "go live".
    setTimeout(() => setWanReady(true), 2600);
  };

  return (
    <div class="dash-layout">
      <LeftRail active="/setup" mode="standalone" onOpenCopilot={() => {}} />

      <main class="dash-main set-main">
        {/* Header band */}
        <header class="set-header">
          <div>
            <h1 class="set-h1">Welcome to HookProbe OS</h1>
            <p class="set-sub">Let's get your HookProbe appliance up and running.</p>
          </div>
          <div class="set-header-actions">
            <span class="set-mode"><span class="set-mode-dot" /> Setup Mode</span>
            <a class="set-exit" href="/mission">Exit Setup ⤴</a>
          </div>
        </header>

        {/* 3-column body: step rail · active form · summary */}
        <div class="set-body">
          {/* ── step rail ── */}
          <nav class="set-rail" aria-label="Setup steps">
            <For each={STEPS}>{(s, i) => {
              const st = () => stepStatus(i());
              return (
                <button class={`set-step set-step--${st()}`} onClick={() => setStep(i())}>
                  <span class="set-step-num">{st() === 'done' ? '✓' : s.num}</span>
                  <span class="set-step-text">
                    <b>{s.title}{s.optional && <em class="set-opt"> (Optional)</em>}</b>
                    <em>{s.subtitle}</em>
                  </span>
                </button>
              );
            }}</For>
            <a class="set-help" href="/knowledge/docs">
              <span>❔</span><span><b>Need Help?</b><em>Read the quick start guide ↗</em></span>
            </a>
          </nav>

          {/* ── active step form ── */}
          <section class="set-panel">
            <Show when={!deploying()} fallback={<DeployView />}>
              <div class="set-panel-head">
                <h2 class="set-panel-title">{cur().num}. {cur().title}</h2>
                <p class="set-panel-desc">{cur().subtitle}.</p>
              </div>

              <div class="set-form">
                <Switch>
                  {/* 1 — System Identity */}
                  <Match when={cur().id === 'identity'}>
                    <Field label="Device Name" hint="A friendly name for this appliance">
                      <input class="set-input" value={m().deviceName} onInput={e => patch({ deviceName: e.currentTarget.value })} />
                    </Field>
                    <Field label="Timezone">
                      <select class="set-input" value={m().timezone} onChange={e => patch({ timezone: e.currentTarget.value })}>
                        <For each={TIMEZONES}>{tz => <option>{tz}</option>}</For>
                      </select>
                    </Field>
                    <Field label="Admin Password" hint="Holds root + the disk key (ADR 0008 RBAC)">
                      <input class="set-input" type="password" value={m().adminPassword} onInput={e => patch({ adminPassword: e.currentTarget.value })} placeholder="••••••••••••" />
                    </Field>
                    <Show when={m().adminPassword}>
                      <div class="set-pw">
                        <div class="set-pw-bar">
                          <For each={[0, 1, 2]}>{n => <span class={`set-pw-seg${pw().score > n ? ' set-pw-seg--on' : ''}`} />}</For>
                        </div>
                        <span class={`set-pw-label set-pw-label--${pw().score}`}>{pw().label}</span>
                      </div>
                    </Show>
                    <Field label="Confirm Password">
                      <input class="set-input" type="password" value={m().confirmPassword} onInput={e => patch({ confirmPassword: e.currentTarget.value })} placeholder="••••••••••••" />
                    </Field>
                    <Field label="Device Location (Optional)">
                      <input class="set-input" value={m().location} onInput={e => patch({ location: e.currentTarget.value })} placeholder="e.g. Branch Office, Data Center, Home Lab" />
                    </Field>
                  </Match>

                  {/* 2 — Wireless */}
                  <Match when={cur().id === 'wireless'}>
                    <Field label="Wi-Fi Network Name (SSID)">
                      <input class="set-input" value={m().ssid} onInput={e => patch({ ssid: e.currentTarget.value })} />
                    </Field>
                    <Field label="Band">
                      <div class="set-seg">
                        <For each={['auto', '2.4', '5', '6'] as const}>{b =>
                          <button class={`set-seg-btn${m().wifiBand === b ? ' set-seg-btn--on' : ''}`} onClick={() => patch({ wifiBand: b })}>{b === 'auto' ? 'Auto' : b + ' GHz'}</button>
                        }</For>
                      </div>
                    </Field>
                    <Field label="Wi-Fi Password" hint="WPA2/WPA3, 8–63 characters">
                      <input class="set-input" type="password" value={m().wifiPassword} onInput={e => patch({ wifiPassword: e.currentTarget.value })} placeholder="••••••••••••" />
                    </Field>
                    <Toggle label="Seamless roaming (802.11r/k/v)" sub="Fast BSS transition — no session drops between bands/nodes" checked={m().wifiRoaming} onChange={v => patch({ wifiRoaming: v })} />
                  </Match>

                  {/* 3 — Network / LAN */}
                  <Match when={cur().id === 'network'}>
                    <Field label="LAN Subnet (CIDR)" hint="Gateway is the first host (.1)">
                      <input class="set-input" value={m().lanSubnet} onInput={e => patch({ lanSubnet: e.currentTarget.value })} />
                    </Field>
                    <Toggle label="DHCP server" sub="Hand out addresses to LAN clients" checked={m().dhcp} onChange={v => patch({ dhcp: v })} />
                    <Toggle label="Dual-stack IPv6" sub="ULA prefix + RA + NAT66 — clients get v6 on any upstream (ADR 0010)" checked={m().dualStackV6} onChange={v => patch({ dualStackV6: v })} />
                  </Match>

                  {/* 4 — WAN (all uplink types; Wi-Fi/modem capability-gated from the manifest) */}
                  <Match when={cur().id === 'wan'}>
                    <Field label="Connection Type">
                      <div class="set-seg">
                        <For each={WAN_OPTIONS}>{o => {
                          const ok = () => !o.needs || o.needs();
                          return (
                            <button
                              class={`set-seg-btn${m().wanMode === o.id ? ' set-seg-btn--on' : ''}${ok() ? '' : ' set-seg-btn--locked'}`}
                              disabled={!ok()} title={ok() ? undefined : o.reason}
                              onClick={() => ok() && patch({ wanMode: o.id })}
                            >{o.label}{!ok() && <span class="set-seg-lock"> 🔒</span>}</button>
                          );
                        }}</For>
                      </div>
                    </Field>
                    {/* explain any greyed-out option (capability gating, never a dead button) */}
                    <Show when={WAN_OPTIONS.some(o => o.needs && !o.needs())}>
                      <p class="set-cap-note">
                        <For each={WAN_OPTIONS.filter(o => o.needs && !o.needs())}>{o =>
                          <span>🔒 <b>{o.label}</b> — {o.reason}. </span>
                        }</For>
                      </p>
                    </Show>

                    <Show when={m().wanMode !== 'wifi'}>
                      <Field label="WAN Interface">
                        <input class="set-input" value={m().wanIface} onInput={e => patch({ wanIface: e.currentTarget.value })} />
                      </Field>
                    </Show>

                    {/* static */}
                    <Show when={m().wanMode === 'static'}>
                      <Field label="IP Address / CIDR"><input class="set-input" value={m().staticIp} onInput={e => patch({ staticIp: e.currentTarget.value })} placeholder="203.0.113.2/24" /></Field>
                      <Field label="Gateway"><input class="set-input" value={m().staticGw} onInput={e => patch({ staticGw: e.currentTarget.value })} placeholder="203.0.113.1" /></Field>
                      <Field label="DNS"><input class="set-input" value={m().staticDns} onInput={e => patch({ staticDns: e.currentTarget.value })} /></Field>
                    </Show>
                    {/* modem (LTE/5G) */}
                    <Show when={m().wanMode === 'modem'}>
                      <Field label="APN" hint="Leave blank to auto-detect from the SIM">
                        <input class="set-input" value={m().modemApn} onInput={e => patch({ modemApn: e.currentTarget.value })} placeholder="internet (auto-detected if blank)" />
                      </Field>
                      <p class="set-note">A USB LTE/5G modem is detected via ModemManager; failover slot plumbed for SASE wwan uplink.</p>
                    </Show>
                    {/* wifi station uplink */}
                    <Show when={m().wanMode === 'wifi'}>
                      <Field label="Upstream Wi-Fi SSID"><input class="set-input" value={m().wanWifiSsid} onInput={e => patch({ wanWifiSsid: e.currentTarget.value })} placeholder="Cafe / hotel / phone hotspot" /></Field>
                      <Field label="Upstream Wi-Fi Password"><input class="set-input" type="password" value={m().wanWifiPass} onInput={e => patch({ wanWifiPass: e.currentTarget.value })} placeholder="••••••••" /></Field>
                      <p class="set-note">Uses your <b>second radio</b> as a station — the onboard radio keeps serving the <b>HookProbe</b> AP.</p>
                    </Show>

                    <Toggle label="Multi-WAN failover" sub="Policy-based routing across uplinks (health-gated)" checked={m().multiWanFailover} onChange={v => patch({ multiWanFailover: v })} />
                    <Show when={m().wanMode === 'pppoe'}><p class="set-note">PPPoE credentials on the next step.</p></Show>
                  </Match>

                  {/* 5 — PPPoE */}
                  <Match when={cur().id === 'pppoe'}>
                    <Show when={m().wanMode === 'pppoe'} fallback={<p class="set-note">Not needed — your WAN is <b>{m().wanMode.toUpperCase()}</b>. Skip to the next step.</p>}>
                      <Field label="PPPoE Username"><input class="set-input" value={m().pppoeUser} onInput={e => patch({ pppoeUser: e.currentTarget.value })} placeholder="user@isp" /></Field>
                      <Field label="PPPoE Password"><input class="set-input" type="password" value={m().pppoePass} onInput={e => patch({ pppoePass: e.currentTarget.value })} placeholder="••••••••" /></Field>
                    </Show>
                  </Match>

                  {/* 6 — Security & Encryption (E4) */}
                  <Match when={cur().id === 'security'}>
                    <p class="set-note">Your data volume is <b>always encrypted</b> (dm-crypt). Choose how the key is protected.</p>
                    <div class="set-choice">
                      <button class={`set-choice-card${m().anchor === 'factory' ? ' set-choice-card--on' : ''}`} onClick={() => patch({ anchor: 'factory' })}>
                        <b>Factory key</b><em>Zero-touch. Protects against a stolen/cloned SD. (default)</em>
                      </button>
                      <button class={`set-choice-card${m().anchor === 'passphrase' ? ' set-choice-card--on' : ''}`} onClick={() => patch({ anchor: 'passphrase' })}>
                        <b>Customer passphrase</b><em>Strongest. Required to unlock — protects a stolen appliance too.</em>
                      </button>
                    </div>
                    <Show when={m().anchor === 'passphrase'}>
                      <Field label="Encryption Passphrase" hint="Re-wraps the master key (Argon2)">
                        <input class="set-input" type="password" value={m().passphrase} onInput={e => patch({ passphrase: e.currentTarget.value })} placeholder="••••••••••••" />
                      </Field>
                    </Show>
                    <Toggle label="Recovery key" sub="Never brick — a recovery slot always keeps the device unlockable" checked={m().recoveryKey} onChange={v => patch({ recoveryKey: v })} />
                    <Toggle label="Signed updates only" sub="Refuse unsigned OS images (cosign gate)" checked={m().signedUpdatesOnly} onChange={v => patch({ signedUpdatesOnly: v })} />
                  </Match>

                  {/* 7 — Review & Apply (plan-as-diff) */}
                  <Match when={cur().id === 'review'}>
                    <p class="set-note">This is the <b>plan</b> the reconciler will apply and verify. Nothing changes until you launch.</p>
                    <div class="set-plan">
                      <For each={planDiff()}>{d =>
                        <div class="set-plan-row">
                          <span class={`set-plan-op set-plan-op--${d.tone}`}>{d.tone === 'add' ? '+' : '~'}</span>
                          <span class="set-plan-key">{d.label}</span>
                          <span class="set-plan-val">{d.value}</span>
                        </div>
                      }</For>
                    </div>
                  </Match>
                </Switch>
              </div>

              {/* footer nav */}
              <div class="set-actions">
                <Show when={step() > 0}><button class="set-btn set-btn--ghost" onClick={back}>← Back</button></Show>
                <span class="set-spacer" />
                <Show when={step() < last()} fallback={<button class="set-btn set-btn--launch" onClick={launch}>🚀 Launch SASE</button>}>
                  <button class="set-btn set-btn--primary" onClick={next}>Next →</button>
                </Show>
              </div>
            </Show>
          </section>

          {/* ── summary ── */}
          <aside class="set-summary">
            <div class="set-summary-head"><span>⚑</span> Setup Summary</div>
            <For each={STEPS.slice(0, 6)}>{(s, i) => {
              const st = () => stepStatus(i());
              return (
                <div class="set-sum-row" onClick={() => setStep(i())}>
                  <span class="set-sum-icon">{s.icon}</span>
                  <span class="set-sum-text"><b>{s.title}</b><em>{st() === 'done' ? valueFor(s.id) : 'Not configured'}</em></span>
                  <span class={`set-sum-dot set-sum-dot--${st()}`}>{st() === 'done' ? '✓' : ''}</span>
                </div>
              );
            }}</For>
            <div class="set-summary-note">
              <b>You are in Setup Mode</b>
              <span>A one-time wizard to configure your appliance. You can change any of this later from Network / Gateway → Quick Setup.</span>
            </div>
          </aside>
        </div>

        {/* device status strip */}
        <footer class="set-strip">
          <StripItem icon="🌐" label="Hostname" value={DEVICE.hostname} />
          <StripItem icon="▦" label="LAN IP (gateway)" value={DEVICE.lanIp} />
          <StripItem icon="⌾" label="Wi-Fi Hotspot" value={DEVICE.hotspot} />
          <StripItem icon="↻" label="Firmware" value={DEVICE.firmware} />
          <StripItem icon="⏱" label="Uptime" value={DEVICE.uptime} />
        </footer>
      </main>
    </div>
  );
};

// value shown in the summary once a step is complete
function valueFor(id: string): string {
  const m = model();
  return {
    identity: m.deviceName, wireless: `${m.ssid} · ${m.wifiBand === 'auto' ? 'auto' : m.wifiBand + 'GHz'}`,
    network: m.lanSubnet, wan: m.wanMode.toUpperCase(),
    pppoe: m.wanMode === 'pppoe' ? m.pppoeUser : 'n/a',
    security: m.anchor === 'passphrase' ? 'passphrase' : 'factory key',
  }[id] || '';
}

const StripItem: Component<{ icon: string; label: string; value: string }> = (p) => (
  <div class="set-strip-item">
    <span class="set-strip-icon">{p.icon}</span>
    <span class="set-strip-text"><em>{p.label}</em><b>{p.value}</b></span>
  </div>
);

// Launch → deploying overlay: the booster-drop, with the WAN-readiness poll (ADR 0010).
const DeployView: Component = () => {
  const steps = [
    { t: 'Committing configuration (plan-as-diff → intent)', done: () => true },
    { t: 'Reconciling: Wi-Fi AP · LAN gateway · NAT · firewall', done: () => true },
    { t: 'Bringing up the WAN uplink', done: () => wanReady() },
    { t: 'Network live — redirecting to os.hookprobe.local', done: () => wanReady() },
  ];
  return (
    <div class="set-deploy">
      <div class={`set-deploy-orb${wanReady() ? ' set-deploy-orb--live' : ''}`} />
      <h2 class="set-deploy-title">{wanReady() ? 'Your SASE is live' : 'Deploying network…'}</h2>
      <p class="set-deploy-sub">Keeping your connection alive while the appliance rewrites its own network (same Wi-Fi, no reconnect).</p>
      <div class="set-deploy-steps">
        <For each={steps}>{s =>
          <div class={`set-deploy-step${s.done() ? ' set-deploy-step--done' : ''}`}>
            <span class="set-deploy-check">{s.done() ? '✓' : '◦'}</span>{s.t}
          </div>
        }</For>
      </div>
      <Show when={wanReady()}>
        <a class="set-btn set-btn--launch" href="/mission">Open Mission Control →</a>
      </Show>
    </div>
  );
};

export default SystemSetupApp;
