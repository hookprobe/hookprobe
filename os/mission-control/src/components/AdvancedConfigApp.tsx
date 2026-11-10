/**
 * AdvancedConfigApp — Advanced signed configuration (wireframes "Advanced · Internet / Wi-Fi /
 * Firewall and routes / Review, sign, upload, apply"; ADR 0058; requirements doc §Configuration
 * journey). One app, three sections, each a real route:
 *   internet  /network/wan/advanced  → WAN.TXT
 *   wifi      /network/wifi          → WIFI.TXT
 *   firewall  /protect/policies      → POLICY.TXT (4096 B)
 *
 * Build in a form (validated exactly as the device parses) → see the exact file → review the diff
 * against what the device reports → sign in this browser (Ed25519, byte-identical to policy-sign.py)
 * → upload (`/api/upload`, type wan | wifi | policy; applies at the next boot, previous generation kept)
 * → when the device cannot take the file over the network yet (ADR 0058 D1 not served), it says so and
 * the two signed files are offered for the boot card. Nothing here applies a change without the owner's
 * signature; the device re-verifies everything.
 */
import { type Component, For, Show, createMemo, createSignal, onMount } from 'solid-js';
import { substrate } from '../store/mock';
import { healthChecked } from '../store/health';
import { networkView, startNetworkLive } from '../store/networkLive';
import { uploadView, refreshUploads, uploadPack } from '../store/packUpload';
import { ownerKey, loadOwnerKey, signPack, signPolicy, signBundle, ownerKeyId, PACKS, download } from '../store/signing';
import {
  buildWan, checkWan, buildWifi, checkWifi, buildPolicyText, checkPolicy, stagePolicy, lineDiff,
  type WanForm, type WifiForm, type PolicyForm, type AclRow,
} from '../store/configBuild';
import AppShell, { normPath } from './AppShell';
import Drawer from './Drawer';
import SigningKeyPanel from './SigningKeyPanel';
import RestartButton from './RestartButton';
import { buildBundle, fromLegacy } from '../store/hqcfg';

type Sec = 'internet' | 'wifi' | 'firewall';
const SECS: [Sec, string, string][] = [['internet', 'Internet', '/network/wan/advanced'], ['wifi', 'Wi-Fi', '/network/wifi'], ['firewall', 'Firewall and routes', '/protect/policies']];
const FILE: Record<Sec, { name: string; sig: string; type: string }> = {
  internet: { name: 'WAN.TXT', sig: 'WAN.SIG', type: 'wan' },
  wifi: { name: 'WIFI.TXT', sig: 'WIFI.SIG', type: 'wifi' },
  firewall: { name: 'POLICY.TXT', sig: 'POLICY.SIG', type: 'policy' },
};
const secFor = (p: string): Sec => (p.startsWith('/network/wifi') ? 'wifi' : p.startsWith('/protect/policies') ? 'firewall' : 'internet');
const field = { font: 'inherit', 'min-height': '44px', padding: '0 12px', background: 'var(--hp-surface)', color: 'var(--hp-text-primary)', border: '1px solid var(--hp-border)', 'border-radius': 'var(--hp-radius)', width: '100%', 'box-sizing': 'border-box' } as const;

type Step = 'review' | 'sign' | 'upload' | 'done' | 'card';

const AdvancedConfigApp: Component<{ path?: string }> = (props) => {
  const [sec, setSec] = createSignal<Sec>(secFor(props.path ?? '/network/wan/advanced'));
  const [wan, setWan] = createSignal<WanForm>({ mode: 'dhcp', ip: '', gw: '', dns: '', pppoeUser: '', pppoePass: '', vlanOn: false, vlan: '', vlanOuter: '', pcp: '', mgmtOn: false, mgmtVlan: '', mgmtIp: '', mgmtGw: '' });
  const [wifi, setWifi] = createSignal<WifiForm>({ ssid: '', psk: '', security: 'wpa3-transition', channel: 'auto', maxClients: '' });
  const [pol, setPol] = createSignal<PolicyForm>({
    prefixes: [{ name: 'ADMIN', seq: '10', action: 'permit', prefix: '10.0.99.0/24', ge: '', le: '' }],
    acls: [{ name: 'MGMT_IN', seq: '10', action: 'allow', proto: 'tcp', src: 'pl:ADMIN', dst: 'any', port: '443' }],
    defaults: [{ name: 'MGMT_IN', action: 'drop' }],
    binds: [{ iface: 'mgmt', kind: 'acl', dir: 'in', name: 'MGMT_IN' }],
    routes: [{ dst: '0.0.0.0/0', from: '', via: 'wan', gw: '', metric: '10' }],
  });
  const [gen, setGen] = createSignal('');
  const [open, setOpen] = createSignal(false);
  const [step, setStep] = createSignal<Step>('review');
  const [signed, setSigned] = createSignal<{ txt: Uint8Array; sig: Uint8Array } | null>(null);
  const [msg, setMsg] = createSignal('');
  const [prefilled, setPrefilled] = createSignal(false);

  onMount(() => {
    setSec(secFor(normPath(location.pathname)));
    startNetworkLive(); void refreshUploads(); void loadOwnerKey();
  });

  const sample = () => healthChecked() && !substrate();
  // Prefill from what the device reports (once), so the draft starts from today's settings.
  const prefill = () => {
    const n = networkView();
    if (prefilled() || !n?.available) return;
    setPrefilled(true);
    if (n.wan) setWan({ ...wan(), mode: (n.wan.mode as WanForm['mode']) ?? 'dhcp', vlanOn: n.wan.vlan > 0, vlan: n.wan.vlan ? String(n.wan.vlan) : '', ip: n.wan.mode === 'static' ? `${n.wan.ip}/24` : '', gw: n.wan.mode === 'static' ? n.wan.gateway : '' });
    if (n.management) setWan({ ...wan(), mgmtOn: true, mgmtVlan: String(n.management.vlan), mgmtIp: `${n.management.ip}/24` });
    if (n.wifi) setWifi({ ...wifi(), ssid: n.wifi.ssid, channel: n.wifi.channel ? String(n.wifi.channel) : 'auto', security: /wpa3/i.test(n.wifi.security) ? 'wpa3-transition' : 'wpa2' });
  };

  // The builders refuse (throw) rather than emit a file the device would reject; show that as a problem.
  const built = createMemo(() => {
    try { return { t: sec() === 'internet' ? buildWan(wan()) : sec() === 'wifi' ? buildWifi(wifi()) : buildPolicyText(pol()), err: '' }; }
    catch (e) { return { t: '', err: e instanceof Error ? e.message : String(e) }; }
  });
  const text = () => built().t;
  const errors = createMemo(() => {
    const e = sec() === 'internet' ? checkWan(wan()) : sec() === 'wifi' ? checkWifi(wifi()) : checkPolicy(pol());
    return built().err && !e.length ? [...e, built().err] : e;
  });
  /** What the device reports today, as the same file (for the review diff). */
  const current = createMemo(() => {
    const n = networkView();
    if (!n?.available) return '';
    if (sec() === 'internet' && n.wan) try { return buildWan({ ...wan(), mode: n.wan.mode as WanForm['mode'], vlanOn: n.wan.vlan > 0, vlan: String(n.wan.vlan), mgmtOn: !!n.management, mgmtVlan: n.management ? String(n.management.vlan) : '', pppoeUser: n.wan.mode === 'pppoe' ? '(current)' : '', pppoePass: n.wan.mode === 'pppoe' ? '(current)' : '' }); } catch { return ''; }
    if (sec() === 'wifi' && n.wifi) return `ssid=${n.wifi.ssid}\npsk=(current)\n${n.wifi.channel ? `channel=${n.wifi.channel}\n` : ''}`;
    return '';
  });
  const activeGen = () => {
    if (sec() === 'firewall') return networkView()?.policy?.generation ?? 0;
    return uploadView()?.types.find((t) => t.type === FILE[sec()].type)?.generation ?? 0;
  };
  const genNum = () => (gen().trim() ? Number(gen()) : activeGen() + 1);

  const sign = async () => {
    setMsg('');
    try {
      const txt = sec() === 'firewall' ? stagePolicy(text()) : new TextEncoder().encode(text());
      const sig = sec() === 'firewall' ? await signPolicy(genNum(), txt) : await signPack(sec() === 'internet' ? PACKS.wan : PACKS.wifi, genNum(), txt);
      setSigned({ txt, sig });
      setStep(sample() ? 'card' : 'upload');
    } catch (e) { setMsg(e instanceof Error ? e.message : String(e)); }
  };

  const [staged, setStaged] = createSignal(true);
  const upload = async () => {
    const s = signed(); if (!s) return;
    setMsg('');
    try {
      const container = new File([new Uint8Array(s.sig), new Uint8Array(s.txt)], `${FILE[sec()].type}.pack`);
      const r = await uploadPack(FILE[sec()].type, container, () => window.prompt('This changes how the device connects. Enter your owner key:', ''), () => undefined);
      setStaged(r.staged);
      setMsg(`${r.text} The previous generation is kept: Administration → Signed packs can roll back to it.`);
      setStep('done');
    } catch (e) {
      const m = e instanceof Error ? e.message : String(e);
      // "type" = this kernel does not accept this file over the network yet (ADR 0058 D1 not served):
      // only then is the boot card the way. Any other refusal (signature, generation…) is the answer.
      if (/: type$/.test(m)) { setMsg(`The device answered that it doesn't accept ${FILE[sec()].name} over the network yet.`); setStep('card'); }
      else setMsg(m);
    }
  };

  /** The current section as an HQCFG1 bundle + HQCSIG1 (same generation), signed with the browser key. */
  const bundle = async () => {
    setMsg('');
    try {
      const kind = sec() === 'internet' ? 'wan' : sec() === 'wifi' ? 'wifi' : 'policy';
      const b = buildBundle({ [kind]: fromLegacy(kind, text()) }, genNum(), await ownerKeyId());
      download('HQCFG1.BIN', b);
      download('HQCFG1.SIG', await signBundle(b));
    } catch (e) { setMsg(e instanceof Error ? e.message : String(e)); }
  };

  const startApply = () => { setStep('review'); setSigned(null); setMsg(''); setOpen(true); };
  const setAcl = (i: number, patch: Partial<AclRow>) => setPol({ ...pol(), acls: pol().acls.map((a, j) => (j === i ? { ...a, ...patch } : a)) });

  return (
    <AppShell path={props.path ?? '/network/wan/advanced'}>
      <main class="pro-main" aria-label="Advanced settings" ref={() => queueMicrotask(prefill)}>
        <div class="pro-head">
          <div>
            <p class="pro-crumb"><a href="/network/wan">Get Online</a> / Advanced</p>
            <h1 class="pro-title">Advanced settings</h1>
            <p class="pro-sub">Changes here are signed with your key and apply on the next reboot. Only options this device supports are shown.</p>
          </div>
        </div>
        <nav class="tabs" aria-label="Advanced sections">
          <For each={SECS}>{([s, label, href]) => <a class="tab" href={href} aria-current={sec() === s ? 'page' : undefined} aria-selected={sec() === s} style={{ display: 'inline-flex', 'align-items': 'center', 'text-decoration': 'none' }}>{label}</a>}</For>
        </nav>

        <div class="tl" style={{ 'grid-template-columns': 'minmax(0, 1fr) 380px' }} ref={() => queueMicrotask(prefill)}>
          <section style={{ display: 'flex', 'flex-direction': 'column', gap: '16px', 'min-width': 0 }}>
            <Show when={sec() === 'internet'}>
              <div class="pcard">
                <p class="l0-label">Connection type</p>
                <div class="l0-seg" role="group" aria-label="Connection type" style={{ 'align-self': 'flex-start' }}>
                  <For each={[['dhcp', 'Automatic (DHCP)'], ['static', 'Static'], ['pppoe', 'PPPoE']] as [WanForm['mode'], string][]}>{([m, label]) => (
                    <button class={`l0-seg-item${wan().mode === m ? ' is-active' : ''}`} aria-pressed={wan().mode === m} style={{ border: 0, font: 'inherit', cursor: 'pointer', background: wan().mode === m ? undefined : 'none' }} onClick={() => setWan({ ...wan(), mode: m })}>{label}</button>
                  )}</For>
                </div>
                <Show when={wan().mode === 'dhcp'}><p class="l0-card-sub">The device asks your modem or ISP for an address automatically. Nothing else to fill in.</p></Show>
                <Show when={wan().mode === 'pppoe'}>
                  <div class="l0-grid-2">
                    <label class="l0-card-sub">PPPoE username<input style={field} value={wan().pppoeUser} onInput={(e) => setWan({ ...wan(), pppoeUser: e.currentTarget.value })} placeholder="from your ISP letter" autocomplete="off" /></label>
                    <label class="l0-card-sub">PPPoE password<input style={field} type="password" value={wan().pppoePass} onInput={(e) => setWan({ ...wan(), pppoePass: e.currentTarget.value })} autocomplete="new-password" /></label>
                  </div>
                </Show>
                <Show when={wan().mode === 'static'}>
                  <div class="l0-grid-3">
                    <label class="l0-card-sub">Address / prefix<input style={field} value={wan().ip} onInput={(e) => setWan({ ...wan(), ip: e.currentTarget.value })} placeholder="192.0.2.10/24" /></label>
                    <label class="l0-card-sub">Gateway<input style={field} value={wan().gw} onInput={(e) => setWan({ ...wan(), gw: e.currentTarget.value })} placeholder="192.0.2.1" /></label>
                    <label class="l0-card-sub">DNS (optional)<input style={field} value={wan().dns} onInput={(e) => setWan({ ...wan(), dns: e.currentTarget.value })} placeholder="defaults to gateway" /></label>
                  </div>
                </Show>
              </div>
              <div class="pcard">
                <label class="prow" style={{ border: 0, padding: 0, 'align-items': 'center' }}><span class="l0-label">ISP VLAN</span>
                  <input type="checkbox" checked={wan().vlanOn} onChange={(e) => setWan({ ...wan(), vlanOn: e.currentTarget.checked })} style={{ width: '22px', height: '22px' }} /></label>
                <p class="l0-card-sub">Some fibre ISPs need traffic tagged with a VLAN number. Check your ISP's instructions.</p>
                <Show when={wan().vlanOn}>
                  <div class="l0-grid-3">
                    <label class="l0-card-sub">VLAN ID<input style={field} value={wan().vlan} onInput={(e) => setWan({ ...wan(), vlan: e.currentTarget.value })} placeholder="6" inputmode="numeric" /></label>
                    <label class="l0-card-sub">Outer VLAN (QinQ, optional)<input style={field} value={wan().vlanOuter} onInput={(e) => setWan({ ...wan(), vlanOuter: e.currentTarget.value })} placeholder="none" inputmode="numeric" /></label>
                    <label class="l0-card-sub">Priority (PCP 0–7)<input style={field} value={wan().pcp} onInput={(e) => setWan({ ...wan(), pcp: e.currentTarget.value })} placeholder="0" inputmode="numeric" /></label>
                  </div>
                </Show>
              </div>
              <div class="pcard">
                <label class="prow" style={{ border: 0, padding: 0, 'align-items': 'center' }}><span class="l0-label">Management VLAN (Pro)</span>
                  <input type="checkbox" checked={wan().mgmtOn} onChange={(e) => setWan({ ...wan(), mgmtOn: e.currentTarget.checked })} style={{ width: '22px', height: '22px' }} /></label>
                <p class="l0-card-sub">Reach Mission Control from a separate admin network on the same cable.</p>
                <Show when={wan().mgmtOn}>
                  <div class="l0-grid-3">
                    <label class="l0-card-sub">VLAN ID<input style={field} value={wan().mgmtVlan} onInput={(e) => setWan({ ...wan(), mgmtVlan: e.currentTarget.value })} placeholder="99" inputmode="numeric" /></label>
                    <label class="l0-card-sub">Address / prefix (empty = DHCP)<input style={field} value={wan().mgmtIp} onInput={(e) => setWan({ ...wan(), mgmtIp: e.currentTarget.value })} placeholder="10.0.99.2/24" /></label>
                    <label class="l0-card-sub">Gateway<input style={field} value={wan().mgmtGw} onInput={(e) => setWan({ ...wan(), mgmtGw: e.currentTarget.value })} placeholder="10.0.99.1" /></label>
                  </div>
                </Show>
              </div>
            </Show>

            <Show when={sec() === 'wifi'}>
              <div class="pcard">
                <p class="l0-label">Network</p>
                <div class="l0-grid-2">
                  <label class="l0-card-sub">Wi-Fi name (1–32 characters)<input style={field} value={wifi().ssid} onInput={(e) => setWifi({ ...wifi(), ssid: e.currentTarget.value })} placeholder="HookProbe-Home" /></label>
                  <label class="l0-card-sub">Password (8–63 characters)<input style={field} type="password" value={wifi().psk} onInput={(e) => setWifi({ ...wifi(), psk: e.currentTarget.value })} autocomplete="new-password" /></label>
                </div>
              </div>
              <div class="pcard">
                <p class="l0-label">Security</p>
                <div class="l0-chips" role="group" aria-label="Security">
                  <For each={[['wpa2', 'WPA2'], ['wpa3', 'WPA3 only'], ['wpa3-transition', 'WPA3 + WPA2']] as [WifiForm['security'], string][]}>{([s, label]) => (
                    <button class={`l0-chip${wifi().security === s ? ' is-on' : ''}`} aria-pressed={wifi().security === s} onClick={() => setWifi({ ...wifi(), security: s })}>{label}</button>
                  )}</For>
                </div>
                <p class="l0-card-sub">{{ wpa2: 'Works with every device. Choose this if older devices can’t connect.', wpa3: 'Strongest. Older devices without WPA3 won’t connect.', 'wpa3-transition': 'WPA3 for devices that support it, WPA2 for the rest.' }[wifi().security]}</p>
              </div>
              <div class="pcard">
                <p class="l0-label">Channel</p>
                <div class="l0-chips" role="group" aria-label="Channel">
                  <For each={['auto', '1', '6', '11', '36', '40', '44', '48']}>{(c) => (
                    <button class={`l0-chip${wifi().channel === c ? ' is-on' : ''}`} aria-pressed={wifi().channel === c} onClick={() => setWifi({ ...wifi(), channel: c })}>{c === 'auto' ? 'Auto' : c}</button>
                  )}</For>
                </div>
                <p class="pcard-note">5 GHz is limited to channels 36–48 on this hardware (DFS channels aren't supported by the radio firmware).</p>
              </div>
              <div class="pcard l0-card--dashed">
                <p class="l0-label">Guest network</p>
                <p class="l0-card-sub">Not available: this device runs one Wi-Fi network (the radio firmware cannot run a second). Put guests in an internet-only zone in My Network instead.</p>
              </div>
            </Show>

            <Show when={sec() === 'firewall'}>
              <div class="pcard">
                <p class="l0-label">Access lists · checked top to bottom, first match wins; replies to connections your network opened always come back</p>
                <div class="l0-table-wrap"><table class="l0-table">
                  <thead><tr><th>List</th><th>Seq</th><th>Action</th><th>Proto</th><th>Source</th><th>Destination</th><th>Port</th><th><span class="sr-only">Remove</span></th></tr></thead>
                  <tbody><For each={pol().acls}>{(a, i) => (
                    <tr>
                      <td><input style={{ ...field, 'min-height': '36px', width: '110px' }} value={a.name} onInput={(e) => setAcl(i(), { name: e.currentTarget.value })} aria-label="List name" /></td>
                      <td><input style={{ ...field, 'min-height': '36px', width: '60px' }} value={a.seq} onInput={(e) => setAcl(i(), { seq: e.currentTarget.value })} aria-label="Sequence" /></td>
                      <td><select style={{ ...field, 'min-height': '36px', width: '90px' }} value={a.action} onChange={(e) => setAcl(i(), { action: e.currentTarget.value as AclRow['action'] })} aria-label="Action"><option>allow</option><option>block</option><option>drop</option></select></td>
                      <td><input style={{ ...field, 'min-height': '36px', width: '70px' }} value={a.proto} onInput={(e) => setAcl(i(), { proto: e.currentTarget.value })} aria-label="Protocol" /></td>
                      <td><input style={{ ...field, 'min-height': '36px', width: '130px' }} value={a.src} onInput={(e) => setAcl(i(), { src: e.currentTarget.value })} aria-label="Source" /></td>
                      <td><input style={{ ...field, 'min-height': '36px', width: '130px' }} value={a.dst} onInput={(e) => setAcl(i(), { dst: e.currentTarget.value })} aria-label="Destination" /></td>
                      <td><input style={{ ...field, 'min-height': '36px', width: '80px' }} value={a.port} onInput={(e) => setAcl(i(), { port: e.currentTarget.value })} aria-label="Port" /></td>
                      <td><button class="hp-btn" style={{ 'min-height': '36px' }} onClick={() => setPol({ ...pol(), acls: pol().acls.filter((_, j) => j !== i()) })} aria-label="Remove rule">✕</button></td>
                    </tr>
                  )}</For></tbody>
                </table></div>
                <div class="l0-card-foot">
                  <button class="hp-btn" onClick={() => setPol({ ...pol(), acls: [...pol().acls, { name: 'LAN_IN', seq: String((pol().acls.length + 1) * 10), action: 'allow', proto: 'any', src: 'any', dst: 'any', port: '' }] })}>+ Rule</button>
                  <button class="hp-btn" onClick={() => setPol({
                    ...pol(),
                    acls: [...pol().acls.filter((a) => a.name !== 'LAN_IN'), { name: 'LAN_IN', seq: '10', action: 'block', proto: 'any', src: '10.66.0.0/24', dst: '10.66.0.0/24', port: '' }, { name: 'LAN_IN', seq: '20', action: 'allow', proto: 'any', src: 'any', dst: 'any', port: '' }],
                    binds: [...pol().binds.filter((b) => !(b.iface === 'lan' && b.kind === 'acl')), { iface: 'lan', kind: 'acl', dir: 'in', name: 'LAN_IN' }],
                  })}>+ From template: block device-to-device traffic</button>
                </div>
                <p class="pcard-note">Anything not matched: the list's default (unset = drop). Block rejects so the sender knows; drop is silent.</p>
              </div>
              <div class="pcard">
                <p class="l0-label">Prefix lists · interfaces · routes</p>
                <For each={pol().prefixes}>{(p) => <span class="prow"><span>prefix-list {p.name} seq {p.seq}</span><span>{p.action} {p.prefix}</span></span>}</For>
                <For each={pol().binds}>{(b) => <span class="prow"><span>interface {b.iface}</span><span>{b.kind} {b.dir} {b.name}</span></span>}</For>
                <For each={pol().routes}>{(r) => <span class="prow"><span>route {r.dst}</span><span>via {r.via}{r.gw ? ` gw ${r.gw}` : ''}{r.metric ? ` metric ${r.metric}` : ''}</span></span>}</For>
                <p class="pcard-note">Two default routes with different metrics form an automatic failover pair.</p>
              </div>
            </Show>
          </section>

          <aside class="tl-side" aria-label="Draft file">
            <div class="pcard" style={{ 'border-width': '2px', padding: 0, overflow: 'hidden', gap: 0 }}>
              <span class="prow" style={{ padding: '10px 14px' }}><span style={{ 'font-weight': 600 }}>{FILE[sec()].name} · draft</span><span>generation {activeGen() || '?'} → {genNum()}</span></span>
              <pre style={{ margin: 0, padding: '14px', font: '13px/1.7 var(--hp-font-mono)', background: 'rgba(255,255,255,.03)', 'white-space': 'pre-wrap', 'overflow-wrap': 'anywhere' }}>{text().replace(/(pppoe_pass|psk)=.*/g, '$1=••••••••')}</pre>
            </div>
            <label class="l0-card-sub" style={{ display: 'flex', 'flex-direction': 'column', gap: '4px' }}>Generation (must be higher than the active one)
              <input style={field} inputmode="numeric" value={gen()} placeholder={String(activeGen() + 1)} onInput={(e) => setGen(e.currentTarget.value.replace(/\D/g, ''))} /></label>
            <Show when={errors().length > 0}>
              <ul style={{ margin: 0, 'padding-left': '18px' }} aria-label="Problems">
                <For each={errors()}>{(e) => <li class="plan-diff-warn">{e}</li>}</For>
              </ul>
            </Show>
            <p class="pcard-note">This is the exact file the device will receive (secrets hidden here). You sign it with your key on the next step.</p>
            <button class="hp-btn hp-btn--primary" disabled={errors().length > 0} onClick={startApply}>Review and sign →</button>
            <a class="hp-btn" href="/network/wan" style={{ 'justify-content': 'center' }}>Discard draft</a>
          </aside>
        </div>
      </main>

      <Drawer open={open()} title="Review, sign and apply" crumb={`${FILE[sec()].name} · generation ${genNum()}`} onClose={() => setOpen(false)}>
        <ol class="plan-steps" aria-label="Progress">
          <For each={[['review', 'Review'], ['sign', 'Sign'], ['upload', 'Upload and check'], ['done', 'Apply']] as [Step, string][]}>{([s, label], i) => {
            const order: Step[] = ['review', 'sign', 'upload', 'done'];
            const cur = order.indexOf(step() === 'card' ? 'upload' : step());
            return <li class={`plan-step${i() < cur || step() === 'done' ? ' plan-step--done' : i() === cur ? ' plan-step--now' : ''}`}>{label}</li>;
          }}</For>
        </ol>

        <Show when={step() === 'review'}>
          <p class="l0-label">The change</p>
          <div class="plan-diff-lines">
            <For each={current() ? lineDiff(current(), text()) : text().split('\n').filter(Boolean).map((t) => ({ kind: 'added' as const, text: t }))}>{(l) => (
              <div class={`plan-diff-line plan-diff-line--${l.kind}`}><span class="plan-diff-mark">{l.kind === 'added' ? '+' : l.kind === 'removed' ? '−' : ' '}</span>{l.text.replace(/(pppoe_pass|psk)=.*/, '$1=••••••••')}</div>
            )}</For>
          </div>
          <p class="pcard-note">{current() ? 'Compared with what the device reports today.' : 'The device does not report this file’s current contents, so the whole new file is shown.'}</p>
          <p class="l0-card-sub"><b>What happens:</b> {sec() === 'firewall' ? 'the new rules take effect after the next reboot.' : 'the connection drops for about a minute during the reboot; Wi-Fi and protection come back on their own.'} If the new settings don't work, the previous generation stays available for rollback.</p>
          <button class="hp-btn hp-btn--primary" onClick={() => setStep('sign')}>Looks right · sign it</button>
        </Show>

        <Show when={step() === 'sign'}>
          <Show when={ownerKey()} fallback={<SigningKeyPanel compact />}>
            <p class="l0-card-sub">Signing {FILE[sec()].name} · generation {genNum()} with your key {ownerKey()!.pubHex.slice(0, 8)}…</p>
            <button class="hp-btn hp-btn--primary" onClick={() => void sign()}>Sign in this browser</button>
          </Show>
        </Show>

        <Show when={step() === 'upload'}>
          <p class="go-state--up" style={{ margin: 0 }}>✓ Signed in the browser</p>
          <p class="l0-card-sub">Upload it: the device checks your signature and that the generation is newer, then stages it for the next boot (owner key).</p>
          <button class="hp-btn hp-btn--primary" onClick={() => void upload()}>Upload to the device</button>
        </Show>

        <Show when={step() === 'done'}>
          <Show when={staged()} fallback={<p class="go-state--up" style={{ margin: 0, 'font-weight': 600 }}>✓ Applied</p>}>
            <p class="go-state--up" style={{ margin: 0, 'font-weight': 600 }}>✓ Staged: takes effect at the next restart</p>
            <p class="l0-card-sub">Restart now, or let it apply at the next restart.</p>
            <RestartButton primary />
          </Show>
        </Show>

        <Show when={step() === 'card' && signed()}>
          <p class="go-state--up" style={{ margin: 0 }}>✓ Signed in the browser</p>
          <p class="l0-card-sub">{sample() ? 'Preview: no device is connected.' : 'This device cannot take this file over the network yet (ADR 0058).'} Copy both files to the device's boot card (replacing the old ones), then restart it — no build machine needed.</p>
          <div class="l0-card-foot">
            <button class="hp-btn hp-btn--primary" onClick={() => download(FILE[sec()].name, signed()!.txt, 'text/plain')}>Download {FILE[sec()].name}</button>
            <button class="hp-btn" onClick={() => download(FILE[sec()].sig, signed()!.sig)}>Download {FILE[sec()].sig}</button>
          </div>
          <p class="pcard-note">Or the same settings as one signed configuration bundle (HQCFG1, ADR 0059), for devices that take bundles:</p>
          <div class="l0-card-foot"><button class="hp-btn" onClick={() => void bundle()}>Download as a signed bundle</button></div>
          <Show when={sec() !== 'firewall'}>
            <p class="pcard-note">{sec() === 'wifi' ? 'The Wi-Fi password' : 'A PPPoE password'} is inside the signed file in clear: anyone holding the boot card can read it. It is not protected at rest yet.</p>
          </Show>
        </Show>
        <Show when={msg()}><p class="pro-sub" role="status" style={{ margin: 0 }}>{msg()}</p></Show>
      </Drawer>
    </AppShell>
  );
};

export default AdvancedConfigApp;
