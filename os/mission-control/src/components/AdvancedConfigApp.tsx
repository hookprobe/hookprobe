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
import { type Component, For, Show, createEffect, createMemo, createSignal, onMount } from 'solid-js';
import { substrate } from '../store/mock';
import { healthChecked } from '../store/health';
import { networkView, startNetworkLive } from '../store/networkLive';
import { uploadView, refreshUploads, uploadPack } from '../store/packUpload';
import { ownerKey, loadOwnerKey, signPack, signPolicy, signBundle, ownerKeyId, PACKS, download } from '../store/signing';
import {
  buildWan, checkWan, buildWifi, checkWifi, buildPolicyText, parsePolicyText, checkPolicy, stagePolicy, lineDiff,
  type WanForm, type WifiForm, type PolicyForm, type AclRow,
} from '../store/configBuild';
import AppShell, { normPath } from './AppShell';
import Drawer from './Drawer';
import SigningKeyPanel from './SigningKeyPanel';
import RestartButton from './RestartButton';
import { askOwnerKey } from '../store/approve';
import { buildBundle, fromLegacy } from '../store/hqcfg';
import { configView, refreshConfig, restNote } from '../store/configState';
import { anchorView, refreshAnchor } from '../store/anchor';

type Sec = 'internet' | 'wifi' | 'firewall';
const SECS: [Sec, string, string][] = [['internet', 'Internet', '/network/wan/advanced'], ['wifi', 'Wi-Fi', '/network/wifi'], ['firewall', 'Firewall and routes', '/protect/policies']];
const FILE: Record<Sec, { name: string; sig: string; type: string }> = {
  internet: { name: 'WAN.TXT', sig: 'WAN.SIG', type: 'wan' },
  wifi: { name: 'WIFI.TXT', sig: 'WIFI.SIG', type: 'wifi' },
  firewall: { name: 'POLICY.TXT', sig: 'POLICY.SIG', type: 'policy' },
};
const secFor = (p: string): Sec => (p.startsWith('/network/wifi') ? 'wifi' : p.startsWith('/protect/policies') ? 'firewall' : 'internet');
const field = { font: 'inherit', 'font-size': '16px', 'min-height': '44px', padding: '0 12px', background: 'var(--hp-surface)', color: 'var(--hp-text-primary)', border: '1px solid var(--hp-border)', 'border-radius': 'var(--hp-radius)', width: '100%', 'box-sizing': 'border-box' } as const;

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
  // The device does not report its firewall text, so the form starts from an EXAMPLE. It is only ever signed when
  // the owner actually edits it: a bundle carries a policy section only then (a bundle is the complete
  // configuration for the sections it carries; without one the device keeps its own firewall).
  // "Edited" = differs from where the form started (the example, or the firewall in force once prefilled).
  const [polBase, setPolBase] = createSignal(JSON.stringify(pol()));
  const polDirty = () => JSON.stringify(pol()) !== polBase();
  // The bundle in force, as the device reports it (kernel #1055): the editors start from it, and an untouched
  // firewall is re-sent verbatim (byte-for-byte), never rebuilt.
  const devPolicy = () => (configView()?.sections?.policy?.present ? configView()!.policy_text ?? null : null);
  const [polEditable, setPolEditable] = createSignal(true);
  const [fromDevice, setFromDevice] = createSignal(false);
  createEffect(() => {
    const c = configView();
    if (!c || fromDevice() || (!c.wan_keys && !c.wifi_keys && !c.sections)) return;
    setFromDevice(true);
    const s = (o: Record<string, string | boolean> | null | undefined, k: string) => (typeof o?.[k] === 'string' ? (o[k] as string) : '');
    const w = c.wan_keys;
    if (w) setWan({ ...wan(), mode: (s(w, 'mode') || 'dhcp') as WanForm['mode'], ip: s(w, 'ip'), gw: s(w, 'gw'), dns: s(w, 'dns'), pppoeUser: s(w, 'pppoe_user'), pppoePass: '',
      vlanOn: !!s(w, 'vlan'), vlan: s(w, 'vlan'), vlanOuter: s(w, 'vlan_outer'), pcp: s(w, 'pcp'), mgmtOn: !!s(w, 'mgmt_vlan'), mgmtVlan: s(w, 'mgmt_vlan'), mgmtIp: s(w, 'mgmt_ip'), mgmtGw: s(w, 'mgmt_gw') });
    const f = c.wifi_keys;
    if (f) setWifi({ ...wifi(), ssid: s(f, 'ssid'), psk: '', security: (s(f, 'security') || 'wpa2') as WifiForm['security'], channel: s(f, 'channel') || 'auto', maxClients: s(f, 'max_clients') });
    const t = devPolicy();
    if (t) { const parsed = parsePolicyText(t); if (parsed) { setPol(parsed); setPolBase(JSON.stringify(parsed)); } else setPolEditable(false); }
    setPrefilled(true);
  });
  const [gen, setGen] = createSignal('');
  const [open, setOpen] = createSignal(false);
  const [step, setStep] = createSignal<Step>('review');
  const [signed, setSigned] = createSignal<{ txt: Uint8Array; sig: Uint8Array } | null>(null);
  const [msg, setMsg] = createSignal('');
  const [prefilled, setPrefilled] = createSignal(false);

  onMount(() => {
    setSec(secFor(normPath(location.pathname)));
    window.addEventListener('popstate', () => setSec(secFor(normPath(location.pathname))));
    void refreshConfig(); void refreshAnchor();
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
      const r = await uploadPack(FILE[sec()].type, container, () => askOwnerKey('Send this file to the device?', 'It changes how the device connects. The device checks your signature first.', 'Send'), () => undefined);
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

  // ── All three together: one HQCFG1 bundle (ADR 0059). A bundle is the COMPLETE configuration for
  // internet + Wi-Fi + firewall, applied as a health-checked trial; the device never reveals stored
  // secrets, so the PPPoE password and Wi-Fi passphrase must be typed again here.
  const [bOpen, setBOpen] = createSignal(false);
  const [bMsg, setBMsg] = createSignal('');
  const [bLive, setBLive] = createSignal(false);
  const [bNeedsConfirm, setBNeedsConfirm] = createSignal(false);
  const [bStep, setBStep] = createSignal<'review' | 'done' | 'files'>('review');
  const [bFiles, setBFiles] = createSignal<{ bin: Uint8Array; sig: Uint8Array } | null>(null);
  /** Bind the bundle to this device when it reports its id (it then refuses the bundle on any other device). */
  // An all-zero id means 'any device' in HQCFG1 (and is what a device without an identity reports), so it is
  // treated as no id: the bundle stays unbound and the drawer says so.
  const deviceIdHex = () => { const h = anchorView()?.device_id; return h && /^[0-9a-f]{32}$/i.test(h) && /[1-9a-f]/i.test(h) ? h : ''; };
  const deviceIdBytes = () => (deviceIdHex() ? Uint8Array.from(deviceIdHex().match(/../g)!, (x) => parseInt(x, 16)) : new Uint8Array(16));
  /** After enrollment the device accepts internet / Wi-Fi / firewall / bundle files ONLY when signed by its
   *  owner key (vendor- or other-key signatures are refused; a factory reset keeps the owner key). */
  const keyMismatch = () => { const a = anchorView(); return !!(a?.owner_enrolled && a.owner_key && ownerKey() && a.owner_key !== ownerKey()!.pubHex); };
  const MismatchNote = () => (
    <p class="plan-diff-warn" role="alert" style={{ margin: 0 }}>This device only accepts settings signed with the signing key it trusts ({anchorView()!.owner_key!.slice(0, 8)}…), and the key in this browser is a different one, so the device would refuse anything signed here. <a href="/admin/identity">Import that key's backup</a> in Administration → Signing key.</p>
  );
  /** A configuration bundle in force: the device refuses single-file wan / wifi / policy uploads (ADR 0059). */
  const bundleInForce = () => { const c = configView(); return !!c && (c.state === 'trial' || c.state === 'committed') && c.generation > 0; };
  const takesBundles = () => !!uploadView()?.types.some((t) => t.type === 'config');
  const bundleGen = () => Math.max(configView()?.generation ?? 0, configView()?.floor ?? 0, uploadView()?.types.find((t) => t.type === 'config')?.generation ?? 0) + 1;
  const bundleProblems = createMemo(() => {
    const e: string[] = [];
    checkWan(wan()).forEach((x) => e.push(`Internet: ${x}`));
    checkWifi(wifi()).forEach((x) => e.push(`Wi-Fi: ${x}`));
    if (polDirty()) checkPolicy(pol()).forEach((x) => e.push(`Firewall: ${x}`));
    // A bundle is the WHOLE configuration (metal, 12 Nov): over a bundle in force, a section left out is REMOVED,
    // not kept. The device does not report the firewall in force, so the owner must supply it.
    else if (bundleInForce() && !configView()?.sections) e.push('Firewall: a configuration bundle is in force, and a new bundle replaces all of it. This device does not report the firewall in force, so include the firewall you want (edit the Firewall tab): leaving it out removes it.');
    if (wan().mode === 'pppoe' && (!wan().pppoePass || wan().pppoePass === '(current)')) e.push('Internet: type the PPPoE password again (the device never shows it).');
    if (!wifi().psk) e.push('Wi-Fi: type the Wi-Fi password again (the device never shows it).');
    return e;
  });
  const bundleSections = (): { wan: string; wifi: string; policy?: string } => ({ wan: fromLegacy('wan', buildWan(wan())), wifi: fromLegacy('wifi', buildWifi(wifi())),
    ...(polDirty() ? { policy: fromLegacy('policy', buildPolicyText(pol())) } : devPolicy() ? { policy: fromLegacy('policy', devPolicy()!) } : {}) });
  const applyBundle = async () => {
    setBMsg('');
    try {
      const b = buildBundle(bundleSections(), bundleGen(), await ownerKeyId(), deviceIdBytes());
      const sig = await signBundle(b);
      setBFiles({ bin: b, sig });
      if (sample() || !takesBundles()) { setBStep('files'); return; }
      const r = await uploadPack('config', new File([new Uint8Array(sig), new Uint8Array(b)], 'config.pack'), () => askOwnerKey('Send the bundle to the device?', 'It replaces the sections it carries, then runs as a trial.', 'Send'), () => undefined);
      setBLive(!!r.live); setBNeedsConfirm(!!r.needsConfirm); setBMsg(r.text); setBStep('done');
    } catch (e) { setBMsg(e instanceof Error ? e.message : String(e)); }
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
          <For each={SECS}>{([s, label, href]) => <a class="tab" href={href} onClick={(e) => { e.preventDefault(); history.pushState(null, '', href); setSec(s); setOpen(false); }} aria-current={sec() === s ? 'page' : undefined} aria-selected={sec() === s} style={{ display: 'inline-flex', 'align-items': 'center', 'text-decoration': 'none' }}>{label}</a>}</For>
        </nav>

        <div class="tl adv-grid" ref={() => queueMicrotask(prefill)}>
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
              <Show when={!polDirty() && !devPolicy()}>
                <p class="plan-diff-warn" role="note" style={{ margin: 0 }}>These rules are an <b>example</b> to start from, not your device's current firewall (the device does not report it). Signing them replaces the device's firewall, so change them to what you want first.</p>
              </Show>
              <Show when={devPolicy() && polEditable() && !polDirty()}>
                <p class="pcard-note" role="note" style={{ margin: 0 }}>These are the rules in force on the device. Change them and they replace it; leave them and a bundle sends them again unchanged.</p>
              </Show>
              <Show when={devPolicy() && !polEditable()}>
                <p class="plan-diff-warn" role="note" style={{ margin: 0 }}>The firewall in force uses statements this editor does not handle, so it is shown as text and sent again unchanged. Edit it with the policy tools instead.</p>
                <pre class="pro-pre" aria-label="Firewall in force">{devPolicy()}</pre>
              </Show>
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
            <Show when={bundleInForce()}>
              <p class="plan-diff-warn" role="alert" style={{ margin: 0 }}>A configuration bundle is in force (generation {configView()!.generation}), so the device refuses single-file changes. Use "Apply all three together" below, with every section you want to keep.</p>
            </Show>
            <button class="hp-btn hp-btn--primary" disabled={errors().length > 0 || bundleInForce()} onClick={startApply}>Review and sign →</button>
            <a class="hp-btn" href="/network/wan" style={{ 'justify-content': 'center' }}>Discard draft</a>
            <div class="pcard" aria-label="Apply all together">
              <p class="l0-label">Or apply all three together</p>
              <p class="l0-card-sub">One signed bundle replaces internet + Wi-Fi + firewall together and runs as a health-checked trial: if the internet does not come back, the device goes back by itself. A single-section change (above) is not health-checked.</p>
              <button class="hp-btn" onClick={() => { setBStep('review'); setBMsg(''); setBOpen(true); }}>Review all three →</button>
            </div>
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
            <Show when={keyMismatch()}><MismatchNote /></Show>
            <button class="hp-btn hp-btn--primary" disabled={keyMismatch()} onClick={() => void sign()}>Sign in this browser</button>
          </Show>
        </Show>

        <Show when={step() === 'upload'}>
          <p class="go-state--up" style={{ margin: 0 }}>✓ Signed in the browser</p>
          <p class="l0-card-sub">Upload it: the device checks your signature and that the generation is newer, then stages it for the next boot (device password to send; your signing key authorises it).</p>
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
          <Show when={sec() !== 'firewall'}>
            <p class="pcard-note">{restNote()}</p>
          </Show>
        </Show>
        <Show when={msg()}><p class="pro-sub" role="status" style={{ margin: 0 }}>{msg()}</p></Show>
      </Drawer>

      <Drawer open={bOpen()} title="Apply all three together" crumb={`configuration bundle · generation ${bundleGen()}`} onClose={() => setBOpen(false)}>
        <p class="l0-card-sub">The bundle is the complete configuration for the sections it carries. After the restart it runs as a trial: the device keeps it once the internet works, or goes back to the previous settings by itself. Changes to the management network must be kept by you within the window.</p>
        <Show when={bStep() === 'review'}>
          <For each={(['wan', 'wifi', 'policy'] as const)}>{(k) => (
            <div class="pcard" style={{ padding: '10px 12px', gap: '6px' }}>
              <p class="l0-label">{k === 'wan' ? 'Internet' : k === 'wifi' ? 'Wi-Fi' : 'Firewall'}</p>
              <Show when={k !== 'policy' || polDirty() || !!devPolicy()} fallback={
                <p class="l0-card-sub" aria-label="Firewall not included" style={{ margin: 0 }}>Not included: the device keeps the firewall from its own files (no bundle is in force). To replace it, edit the Firewall tab first.</p>
              }>
                <p class="pcard-note" style={{ margin: 0 }}>{k === 'policy' ? (polDirty() ? 'Replaced by your edits in the Firewall tab.' : 'Kept: sent again exactly as in force.') : 'Replaced by this section.'}</p>
                <pre style={{ margin: 0, font: '12px/1.6 var(--hp-font-mono)', 'white-space': 'pre-wrap' }}>{(() => { try { return (bundleSections()[k] ?? '').replace(/(pppoe_pass|psk)=.*/g, '$1=••••••••'); } catch (e) { return String((e as Error).message); } })()}</pre>
              </Show>
            </div>
          )}</For>
          <Show when={wan().mode === 'pppoe'}>
            <label class="l0-card-sub" style={{ display: 'flex', 'flex-direction': 'column', gap: '4px' }}>PPPoE password (again)
              <input style={field} type="password" autocomplete="off" value={wan().pppoePass === '(current)' ? '' : wan().pppoePass} onInput={(e) => setWan({ ...wan(), pppoePass: e.currentTarget.value })} /></label>
          </Show>
          <label class="l0-card-sub" style={{ display: 'flex', 'flex-direction': 'column', gap: '4px' }}>Wi-Fi password (again)
            <input style={field} type="password" autocomplete="new-password" value={wifi().psk} onInput={(e) => setWifi({ ...wifi(), psk: e.currentTarget.value })} /></label>
          <Show when={bundleProblems().length > 0}>
            <ul style={{ margin: 0, 'padding-left': '18px' }} aria-label="Bundle problems"><For each={bundleProblems()}>{(e) => <li class="plan-diff-warn">{e}</li>}</For></ul>
          </Show>
          <p class="pcard-note" aria-label="Device binding">{deviceIdHex() ? `Bound to this device (id ${deviceIdHex().slice(0, 8)}…): any other device refuses it.` : 'Not bound to a device: this device does not report an identity, so the bundle would be accepted by any device that trusts your key.'}</p>
          <p class="pcard-note" aria-label="At rest">{restNote()}</p>
          <Show when={ownerKey()} fallback={<SigningKeyPanel compact />}>
            <Show when={keyMismatch()}><MismatchNote /></Show>
            <button class="hp-btn hp-btn--primary" disabled={bundleProblems().length > 0 || keyMismatch()} onClick={() => void applyBundle()}>{takesBundles() ? 'Sign and upload the bundle' : 'Sign the bundle'}</button>
          </Show>
        </Show>
        <Show when={bStep() === 'done'}>
          <Show when={bLive()} fallback={<>
            <p class="go-state--up" style={{ margin: 0, 'font-weight': 600 }}>✓ Staged as a trial for the next restart</p>
            <p class="l0-card-sub">After the restart a banner shows the trial with a countdown: keep it, or let it go back by itself.</p>
            <RestartButton primary />
          </>}>
            <p class="go-state--up" style={{ margin: 0, 'font-weight': 600 }}>✓ Applied live: on trial now</p>
            <p class="l0-card-sub">No restart needed. The banner at the top shows the countdown{bNeedsConfirm() ? ': press Keep it within the window, or the device switches back by itself.' : ': the device keeps it once the internet works, or switches back by itself.'}</p>
          </Show>
        </Show>
        <Show when={bStep() === 'files' && bFiles()}>
          <p class="go-state--up" style={{ margin: 0 }}>✓ Signed in the browser</p>
          <p class="l0-card-sub">{sample() ? 'Preview: no device is connected.' : 'This device does not take configuration bundles yet.'} The signed bundle can be checked with <code>hqcfg.py verify</code>.</p>
          <div class="l0-card-foot">
            <button class="hp-btn" onClick={() => download('HQCFG1.BIN', bFiles()!.bin)}>Download HQCFG1.BIN</button>
            <button class="hp-btn" onClick={() => download('HQCFG1.SIG', bFiles()!.sig)}>Download HQCFG1.SIG</button>
          </div>
        </Show>
        <Show when={bMsg()}><p class="pro-sub" role="status" style={{ margin: 0 }}>{bMsg()}</p></Show>
      </Drawer>
    </AppShell>
  );
};

export default AdvancedConfigApp;
