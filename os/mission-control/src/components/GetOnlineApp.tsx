/**
 * GetOnlineApp — Get Online (`/network/wan`), the Layer 0 pillar "Get me online, fix my Wi-Fi"
 * (wireframe "Get Online"; MissionControl.md §6b, the non-captive lens of the setup portal).
 *
 * On a device: the WAN + Wi-Fi the device actually applied (`/api/network`, `/api/health.wan`).
 * Configuration there is durable and signed (WIFI.TXT / WAN.TXT / POLICY.TXT), so change controls
 * are greyed with that reason — never a button that silently does nothing. Hardware limits come
 * from the manifest (`multi_wan`, `guest_ssid`) via Gate. No speed test is shown: the device has
 * no endpoint for one, and a number we cannot measure is not shown.
 */
import { type Component, Show, createSignal, onMount } from 'solid-js';
import { substrate, deviceStats } from '../store/mock';
import { networkView, networkState, startNetworkLive, type NetworkView } from '../store/networkLive';
import AppShell from './AppShell';
import PageHeader from './PageHeader';
import Gate from './Gate';
import WifiSheet from './WifiSheet';
import QrSheet from './QrSheet';

const SIGNED = 'Changes are signed with your signing key in this browser and apply live, without a restart, as a short trial: they keep themselves when everything works, or switch back by themselves.';

/** Shown only when no device answers (preview build), under the Sample-data banner. */
const SAMPLE: NetworkView = {
  available: true,
  wifi: { ssid: 'HookProbe-Home', source: 'signed WIFI.TXT', channel: 36, width_mhz: 80, security: 'WPA3' },
  wan: { up: true, mode: 'dhcp', ip: '192.0.2.10', gateway: '192.0.2.1', vlan: 0, clients: 21 },
  ipv6: { up: true, lan_prefix: '2001:db8:1:2::/64' },
  policy: { state: 'signed', generation: 4 },
  trust_anchor: { state: 'pinned', key: '0a1b2c3d' },
};

const MODE: Record<string, string> = { dhcp: 'automatic (DHCP)', static: 'static address', pppoe: 'PPPoE (username and password)' };

const GetOnlineApp: Component = () => {
  const [adv, setAdv] = createSignal(false);
  onMount(() => startNetworkLive());
  const [sheet, setSheet] = createSignal(false);
  const [qr, setQr] = createSignal(false);

  const device = () => substrate() === 'heqk';
  const n = (): NetworkView | null => (networkState() === 'absent' && !device() ? SAMPLE : networkView());
  const wan = () => n()?.wan ?? (deviceStats()?.wan ? { ...deviceStats()!.wan!, gateway: '', vlan: 0 } : undefined);
  const online = () => !!wan()?.up;

  const status = () => {
    if (!n() && !wan()) return 'Checking your connection…';
    if (!wan()) return 'This device is not acting as your internet gateway.';
    return online() ? 'You’re online. Internet and Wi-Fi look healthy.' : 'You’re offline. The internet line is down.';
  };

  return (
    <AppShell path="/network/wan">
      <main class="l0-main" aria-label="Get Online">
        <PageHeader
          title="Get Online"
          status={status()}
          segmentsLabel="Detail level"
          actions={
            <div class="l0-seg" role="group" aria-label="Detail level">
              <button class={`l0-seg-item${!adv() ? ' is-active' : ''}`} aria-pressed={!adv()} onClick={() => setAdv(false)} style={{ border: '0', background: !adv() ? undefined : 'none', font: 'inherit', cursor: 'pointer' }}>Simple</button>
              <button class={`l0-seg-item${adv() ? ' is-active' : ''}`} aria-pressed={adv()} onClick={() => setAdv(true)} style={{ border: '0', 'border-left': '1px solid var(--hp-border)', background: adv() ? undefined : 'none', font: 'inherit', cursor: 'pointer' }}>Advanced</button>
            </div>
          }
        />

        <section aria-label="Internet" style={{ display: 'flex', 'flex-direction': 'column', gap: '12px' }}>
          <p class="l0-label">Internet</p>
          <div class="l0-grid-2">
            <article class="l0-card">
              <div class="go-link-head">
                <span class="go-link-name">Main line</span>
                <Show when={wan()} fallback={<span class="l0-muted" style={{ 'font-size': '13px' }}>Not reported</span>}>
                  <span class={online() ? 'go-state--up' : 'go-state--down'}>{online() ? '● Online' : '○ Offline'}</span>
                </Show>
              </div>
              <Show when={wan()} fallback={<p class="l0-card-sub">The device has not reported an internet connection.</p>}>
                <p class="l0-card-sub">{MODE[wan()!.mode] ?? wan()!.mode} · address <span class="l0-num" style={{ 'font-weight': 500 }}>{wan()!.ip}</span></p>
                <p class="l0-card-sub">{wan()!.clients} device{wan()!.clients === 1 ? '' : 's'} online through it</p>
              </Show>
              <div class="l0-card-foot">
                <Gate cap="wan" reason="tooltip"><a class="hp-btn" href="/setup">Run setup again</a></Gate>
              </div>
            </article>
            <article class="l0-card l0-card--dashed">
              <div class="go-link-head"><span class="go-link-name">Backup line</span><span class="l0-muted" style={{ 'font-size': '13px' }}>Not set up</span></div>
              <p class="l0-card-sub">A second connection (LTE or another cable) keeps you online if the main one drops.</p>
              <div class="l0-card-foot"><Gate cap="multi_wan"><button class="hp-btn">Add backup</button></Gate></div>
            </article>
          </div>
        </section>

        <section aria-label="Wi-Fi" style={{ display: 'flex', 'flex-direction': 'column', gap: '12px' }}>
          <p class="l0-label">Wi-Fi</p>
          <div class="l0-grid-2">
            <article class="l0-card">
              <Show when={n()?.wifi} fallback={
                <>
                  <span class="go-link-name">No Wi-Fi network</span>
                  <p class="l0-card-sub">{n()?.available === false ? 'This device is not running a Wi-Fi network.' : 'Checking…'}</p>
                </>
              }>
                <span class="go-link-name">{n()!.wifi!.ssid}</span>
                <p class="l0-card-sub">{n()!.wifi!.width_mhz >= 80 || n()!.wifi!.channel > 14 ? '5 GHz' : '2.4 GHz'} · channel {n()!.wifi!.channel} · {n()!.wifi!.security}</p>
                <p class="l0-card-sub">From {n()!.wifi!.source}</p>
              </Show>
              <div class="l0-card-foot">
                <Show when={n()?.wifi} fallback={<a class="hp-btn hp-btn--primary" href="/network/wifi">Set up Wi-Fi</a>}>
                  <button class="hp-btn hp-btn--primary" onClick={() => setSheet(true)}>Change password</button>
                  <button class="hp-btn" onClick={() => setQr(true)}>Share QR</button>
                  <a class="hp-btn" href="/network/wifi">More Wi-Fi settings</a>
                </Show>
              </div>
              <p class="pcard-note">{SIGNED}</p>
            </article>
            <article class="l0-card">
              <span class="go-link-name">Guest Wi-Fi</span>
              <p class="l0-card-sub">A separate network for visitors: internet only, no access to your devices.</p>
              <div class="l0-card-foot"><Gate cap="guest_ssid"><button class="hp-btn">Turn on guest Wi-Fi</button></Gate></div>
              <p class="pcard-note" style={{ margin: 0 }}>This device runs one Wi-Fi network. Put visitors in an internet-only zone in <a href="/network/zones">My Network</a> instead.</p>
            </article>
          </div>
        </section>

        <Show when={adv()}>
          <section aria-label="Advanced" style={{ display: 'flex', 'flex-direction': 'column', gap: '12px' }}>
            <p class="l0-label">Change advanced settings · signed with your key, applied live as a trial</p>
            <div class="l0-grid-3">
              <a class="l0-card" href="/network/wan/advanced" style={{ 'text-decoration': 'none', color: 'inherit' }}><b>Internet →</b><span class="l0-card-sub">DHCP · Static · PPPoE · ISP VLAN · management VLAN</span></a>
              <a class="l0-card" href="/network/wifi" style={{ 'text-decoration': 'none', color: 'inherit' }}><b>Wi-Fi →</b><span class="l0-card-sub">Name · password · WPA2/WPA3 · channel</span></a>
              <a class="l0-card" href="/protect/policies" style={{ 'text-decoration': 'none', color: 'inherit' }}><b>Firewall and routes →</b><span class="l0-card-sub">Access lists · prefix lists · failover routes</span></a>
            </div>
            <p class="l0-label">Advanced · only what this device reports</p>
            <div class="go-adv">
              <Show when={wan()}><div><b>Connection type</b>{MODE[wan()!.mode] ?? wan()!.mode}</div></Show>
              <Show when={n()?.wan}><div><b>Gateway</b><span class="l0-num" style={{ 'font-weight': 500 }}>{n()!.wan!.gateway}</span></div></Show>
              <Show when={n()?.wan}><div><b>VLAN tag</b>{n()!.wan!.vlan ? n()!.wan!.vlan : 'None'}</div></Show>
              <Show when={n()?.ipv6}><div><b>IPv6</b>{n()!.ipv6!.up ? `On · ${n()!.ipv6!.lan_prefix}` : 'Off'}</div></Show>
              <Show when={n()?.management}><div><b>Management network</b>VLAN {n()!.management!.vlan} · {n()!.management!.ip}</div></Show>
              <Show when={n()?.policy}><div><b>Network policy</b>{n()!.policy!.state} · generation {n()!.policy!.generation}</div></Show>
              <Show when={n()?.trust_anchor}><div><b>Signing key</b>{n()!.trust_anchor!.state} · {n()!.trust_anchor!.key}</div></Show>
              <Show when={n()?.wifi}><div><b>Wi-Fi channel width</b>{n()!.wifi!.width_mhz} MHz</div></Show>
            </div>
            <p class="l0-card-sub">{n()?.changes ? `Changes are made through ${n()!.changes}.` : 'Any change here becomes a plan you approve before it applies.'}</p>
          </section>
        </Show>
      </main>
      <Show when={sheet()}><WifiSheet onClose={() => setSheet(false)} preview={!device()} /></Show>
      <Show when={qr() && n()?.wifi}><QrSheet ssid={n()!.wifi!.ssid} security={/wpa3/i.test(n()!.wifi!.security) && !/wpa2/i.test(n()!.wifi!.security) ? 'wpa3' : 'wpa2'} onClose={() => setQr(false)} /></Show>
    </AppShell>
  );
};

export default GetOnlineApp;
