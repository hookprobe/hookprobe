/**
 * NetworkLive — My Network (Layer 0 pillar; wireframe "My Network"): every device, grouped into the
 * zones the operator-signed DEVICES.TXT gives them (parity G9 / G13). Three views, each a real route:
 * Zones (/network/zones), Map (/network/map), List (/network/devices). Selecting a device opens the
 * shared Drawer.
 *
 * Durable changes (zone, name) are made by re-signing DEVICES.TXT (ADR 0053 S7), so those controls
 * are greyed with that reason. The one session action is a time-bounded "Isolate 1 h" (ADR 0053
 * `isolate`: owner key, expires by itself, DHCP/DNS keep working). With no device answering, the
 * sample devices below render under the Sample-data banner.
 */
import { type Component, For, Show, createMemo, createSignal, onMount } from 'solid-js';

import { devices, refetch as refetchDevices } from '../store/obsLive';
import { formatTime, type DeviceRow } from '../store/api';
import { promptAndRun } from '../store/actions';
import { tlsFor } from '../store/tlsLive';
import { substrate } from '../store/mock';
import { healthChecked } from '../store/health';
import AppShell, { normPath } from './AppShell';
import PageHeader from './PageHeader';
import Drawer from './Drawer';

const ZONES: { key: string; label: string; blurb: string }[] = [
  { key: 'full', label: 'Full access', blurb: 'Internet and the local network.' },
  { key: 'internet_only', label: 'Internet only', blurb: 'No access to other local devices or Mission Control.' },
  { key: 'lan_only', label: 'Local only', blurb: 'No internet.' },
  { key: 'quarantine', label: 'Quarantine', blurb: 'DHCP and DNS only.' },
];

const SIGNED = 'Zones and names come from your signed DEVICES.TXT. Re-sign it to change them.';

const now = Math.floor(Date.now() / 1000);
const S = (id: string, label: string, ip: string, policy: string, category: string, active = true): DeviceRow =>
  ({ id, ip, mac: `02:00:00:00:00:${id.padStart(2, '0')}`, first_seen: now - 86400 * 3, last_seen: now - 60, label, policy, category, active });
const SAMPLE: DeviceRow[] = [
  S('1', 'Alina MacBook', '10.66.0.21', 'full', 'Laptop'),
  S('2', 'Alina iPhone', '10.66.0.22', 'full', 'Phone'),
  S('3', 'Living room Apple TV', '10.66.0.23', 'full', 'TV'),
  S('4', "Ana's iPad", '10.66.0.31', 'internet_only', 'Tablet'),
  S('5', "Luca's Fire tablet", '10.66.0.32', 'internet_only', 'Tablet', false),
  S('6', 'Thermostat', '10.66.0.41', 'internet_only', 'Sensor'),
  S('7', 'Network printer', '10.66.0.51', 'lan_only', 'Printer'),
  S('8', 'Kitchen camera', '10.66.0.42', 'quarantine', 'Camera'),
];

function zoneOf(d: DeviceRow): string {
  return d.policy && ZONES.some((z) => z.key === d.policy) ? d.policy : 'full';
}
const nameOf = (d: DeviceRow) => d.label || d.mdns_name || d.hostname || d.mdns_model || d.model || d.ip;
const kindOf = (d: DeviceRow) => [d.mdns_model || d.model, d.vendor, d.category].filter(Boolean).join(' · ') || 'Device';

type View = 'zones' | 'map' | 'list';
function viewFor(path: string): View {
  return path.startsWith('/network/devices') ? 'list' : path.startsWith('/network/map') ? 'map' : 'zones';
}

const NetworkLive: Component<{ path?: string }> = (props) => {
  const [path, setPath] = createSignal(props.path ?? '/network/zones');
  const [msg, setMsg] = createSignal('');
  const [sel, setSel] = createSignal<string | null>(null);
  onMount(() => { setPath(normPath(location.pathname)); void refetchDevices(); });

  const sample = () => healthChecked() && !substrate();
  const rows = (): DeviceRow[] => (sample() ? SAMPLE : devices());
  const view = () => viewFor(path());
  const grouped = createMemo(() => {
    const m = new Map<string, DeviceRow[]>();
    for (const d of rows()) m.set(zoneOf(d), [...(m.get(zoneOf(d)) ?? []), d]);
    return m;
  });
  const active = createMemo(() => rows().filter((d) => d.active !== false).length);
  const selected = () => rows().find((d) => d.id === sel()) ?? null;
  /** Other entries with the same high-confidence identity: one device seen under rotating private MACs. */
  const twins = (d: DeviceRow): string => {
    if (!d.identity || d.identity_basis !== 'high') return '';
    return rows().filter((o) => o !== d && o.identity === d.identity).map((o) => o.ip).join(', ');
  };

  const DevButton: Component<{ d: DeviceRow }> = (p) => (
    <button class={`dev-btn${sel() === p.d.id ? ' is-selected' : ''}`} onClick={() => setSel(p.d.id)}>
      <span class={`dev-dot${p.d.active === false ? ' dev-dot--off' : ''}`} aria-hidden="true" />
      <span class="dev-name">{nameOf(p.d)}</span>
      <Show when={tlsFor(p.d.ip).ioc.length > 0 || tlsFor(p.d.ip).bypass.length > 0}><span class="dev-flag">check</span></Show>
      <Show when={p.d.active === false}><span class="sr-only">(offline)</span></Show>
    </button>
  );

  return (
    <AppShell path={props.path ?? '/network/zones'}>
      <main class="l0-main l0-main--wide" aria-label="My Network">
        <PageHeader
          title="My Network"
          status={<>{rows().length} devices known to this device · {active()} with a live lease · grouped by the policy in your signed DEVICES.TXT</>}
          segmentsLabel="View"
          segments={[
            { label: 'Zones', href: '/network/zones', active: view() === 'zones' },
            { label: 'Map', href: '/network/map', active: view() === 'map' },
            { label: 'List', href: '/network/devices', active: view() === 'list' },
          ]}
        />
        <Show when={msg()}><div class="hp-banner" style={{ margin: 0, border: '1px solid var(--hp-border)' }} role="status">{msg()}</div></Show>
        <p class="l0-card-sub" style={{ margin: 0 }}>Select a device to see it, isolate it for an hour, or check why it is flagged.</p>

        <Show when={rows().length > 0} fallback={<p class="l0-muted">No devices have joined yet.</p>}>
          <Show when={view() !== 'list'} fallback={
            <div class="l0-table-wrap">
              <table class="l0-table">
                <thead><tr><th scope="col">Device</th><th scope="col">Zone</th><th scope="col">Address</th><th scope="col">Last seen</th><th scope="col">Status</th></tr></thead>
                <tbody>
                  <For each={rows()}>{(d) => (
                    <tr>
                      <td><button class="dev-btn" style={{ border: 0, padding: 0, background: 'none', 'min-height': '32px' }} onClick={() => setSel(d.id)}>{nameOf(d)}</button></td>
                      <td>{ZONES.find((z) => z.key === zoneOf(d))?.label}</td>
                      <td class="l0-num" style={{ 'font-weight': 400 }}>{d.ip}</td>
                      <td>{formatTime(d.last_seen)}</td>
                      <td>{d.active === false ? 'Lease expired' : 'Online'}</td>
                    </tr>
                  )}</For>
                </tbody>
              </table>
            </div>
          }>
            <div class="zones">
              <For each={ZONES.filter((z) => view() === 'zones' || (grouped().get(z.key) ?? []).length > 0)}>{(z) => (
                <section class={`l0-card zone${(grouped().get(z.key) ?? []).length === 0 ? ' l0-card--dashed' : ''}`} aria-label={z.label}>
                  <div class="zone-head"><h2 class="zone-name">{z.label}</h2><span class="zone-count">{(grouped().get(z.key) ?? []).length}</span></div>
                  <p class="zone-rule">{z.blurb}</p>
                  <For each={grouped().get(z.key) ?? []} fallback={<p class="l0-card-sub">No devices in this zone.</p>}>{(d) => <DevButton d={d} />}</For>
                </section>
              )}</For>
            </div>
          </Show>
        </Show>
        <p class="l0-card-sub">
          Device policy is set in DEVICES.TXT signed with your operator key — change it by re-signing. "Isolate 1 h" is temporary and expires by itself.
        </p>
      </main>

      <Drawer open={!!selected()} title={selected() ? nameOf(selected()!) : ''} onClose={() => setSel(null)}
        crumb={selected() ? `${kindOf(selected()!)} · ${selected()!.active === false ? 'lease expired' : 'online'}` : ''}
        footer={
          <Show when={selected()}>
            <Show when={!sample() && selected()!.mac && zoneOf(selected()!) !== 'quarantine'} fallback={
              <Show when={sample()}><span class="gate-reason">Preview: on a device this isolates it for an hour.</span></Show>
            }>
              <button class="hp-btn hp-btn--primary" title="Quarantine for 1 hour (owner key; DHCP and DNS keep working; expires on its own)"
                onClick={async () => setMsg(await promptAndRun('isolate', selected()!.mac!, 3600))}>Isolate 1 h</button>
            </Show>
            <span class="gate gate--off" title={SIGNED}>
              <span class="gate-body" ref={(el) => el.setAttribute('inert', '')} aria-hidden="true"><button class="hp-btn">Move to zone</button> <button class="hp-btn">Rename</button></span>
              <span class="gate-reason" role="note">{SIGNED}</span>
            </span>
          </Show>
        }>
        <Show when={selected()}>{(d) => {
          const t = () => tlsFor(d().ip);
          return (
            <>
              <div class="dev-facts">
                <p class="l0-card-sub">Zone<b>{ZONES.find((z) => z.key === zoneOf(d()))?.label}</b></p>
                <p class="l0-card-sub">Identified as<b>{kindOf(d())}{d().confidence ? ` (${d().confidence}% via ${d().id_source})` : ''}</b></p>
                <p class="l0-card-sub">Address<b>{d().ip}</b></p>
                <p class="l0-card-sub">Hardware address<b>{d().mac ?? '—'}{d().private_mac ? ' (private)' : ''}</b></p>
                <p class="l0-card-sub">First seen<b>{formatTime(d().first_seen)}</b></p>
                <p class="l0-card-sub">Last seen<b>{formatTime(d().last_seen)}</b></p>
              </div>
              <Show when={d().os}><p class="l0-card-sub">System: {d().os}</p></Show>
              <Show when={d().ssdp_server}><p class="l0-card-sub">Announces: {d().ssdp_server}</p></Show>
              <Show when={twins(d())}><p class="l0-card-sub">Same device as {twins(d())} (its private address rotated).</p></Show>
              <Show when={t().fingerprints > 0}>
                <div>
                  <p class="l0-label">Encrypted connections</p>
                  <p class="net-tls">{t().fingerprints} client program{t().fingerprints > 1 ? 's' : ''}{t().names.length ? ` to ${t().names.slice(0, 4).join(', ')}${t().names.length > 4 ? ` +${t().names.length - 4}` : ''}` : ''}</p>
                  <Show when={t().ioc.length > 0}>
                    <p class="net-flag" style={{ margin: 0 }}>Known-bad TLS client: JA4 {t().ioc.map((x) => x.ja4).join(', ')} is on your signed threat-intel list (rule 125).</p>
                  </Show>
                  <Show when={t().bypass.length > 0}>
                    <p class="net-flag" style={{ margin: 0 }}>Bypassed Shield: connected to {[...new Set(t().bypass.map((x) => x.sni))].join(', ')}, a name Shield blocks (rule 126).</p>
                  </Show>
                </div>
              </Show>
              <a class="l0-link-row" href="/investigate/queue">See incidents for {d().ip} →</a>
            </>
          );
        }}</Show>
      </Drawer>
    </AppShell>
  );
};

export default NetworkLive;
