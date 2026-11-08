/**
 * NetworkLive — My Network on a heqk device: the real device inventory (DHCP leases on the AP image),
 * grouped by the policy the operator-signed DEVICES.TXT gives each device (parity G9 / G13).
 *
 * Read-only by design: device policy is durable configuration, so it changes only by re-signing DEVICES.TXT
 * (ADR 0053 S7). The one session action is a time-bounded "Isolate 1 h" (ADR 0053 `isolate`: owner key,
 * expires by itself, DHCP/DNS keep working).
 */
import { type Component, For, Show, createMemo, createSignal } from 'solid-js';
import TopBar from './TopBar';
import { setCopilotOpen } from '../store/mock';
import { devices } from '../store/obsLive';
import { formatTime, type DeviceRow } from '../store/api';
import { promptAndRun } from '../store/actions';

const GROUPS: { key: string; label: string; blurb: string }[] = [
  { key: 'full', label: 'Full access', blurb: 'Internet and the local network.' },
  { key: 'internet_only', label: 'Internet only', blurb: 'No access to other local devices or Mission Control.' },
  { key: 'lan_only', label: 'Local only', blurb: 'No internet.' },
  { key: 'quarantine', label: 'Quarantine', blurb: 'DHCP and DNS only.' },
];

function groupOf(d: DeviceRow): string {
  return d.policy && GROUPS.some((g) => g.key === d.policy) ? d.policy : 'full';
}

const NetworkLive: Component = () => {
  const [msg, setMsg] = createSignal('');
  const grouped = createMemo(() => {
    const m = new Map<string, DeviceRow[]>();
    for (const d of devices()) {
      const k = groupOf(d);
      m.set(k, [...(m.get(k) ?? []), d]);
    }
    return m;
  });
  const active = createMemo(() => devices().filter((d) => d.active !== false).length);
  /** Other entries with the same high-confidence identity: one device seen under rotating private MACs. */
  const twins = (d: DeviceRow): string => {
    if (!d.identity || d.identity_basis !== 'high') return '';
    return devices().filter((o) => o !== d && o.identity === d.identity).map((o) => o.ip).join(', ');
  };
  return (
    <>
      <TopBar onOpenCopilot={() => setCopilotOpen(true)} />
      <main class="main-content net-page" style={{ 'max-width': '1100px' }}>
        <div class="net-page-header">
          <a href="/" class="net-back-link" aria-label="Back to Mission Control">← Mission Control</a>
          <div class="net-page-title-row">
            <div>
              <h1 class="net-page-title">My Network</h1>
              <div class="net-page-subtitle">
                {devices().length} devices known to this device · {active()} with a live lease · grouped by the policy in your signed DEVICES.TXT
              </div>
            </div>
          </div>
        </div>
        <Show when={msg()}>
          <div class="shield-scope-note" role="status">{msg()}</div>
        </Show>
        <Show when={devices().length > 0} fallback={<div class="shield-empty">No devices have joined yet.</div>}>
          <For each={GROUPS.filter((g) => (grouped().get(g.key) ?? []).length > 0)}>
            {(g) => (
              <section class="net-zone" aria-label={g.label}>
                <h2 class="net-zone-title">{g.label} <span class="net-zone-count">{(grouped().get(g.key) ?? []).length}</span></h2>
                <div class="net-zone-blurb">{g.blurb}</div>
                <ul class="shield-list">
                  <For each={grouped().get(g.key) ?? []}>
                    {(d) => (
                      <li class="shield-list-row">
                        <span class="shield-domain">{d.label || d.hostname || d.model || d.ip}</span>
                        <span>
                          {d.ip}{d.mac ? ` · ${d.mac}` : ''}{d.private_mac ? ' (private address)' : ''}{d.os ? ` · ${d.os}` : ''}
                          {d.model || d.vendor || d.category ? ` · ${[d.model, d.vendor, d.category].filter(Boolean).join(' · ')}` : ''}
                          {d.confidence ? ` (${d.confidence}% via ${d.id_source})` : ''}
                          {twins(d) ? ` · same device as ${twins(d)} (private address rotated)` : ''}
                          {' · last seen '}{formatTime(d.last_seen)}{d.active === false ? ' · lease expired' : ''}
                        </span>
                        <Show when={d.mac && g.key !== 'quarantine'}>
                          <button class="shield-remove" title="Put this device in quarantine for 1 hour (owner key; DHCP and DNS keep working; expires on its own)"
                            onClick={async () => setMsg(await promptAndRun('isolate', d.mac!, 3600))}>Isolate 1 h</button>
                        </Show>
                      </li>
                    )}
                  </For>
                </ul>
              </section>
            )}
          </For>
        </Show>
        <div class="shield-scope-note">
          Device policy is set in DEVICES.TXT signed with your operator key — change it by re-signing. "Isolate 1 h" is temporary
          and expires by itself.
        </div>
      </main>
    </>
  );
};

export default NetworkLive;
