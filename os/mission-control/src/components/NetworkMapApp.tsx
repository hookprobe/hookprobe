/**
 * NetworkMapApp — My Network (Pillar 2) Solid island.
 *
 * Route: /network/map  (Astro static page, Solid client:load island)
 *
 * Spec references:
 *   - docs/research/v2-customer-experience.md §3.2 (Pillar 2 — My Network)
 *   - docs/architecture/MissionControl.md §6b (Network / Gateway workspace)
 *   - V1: bubbles/views.py · sdn/device_policies.py · lib/mdns_resolver.py
 *
 * Reactive props pattern (SolidJS):
 *   Signal accessors are passed as () => T props so child components can
 *   create their own createMemo derivations and stay reactive when the
 *   parent signals change (e.g. after applyChange()). Static values are NOT
 *   passed as reactive props — only signals that the child needs to derive
 *   from or conditionally render based on.
 *
 * Interactions:
 *   - Click device tile → DeviceDrawer opens (slide-in right panel)
 *   - Move device: drawer "Move to" select → PlanDiff strip → Apply
 *   - Apple ecosystem: zone header toggle → PlanDiff strip → Apply
 *   - Change policy / trust / reach: drawer → PlanDiff strip → Apply
 *   - Block now: drawer → PlanDiff strip → Apply (moves to Quarantine)
 *   - AI suggestion chip: Accept (move) or Dismiss
 *   - Pin: immediate, no confirm (local preference, not a network policy)
 *
 * Click-count for "let Apple TV be visible to Family, hidden from Guests":
 *   1. Landing → My Network pillar card "Open map"
 *   2. Click Apple ecosystem toggle on Smart Home zone
 *   3. Click Apply on PlanDiff strip
 *   = 3 clicks total (vs 5–8 on a router admin UI, per spec §4)
 *
 * Click-count for "move Apple TV to Family zone":
 *   1. Landing → Open map
 *   2. Click Apple TV tile → drawer opens
 *   3. "Move to" → select Family
 *   4. Apply
 *   = 4 clicks total
 *
 * Zero new dependencies — pure Solid + SVG/CSS.
 */

import {
  type Component, type Accessor,
  createSignal, createMemo, For, Show, batch,
} from 'solid-js';
import TopBar from './TopBar';
import CommandPalette from './CommandPalette';
import { setCopilotOpen, setCopilotQuery, copilotOpen, copilotQuery } from '../store/mock';
import {
  type Device, type Zone, type NetworkPolicy, type TrustLevel, type PendingChange,
  POLICY_LABELS, DEVICE_ICONS, INITIAL_ZONES, INITIAL_DEVICES, buildPendingChange,
} from '../store/networkMock';

// ── Status helpers ────────────────────────────────────────────────────────────

function statusDotClass(status: Device['status']): string {
  return status === 'online' ? 'dot--green' : status === 'idle' ? 'dot--amber' : 'dot--grey';
}

function statusLabel(status: Device['status']): string {
  return status === 'online' ? 'Online' : status === 'idle' ? 'Idle' : 'Offline';
}

function policyClass(p: NetworkPolicy): string {
  if (p === 'quarantine')    return 'policy--red';
  if (p === 'internet-only') return 'policy--amber';
  if (p === 'lan-only')      return 'policy--grey';
  if (p === 'smart-home')    return 'policy--blue';
  return 'policy--green';
}

function zoneAccentClass(type: Zone['type']): string {
  if (type === 'quarantine') return 'zone--quarantine';
  if (type === 'guests')     return 'zone--guests';
  if (type === 'kids')       return 'zone--kids';
  if (type === 'smart-home') return 'zone--smarthome';
  return 'zone--family';
}

// ── DeviceTile ────────────────────────────────────────────────────────────────
// Props: `selected` is an Accessor so the tile reacts when selectedId changes
// without needing the parent's For to re-run.

interface DeviceTileProps {
  device:   Device;
  selected: Accessor<boolean>;   // () => boolean — reactive
  onSelect: () => void;
}

const DeviceTile: Component<DeviceTileProps> = (props) => (
  <button
    class={`net-device-tile${props.selected() ? ' net-device-tile--selected' : ''}`}
    onClick={props.onSelect}
    aria-label={`${props.device.name} — ${statusLabel(props.device.status)} — ${POLICY_LABELS[props.device.policy]}`}
    aria-pressed={props.selected()}
  >
    <span class="tile-icon" aria-hidden="true">{DEVICE_ICONS[props.device.type]}</span>

    <div class="tile-body">
      <div class="tile-name">
        {props.device.name}
        {props.device.isApple && (
          <span class="tile-apple-chip" aria-label="Apple linked">Apple ✦</span>
        )}
        {props.device.isPinned && (
          <span class="tile-pin" aria-label="Pinned to this zone" title="Pinned">📌</span>
        )}
      </div>

      <div class="tile-meta">
        <span class={`status-dot ${statusDotClass(props.device.status)}`} aria-hidden="true" />
        <span class="tile-status">{statusLabel(props.device.status)}</span>
        <span class="tile-sep" aria-hidden="true">·</span>
        <span class={`tile-policy ${policyClass(props.device.policy)}`}>
          {POLICY_LABELS[props.device.policy]}
        </span>
      </div>
    </div>

    <svg class="tile-chevron" aria-hidden="true" width="12" height="12" viewBox="0 0 24 24"
      fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M9 18l6-6-6-6" />
    </svg>
  </button>
);

// ── ZoneCard ──────────────────────────────────────────────────────────────────
// `devices` is passed as an Accessor so ZoneCard can create its own filtered
// createMemo and react when the parent `devices` signal changes (e.g. after
// a device is moved between zones).

interface ZoneCardProps {
  zone:           Zone;
  devices:        Accessor<Device[]>;    // () => Device[] — reactive
  selectedId:     Accessor<string|null>; // () => string|null — reactive
  hasPending:     Accessor<boolean>;     // () => boolean — reactive
  onSelectDevice: (id: string) => void;
  onToggleApple:  (zone: Zone) => void;
}

const ZoneCard: Component<ZoneCardProps> = (props) => {
  // Derives from the parent signal — reacts when devices() changes
  const zoneDevices = createMemo(() =>
    props.devices().filter(d => d.zoneId === props.zone.id)
  );
  const onlineCount = createMemo(() =>
    zoneDevices().filter(d => d.status === 'online').length
  );

  return (
    <div class={`net-zone-card ${zoneAccentClass(props.zone.type)}`}
      role="region"
      aria-label={`${props.zone.name} zone — ${zoneDevices().length} devices`}
    >
      {/* Terminal title bar — hookprobe@edge ~ <zone> */}
      <div class="hp-terminal-bar net-zone-bar">
        <span class="hp-dot red" aria-hidden="true" />
        <span class="hp-dot yellow" aria-hidden="true" />
        <span class="hp-dot green" aria-hidden="true" />
        <span class="hp-terminal-title">hookprobe@edge ~ {props.zone.type}</span>
      </div>

      {/* Zone header */}
      <div class="zone-header">
        <div class="zone-header-left">
          <span class="zone-name">{props.zone.name}</span>
          {props.zone.isSystem && (
            <span class="zone-system-badge" aria-label="System zone — cannot be deleted">🔒</span>
          )}
          {props.zone.isPinned && (
            <span class="zone-pin" aria-label="Zone pinned" title="Pinned">📌</span>
          )}
          <span class="zone-count">{onlineCount()}/{zoneDevices().length}</span>
        </div>

        {/* Apple ecosystem toggle — hidden for quarantine/guests */}
        <Show when={props.zone.type !== 'quarantine' && props.zone.type !== 'guests'}>
          <button
            class={`zone-apple-toggle ${props.zone.appleEcosystem ? 'zone-apple-toggle--on' : ''}`}
            onClick={() => props.onToggleApple(props.zone)}
            disabled={props.hasPending()}
            aria-label={`Apple ecosystem ${props.zone.appleEcosystem ? 'on' : 'off'} for ${props.zone.name} zone — click to toggle`}
            title={props.zone.appleEcosystem
              ? 'AirPlay, HomeKit, AirDrop active — click to turn off'
              : 'Turn on AirPlay, HomeKit, AirDrop for this zone'}
          >
            <span aria-hidden="true">Apple ✦</span>
            <span class="toggle-pill" aria-hidden="true">
              {props.zone.appleEcosystem ? 'on' : 'off'}
            </span>
          </button>
        </Show>
      </div>

      {/* Zone description */}
      <div class="zone-desc">{props.zone.description}</div>

      {/* Quarantine note */}
      <Show when={props.zone.type === 'quarantine' && zoneDevices().length > 0}>
        <div class="zone-quarantine-note" role="note">
          We isolated {zoneDevices().length === 1 ? 'this device' : `these ${zoneDevices().length} devices`} for
          you — no internet, no LAN.
        </div>
      </Show>

      {/* Device tiles */}
      <Show
        when={zoneDevices().length > 0}
        fallback={
          <div class="zone-empty">
            No devices in this zone.
            <span class="zone-empty-hint"> Move a device here or use ⌘K.</span>
          </div>
        }
      >
        <div class="zone-devices">
          <For each={zoneDevices()}>
            {(device) => (
              <DeviceTile
                device={device}
                selected={createMemo(() => props.selectedId() === device.id)}
                onSelect={() => props.onSelectDevice(device.id)}
              />
            )}
          </For>
        </div>
      </Show>
    </div>
  );
};

// ── DeviceDrawer ──────────────────────────────────────────────────────────────

interface DrawerProps {
  device:     Accessor<Device>;       // reactive — reflects applied changes
  zones:      Accessor<Zone[]>;
  hasPending: Accessor<boolean>;
  onClose:    () => void;
  onChange:   (change: PendingChange) => void;
  onPin:      (deviceId: string) => void;
}

const DeviceDrawer: Component<DrawerProps> = (props) => {
  const d = props.device;  // shorthand; still an accessor

  const currentZone = createMemo(() =>
    props.zones().find(z => z.id === d().zoneId) ?? props.zones()[0]!
  );

  const moveToOptions = createMemo(() =>
    props.zones().filter(z => z.id !== d().zoneId)
  );

  function handleMoveTo(toZoneId: string) {
    if (!toZoneId) return;
    const toZone = props.zones().find(z => z.id === toZoneId);
    if (!toZone) return;
    props.onChange(buildPendingChange('move-device', {
      device: d(), fromZone: currentZone(), toZone,
    }));
  }

  function handleTrust(trust: TrustLevel) {
    if (trust === d().trust) return;
    if (trust === 'blocked') {
      props.onChange(buildPendingChange('block-device', { device: d() }));
      return;
    }
    props.onChange(buildPendingChange('change-trust', { device: d(), newTrust: trust }));
  }

  function handlePolicy(policy: NetworkPolicy) {
    if (policy === d().policy) return;
    if (policy === 'quarantine') {
      props.onChange(buildPendingChange('block-device', { device: d() }));
      return;
    }
    props.onChange(buildPendingChange('change-policy', { device: d(), newPolicy: policy }));
  }

  function handleReach(reach: 'internet' | 'home-devices' | 'smart-home', newValue: boolean) {
    props.onChange(buildPendingChange('change-reach', { device: d(), reach, newValue }));
  }

  return (
    <div class="net-drawer" role="dialog" aria-modal="true"
      aria-label={`Device details: ${d().name}`}>
      <div class="drawer-inner">

        {/* Header */}
        <div class="drawer-header">
          <div class="drawer-title-row">
            <span class="drawer-icon" aria-hidden="true">{DEVICE_ICONS[d().type]}</span>
            <div class="drawer-title-block">
              <h2 class="drawer-name">{d().name}</h2>
              <div class="drawer-fingerprint">{d().fingerprint}</div>
            </div>
            <button class="drawer-close" onClick={props.onClose}
              aria-label="Close device details">
              <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24"
                fill="none" stroke="currentColor" stroke-width="2"
                stroke-linecap="round" stroke-linejoin="round">
                <path d="M18 6 6 18M6 6l12 12" />
              </svg>
            </button>
          </div>

          <div class="drawer-status-row">
            <span class={`status-dot ${statusDotClass(d().status)}`} aria-hidden="true" />
            <span class="drawer-status">{statusLabel(d().status)}</span>
            <span class="drawer-sep" aria-hidden="true">·</span>
            <span class="drawer-zone-pill">{currentZone()?.name ?? '—'}</span>
            <span class="drawer-sep" aria-hidden="true">·</span>
            <span class="drawer-last-seen">seen {d().lastSeen}</span>
          </div>
        </div>

        <div class="drawer-body">

          {/* Apple linked chip */}
          <Show when={d().isApple}>
            <div class="drawer-apple-row">
              <span class="drawer-apple-chip">Apple ✦ linked</span>
              <span class="drawer-apple-note">
                AirPlay, HomeKit &amp; AirDrop active within this zone
              </span>
            </div>
          </Show>

          {/* Trust */}
          <div class="drawer-section">
            <div class="drawer-section-label">Trust</div>
            <div class="drawer-trust-group" role="group" aria-label="Trust level">
              {(['trusted', 'normal', 'guest', 'blocked'] as TrustLevel[]).map((t) => (
                <button
                  class={`trust-btn ${d().trust === t ? 'trust-btn--active' : ''}`}
                  onClick={() => handleTrust(t)}
                  disabled={props.hasPending()}
                  aria-pressed={d().trust === t}
                >
                  {t.charAt(0).toUpperCase() + t.slice(1)}
                </button>
              ))}
            </div>
          </div>

          {/* Can reach */}
          <div class="drawer-section">
            <div class="drawer-section-label">Can reach</div>
            <div class="drawer-reach-list">
              {(
                [
                  { key: 'internet',     label: 'Internet',           val: () => d().canReachInternet },
                  { key: 'home-devices', label: 'Other home devices', val: () => d().canReachHomeDevices },
                  { key: 'smart-home',   label: 'Smart home devices', val: () => d().canReachSmartHome },
                ] as { key: 'internet' | 'home-devices' | 'smart-home'; label: string; val: Accessor<boolean> }[]
              ).map(({ key, label, val }) => (
                <label class="reach-row">
                  <input
                    type="checkbox"
                    class="reach-checkbox"
                    checked={val()}
                    disabled={props.hasPending() || d().policy === 'quarantine'}
                    onChange={(e) => handleReach(key, e.currentTarget.checked)}
                    aria-label={`${label}: ${val() ? 'allowed' : 'blocked'}`}
                  />
                  <span class="reach-label">{label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Policy */}
          <div class="drawer-section">
            <div class="drawer-section-label">Access policy</div>
            <select
              class="drawer-policy-select"
              value={d().policy}
              disabled={props.hasPending() || d().policy === 'quarantine'}
              onChange={(e) => handlePolicy(e.currentTarget.value as NetworkPolicy)}
              aria-label="Access policy"
            >
              {(['full', 'internet-only', 'lan-only', 'smart-home'] as NetworkPolicy[]).map((p) => (
                <option value={p}>{POLICY_LABELS[p]}</option>
              ))}
            </select>
          </div>

          {/* Move to zone */}
          <Show when={d().policy !== 'quarantine'}>
            <div class="drawer-section">
              <div class="drawer-section-label">Zone</div>
              <div class="drawer-zone-row">
                <span class="drawer-current-zone">{currentZone()?.name}</span>
                <select
                  class="drawer-move-select"
                  value=""
                  disabled={props.hasPending()}
                  onChange={(e) => {
                    handleMoveTo(e.currentTarget.value);
                    e.currentTarget.value = '';
                  }}
                  aria-label="Move to zone"
                >
                  <option value="" disabled>Move to…</option>
                  <For each={moveToOptions()}>
                    {(z) => <option value={z.id}>{z.name}</option>}
                  </For>
                </select>
              </div>
            </div>
          </Show>

          {/* Pin toggle */}
          <div class="drawer-section">
            <div class="drawer-section-label">Pin</div>
            <button
              class={`drawer-pin-btn ${d().isPinned ? 'drawer-pin-btn--active' : ''}`}
              onClick={() => props.onPin(d().id)}
              aria-pressed={d().isPinned}
              aria-label={d().isPinned
                ? 'Unpin — allow AI suggestions'
                : 'Pin — stay in this zone, ignore AI suggestions'}
            >
              📌 {d().isPinned ? 'Pinned to this zone' : 'Pin to this zone'}
            </button>
            <div class="drawer-pin-note">
              {d().isPinned
                ? 'AI suggestions ignored for this device — manual always wins.'
                : 'Pinning prevents AI from suggesting zone moves.'}
            </div>
          </div>

          {/* Activity link */}
          <a href="/observe/events" class="drawer-activity-link">
            See device activity
            <svg aria-hidden="true" width="11" height="11" viewBox="0 0 24 24" fill="none"
              stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M5 12h14M12 5l7 7-7 7" />
            </svg>
          </a>
        </div>

        {/* Footer: block/unblock */}
        <div class="drawer-footer">
          <Show when={d().policy !== 'quarantine'}>
            <button
              class="drawer-block-btn"
              disabled={props.hasPending()}
              onClick={() => props.onChange(buildPendingChange('block-device', { device: d() }))}
            >
              Block now
            </button>
          </Show>
          <Show when={d().policy === 'quarantine'}>
            <button
              class="drawer-unblock-btn"
              disabled={props.hasPending()}
              onClick={() => props.onChange(buildPendingChange('change-policy', {
                device: d(), newPolicy: 'internet-only',
              }))}
            >
              Unblock — move to Guests
            </button>
          </Show>
        </div>
      </div>
    </div>
  );
};

// ── PlanDiffPanel (fixed bottom strip) ───────────────────────────────────────

interface PlanDiffProps {
  change:   PendingChange;
  onApply:  () => void;
  onCancel: () => void;
}

const PlanDiffPanel: Component<PlanDiffProps> = (props) => {
  const [expanded, setExpanded] = createSignal(false);

  return (
    <div class="net-plan-strip" role="region"
      aria-label="Pending change — review before applying">
      <div class="plan-strip-inner">

        <div class="plan-strip-body">
          <div class="plan-strip-label">Pending change</div>
          <div class="plan-strip-summary">{props.change.summary}</div>

          {/* Collapsible technical details — Layer 2 jargon lives here only */}
          <Show when={props.change.technical}>
            <button
              class="plan-tech-toggle"
              onClick={() => setExpanded(v => !v)}
              aria-expanded={expanded()}
              aria-controls="plan-tech-details"
            >
              Technical details
              <svg aria-hidden="true" width="12" height="12" viewBox="0 0 24 24" fill="none"
                stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                style={{ transform: expanded() ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }}>
                <path d="M6 9l6 6 6-6" />
              </svg>
            </button>
            <Show when={expanded()}>
              <div id="plan-tech-details" class="plan-tech-body" role="note">
                {props.change.technical}
              </div>
            </Show>
          </Show>
        </div>

        <div class="plan-strip-actions">
          <button class="plan-cancel-btn" onClick={props.onCancel}
            aria-label="Cancel — discard this change">
            Cancel
          </button>
          <button class="plan-apply-btn" onClick={props.onApply}
            aria-label="Apply — commit this change">
            Apply
            <svg aria-hidden="true" width="13" height="13" viewBox="0 0 24 24" fill="none"
              stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M20 6 9 17l-5-5" />
            </svg>
          </button>
        </div>

      </div>
    </div>
  );
};

// ── AiSuggestionBanner ────────────────────────────────────────────────────────

interface SuggestionProps {
  text:      string;
  onAccept:  () => void;
  onDismiss: () => void;
}

const AiSuggestionBanner: Component<SuggestionProps> = (props) => (
  <div class="net-suggestion" role="note" aria-label="AI suggestion">
    <span class="suggestion-dot" aria-hidden="true" />
    <span class="suggestion-text">{props.text}</span>
    <div class="suggestion-actions">
      <button class="suggestion-yes" onClick={props.onAccept}>Yes</button>
      <button class="suggestion-no" onClick={props.onDismiss}>Not now</button>
    </div>
  </div>
);

// ── NetworkMapApp (root island) ───────────────────────────────────────────────

const NetworkMapApp: Component = () => {
  // Component-local signals — avoids SSR/hydration sharing issues between pages.
  const [zones,      setZones]      = createSignal<Zone[]>(INITIAL_ZONES);
  const [devices,    setDevices]    = createSignal<Device[]>(INITIAL_DEVICES);
  const [selectedId, setSelectedId] = createSignal<string | null>(null);
  const [pending,    setPending]    = createSignal<PendingChange | null>(null);
  const [dismissed,  setDismissed]  = createSignal<Set<string>>(new Set());
  const [view,       setView]       = createSignal<'map' | 'list'>('map');

  // ── Derived ───────────────────────────────────────────────────────────────

  const selectedDevice = createMemo<Device | null>(() => {
    const id = selectedId();
    return id ? (devices().find(d => d.id === id) ?? null) : null;
  });

  const hasPending = createMemo(() => pending() !== null);

  const totalOnline  = createMemo(() => devices().filter(d => d.status === 'online').length);
  const totalDevices = createMemo(() => devices().length);

  const activeSuggestion = createMemo(() => {
    const dis = dismissed();
    for (const z of zones()) {
      if (z.suggestion && !dis.has(z.suggestion.id)) return z.suggestion;
    }
    return null;
  });

  // ── Handlers ─────────────────────────────────────────────────────────────

  function selectDevice(id: string) {
    setSelectedId(prev => (prev === id ? null : id));
  }

  function closeDrawer() { setSelectedId(null); }

  function enqueueChange(change: PendingChange) {
    // Close drawer so the plan strip is fully visible and not obscured
    setPending(change);
    setSelectedId(null);
  }

  function cancelChange() { setPending(null); }

  function applyChange() {
    const ch = pending();
    if (!ch) return;

    batch(() => {
      switch (ch.kind) {

        case 'move-device': {
          if (!ch.deviceId || !ch.toZoneId) break;
          const toZone = zones().find(z => z.id === ch.toZoneId)!;
          const policyMap: Record<Zone['type'], NetworkPolicy> = {
            family:       'full',
            kids:         'internet-only',
            'smart-home': 'smart-home',
            guests:       'internet-only',
            quarantine:   'quarantine',
            custom:       'full',
          };
          setDevices(prev => prev.map(d => {
            if (d.id !== ch.deviceId) return d;
            const p = policyMap[toZone.type];
            return {
              ...d,
              zoneId:              ch.toZoneId!,
              policy:              p,
              canReachInternet:    p !== 'quarantine' && p !== 'lan-only',
              canReachHomeDevices: p === 'full',
              canReachSmartHome:   p === 'full' || p === 'smart-home',
              trust:               toZone.type === 'quarantine' ? 'blocked'
                                 : toZone.type === 'guests'     ? 'guest'
                                 : d.trust,
              isPinned: false,
            };
          }));
          break;
        }

        case 'toggle-apple-ecosystem': {
          if (!ch.zoneId) break;
          setZones(prev => prev.map(z =>
            z.id === ch.zoneId ? { ...z, appleEcosystem: !z.appleEcosystem } : z
          ));
          break;
        }

        case 'change-policy': {
          if (!ch.deviceId || !ch.newPolicy) break;
          const p = ch.newPolicy;
          // Move to guests if unblocking from quarantine
          const toZoneId = p === 'internet-only' ? 'guests' : undefined;
          setDevices(prev => prev.map(d => {
            if (d.id !== ch.deviceId) return d;
            return {
              ...d,
              policy:              p,
              zoneId:              toZoneId ?? d.zoneId,
              trust:               toZoneId ? 'guest' : d.trust,
              canReachInternet:    p !== 'quarantine' && p !== 'lan-only',
              canReachHomeDevices: p === 'full',
              canReachSmartHome:   p === 'full' || p === 'smart-home',
            };
          }));
          break;
        }

        case 'change-trust': {
          if (!ch.deviceId || !ch.newTrust) break;
          setDevices(prev => prev.map(d =>
            d.id === ch.deviceId ? { ...d, trust: ch.newTrust! } : d
          ));
          break;
        }

        case 'change-reach': {
          if (!ch.deviceId) break;
          setDevices(prev => prev.map(d => {
            if (d.id !== ch.deviceId) return d;
            return {
              ...d,
              canReachInternet:    ch.reach === 'internet'     ? ch.newValue! : d.canReachInternet,
              canReachHomeDevices: ch.reach === 'home-devices' ? ch.newValue! : d.canReachHomeDevices,
              canReachSmartHome:   ch.reach === 'smart-home'   ? ch.newValue! : d.canReachSmartHome,
            };
          }));
          break;
        }

        case 'block-device': {
          if (!ch.deviceId) break;
          setDevices(prev => prev.map(d =>
            d.id !== ch.deviceId ? d : {
              ...d,
              zoneId:              'quarantine',
              policy:              'quarantine',
              trust:               'blocked',
              canReachInternet:    false,
              canReachHomeDevices: false,
              canReachSmartHome:   false,
              isPinned:            false,
            }
          ));
          break;
        }
      }

      setPending(null);
    });
  }

  function pinToggle(deviceId: string) {
    // Pin is immediate — local preference, no plan-as-diff needed
    setDevices(prev => prev.map(d =>
      d.id === deviceId ? { ...d, isPinned: !d.isPinned } : d
    ));
  }

  function onToggleApple(zone: Zone) {
    if (zone.isSystem) return;
    enqueueChange(buildPendingChange('toggle-apple-ecosystem', { zone }));
  }

  function dismissSuggestion(id: string) {
    setDismissed(prev => new Set([...prev, id]));
  }

  function acceptSuggestion() {
    const sug = activeSuggestion();
    if (!sug) return;
    const deviceId = sug.deviceIds[0];
    if (sug.targetZoneId && deviceId) {
      const device   = devices().find(d => d.id === deviceId);
      const toZone   = zones().find(z => z.id === sug.targetZoneId);
      const fromZone = device ? zones().find(z => z.id === device.zoneId) : undefined;
      if (device && toZone && fromZone) {
        enqueueChange(buildPendingChange('move-device', { device, fromZone, toZone }));
      }
    }
    dismissSuggestion(sug.id);
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <>
      <TopBar onOpenCopilot={() => setCopilotOpen(true)} />

      <main class="main-content net-page" style={{ 'max-width': '1200px' }}>

        {/* Page header */}
        <div class="net-page-header">
          <a href="/" class="net-back-link" aria-label="Back to Mission Control">
            <svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none"
              stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M19 12H5M12 19l-7-7 7-7" />
            </svg>
            Mission Control
          </a>

          <div class="net-page-title-row">
            <div>
              <h1 class="net-page-title">My Network</h1>
              <div class="net-page-subtitle">
                {totalOnline()} of {totalDevices()} devices online
                <span class="net-page-sep" aria-hidden="true"> · </span>
                {zones().length} zones
              </div>
            </div>

            <div class="net-view-toggle" role="group" aria-label="View mode">
              <button
                class={`view-toggle-btn ${view() === 'map' ? 'view-toggle-btn--active' : ''}`}
                onClick={() => setView('map')} aria-pressed={view() === 'map'}>
                Map
              </button>
              <button
                class={`view-toggle-btn ${view() === 'list' ? 'view-toggle-btn--active' : ''}`}
                onClick={() => setView('list')} aria-pressed={view() === 'list'}>
                List
              </button>
            </div>
          </div>
        </div>

        {/* AI suggestion banner */}
        <Show when={activeSuggestion()}>
          {(sug) => (
            <AiSuggestionBanner
              text={sug().text}
              onAccept={acceptSuggestion}
              onDismiss={() => dismissSuggestion(sug().id)}
            />
          )}
        </Show>

        {/* Zone grid (Map view) */}
        <Show when={view() === 'map'}>
          <div class="net-zone-grid">
            <For each={zones()}>
              {(zone) => (
                <ZoneCard
                  zone={zone}
                  devices={devices}          // pass accessor — ZoneCard creates its own memo
                  selectedId={selectedId}    // pass accessor — DeviceTile reacts to selection
                  hasPending={hasPending}    // pass accessor — buttons disable/enable reactively
                  onSelectDevice={selectDevice}
                  onToggleApple={onToggleApple}
                />
              )}
            </For>
          </div>
        </Show>

        {/* List view */}
        <Show when={view() === 'list'}>
          <div class="net-list-view">
            <For each={devices()}>
              {(device) => {
                const zoneName = createMemo(() =>
                  zones().find(z => z.id === device.zoneId)?.name ?? '—'
                );
                return (
                  <button
                    class={`net-list-row${selectedId() === device.id ? ' net-list-row--selected' : ''}`}
                    onClick={() => selectDevice(device.id)}
                    aria-label={`${device.name} — ${statusLabel(device.status)}`}
                  >
                    <span class="list-icon" aria-hidden="true">{DEVICE_ICONS[device.type]}</span>
                    <span class="list-name">
                      {device.name}
                      {device.isApple && <span class="tile-apple-chip">Apple ✦</span>}
                    </span>
                    <span class="list-zone">{zoneName()}</span>
                    <span class="list-status">
                      <span class={`status-dot ${statusDotClass(device.status)}`} aria-hidden="true" />
                      {statusLabel(device.status)}
                    </span>
                    <span class={`list-policy tile-policy ${policyClass(device.policy)}`}>
                      {POLICY_LABELS[device.policy]}
                    </span>
                  </button>
                );
              }}
            </For>
          </div>
        </Show>

        {/* Usage hint */}
        <div class="net-footer-hint" aria-hidden="true">
          Click a device to see details and make changes. All changes show a preview before applying.
          <span class="net-footer-sep"> · </span>
          <button class="net-copilot-hint" onClick={() => setCopilotOpen(true)}>
            ⌘K — "put the new iPad in Kids"
          </button>
        </div>

      </main>

      {/* Device drawer */}
      <Show when={selectedDevice() !== null}>
        {/* selectedDevice() is non-null here — use accessor pattern to stay reactive */}
        <DeviceDrawer
          device={() => selectedDevice()!}
          zones={zones}
          hasPending={hasPending}
          onClose={closeDrawer}
          onChange={enqueueChange}
          onPin={pinToggle}
        />
      </Show>

      {/* Plan-as-diff strip */}
      <Show when={pending()}>
        {(ch) => (
          <PlanDiffPanel
            change={ch()}
            onApply={applyChange}
            onCancel={cancelChange}
          />
        )}
      </Show>

      {/* AI Copilot overlay */}
      <CommandPalette
        open={copilotOpen()}
        query={copilotQuery()}
        onQuery={setCopilotQuery}
        onClose={() => { setCopilotOpen(false); setCopilotQuery(''); }}
      />
    </>
  );
};

export default NetworkMapApp;
