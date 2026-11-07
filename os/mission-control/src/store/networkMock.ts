/**
 * HookProbe OS V2 — My Network (Pillar 2) mock data.
 *
 * Types map to the V1 data model:
 *   - Device  ← clients/views.py (NAC identity) + manual_assignments
 *   - Zone    ← bubbles/views.py (GroupType: FAMILY/GUEST/CORPORATE/SMART_HOME/QUARANTINE)
 *   - NetworkPolicy ← sdn/device_policies.py (FULL_ACCESS/INTERNET_ONLY/LAN_ONLY/SMART_HOME/ISOLATED)
 *   - appleEcosystem toggle ← mDNS reflection: _airplay/_raop/_hap/_companion-link scoped per VLAN
 *
 * Layer 0 contract: friendly labels on default path; technical artifacts in
 * PlanDiff "Technical details" collapse only (never on the default surface).
 *
 * Real implementation reads from /network/{zones,devices,trust} API (Rust/Axum).
 * ADR 0001: SSE fan-out for live status; state mutated locally on Apply (optimistic).
 */

// ── Types ────────────────────────────────────────────────────────────────────

export type NetworkPolicy = 'full' | 'internet-only' | 'lan-only' | 'smart-home' | 'quarantine';
export type TrustLevel    = 'trusted' | 'normal' | 'guest' | 'blocked';
export type DeviceType    = 'phone' | 'laptop' | 'tablet' | 'tv' | 'speaker' | 'camera'
                          | 'printer' | 'game' | 'hub' | 'watch';
export type DeviceStatus  = 'online' | 'idle' | 'offline';
export type ZoneType      = 'family' | 'kids' | 'smart-home' | 'guests' | 'quarantine' | 'custom';
export type ChangeKind    =
  | 'move-device'
  | 'toggle-apple-ecosystem'
  | 'change-policy'
  | 'change-trust'
  | 'change-reach'
  | 'block-device';

export interface Device {
  id:                  string;
  name:                string;
  type:                DeviceType;
  status:              DeviceStatus;
  zoneId:              string;
  policy:              NetworkPolicy;
  isPinned:            boolean;
  isApple:             boolean;         // Apple ✦ chip; mDNS-clustered
  canReachInternet:    boolean;
  canReachHomeDevices: boolean;
  canReachSmartHome:   boolean;
  trust:               TrustLevel;
  lastSeen:            string;
  fingerprint:         string;          // Fingerbank-style identity description
}

export interface AiSuggestion {
  id:            string;
  text:          string;
  deviceIds:     string[];
  targetZoneId?: string;
}

export interface Zone {
  id:              string;
  name:            string;
  type:            ZoneType;
  appleEcosystem:  boolean;            // mDNS reflection on/off per zone
  isPinned:        boolean;
  isSystem:        boolean;            // Quarantine: undeletable
  description:     string;
  suggestion?:     AiSuggestion;
}

export interface PendingChange {
  kind:       ChangeKind;
  deviceId?:  string;
  zoneId?:    string;
  fromZoneId?: string;
  toZoneId?:  string;
  newPolicy?: NetworkPolicy;
  newTrust?:  TrustLevel;
  reach?:     'internet' | 'home-devices' | 'smart-home';
  newValue?:  boolean;
  /** Plain-English summary shown on the default path (Layer 0). */
  summary:    string;
  /** Technical artifact detail shown only in the collapsible (Layer 2). */
  technical:  string;
}

// ── Lookup tables ─────────────────────────────────────────────────────────────

/** Layer-0 friendly policy labels — no jargon. */
export const POLICY_LABELS: Record<NetworkPolicy, string> = {
  'full':          'Full access',
  'internet-only': 'Internet only',
  'lan-only':      'Local only',
  'smart-home':    'Smart home',
  'quarantine':    'Quarantine',
};

/** Device-type icons (emoji — accessible with aria-hidden). */
export const DEVICE_ICONS: Record<DeviceType, string> = {
  phone:   '📱',
  laptop:  '💻',
  tablet:  '📱',
  tv:      '📺',
  speaker: '🔊',
  camera:  '📷',
  printer: '🖨',
  game:    '🎮',
  hub:     '💡',
  watch:   '⌚',
};

// ── Plan-as-diff builder ──────────────────────────────────────────────────────
//
// Generates the human-readable summary AND the collapsible technical details
// from a proposed change. This is the "understand AND control" pattern:
// customer sees the plain story; engineer can expand for the artifact list.

export function buildPendingChange(
  kind: ChangeKind,
  ctx: {
    device?:    Device;
    fromZone?:  Zone;
    toZone?:    Zone;
    zone?:      Zone;
    newPolicy?: NetworkPolicy;
    newTrust?:  TrustLevel;
    reach?:     'internet' | 'home-devices' | 'smart-home';
    newValue?:  boolean;
  },
): PendingChange {
  switch (kind) {

    case 'move-device': {
      const { device, fromZone, toZone } = ctx;
      const d = device!; const from = fromZone!; const to = toZone!;
      const isQuarantine = to.type === 'quarantine';
      const appleNote = d.isApple && to.appleEcosystem
        ? ` AirPlay and HomeKit will be available within ${to.name}.`
        : '';
      return {
        kind,
        deviceId:   d.id,
        fromZoneId: from.id,
        toZoneId:   to.id,
        summary: isQuarantine
          ? `${d.name} moved to Quarantine. No internet, no LAN access. Reversible.`
          : `${d.name} moved from ${from.name} to ${to.name}.${appleNote}`,
        technical: [
          `bubble: ${from.id} → ${to.id}`,
          `VLAN reassignment`,
          `OVS flow update (table-10/20 isolation)`,
          `device_policies → ${to.type.toUpperCase().replace('-', '_')} policy`,
          isQuarantine ? 'ebtables L2 drop · blocked-MAC list' : 'manual_assignment is_pinned=0',
        ].join(' · '),
      };
    }

    case 'toggle-apple-ecosystem': {
      const z = ctx.zone!;
      const turningOn = !z.appleEcosystem;
      return {
        kind,
        zoneId: z.id,
        summary: turningOn
          ? `AirPlay, HomeKit, and casting will work between ${z.name} devices. Still hidden from Guests and other zones.`
          : `Apple ecosystem disabled for ${z.name}. AirPlay, HomeKit, and AirDrop will stop working between these devices.`,
        technical: turningOn
          ? `mDNS reflection: _airplay._tcp · _raop._tcp · _hap._tcp · _companion-link._tcp · _sleep-proxy._tcp scoped to ${z.name} VLAN · cross-VLAN drop maintained`
          : `mDNS reflection removed for ${z.name} VLAN · _airplay / _raop / _hap / _companion-link services no longer reflected`,
      };
    }

    case 'change-policy': {
      const { device, newPolicy } = ctx;
      const d = device!; const p = newPolicy!;
      const summaryMap: Record<NetworkPolicy, string> = {
        'full':          `${d.name} has full access — internet, home devices, and smart home.`,
        'internet-only': `${d.name} can reach the internet only. It cannot see your other devices.`,
        'lan-only':      `${d.name} can reach your home network only. No internet access.`,
        'smart-home':    `${d.name} can access smart home devices and the internet. Isolated from personal devices.`,
        'quarantine':    `${d.name} is fully isolated. No internet, no LAN. Reversible.`,
      };
      const artifactMap: Record<NetworkPolicy, string> = {
        'full':          'device_policies → FULL_ACCESS · OVS flows: internet + LAN + D2D allowed · mDNS reflected',
        'internet-only': 'device_policies → INTERNET_ONLY · OVS peer-isolation flows · mDNS not reflected',
        'lan-only':      'device_policies → LAN_ONLY · default-route blocked · LAN allowed via OVS · internet ebtables drop',
        'smart-home':    'device_policies → SMART_HOME · D2D within zone VLAN · mDNS reflected · personal device isolation',
        'quarantine':    'NetworkPolicy.ISOLATED · ebtables L2 drop · added to Quarantine bubble · blocked-MAC list',
      };
      return {
        kind,
        deviceId:  d.id,
        newPolicy: p,
        summary:   summaryMap[p],
        technical: artifactMap[p],
      };
    }

    case 'change-trust': {
      const { device, newTrust } = ctx;
      const d = device!; const t = newTrust!;
      const summaryMap: Record<TrustLevel, string> = {
        'trusted': `${d.name} marked as Trusted. It gets full zone privileges.`,
        'normal':  `${d.name} has standard access for its zone.`,
        'guest':   `${d.name} treated as Guest — internet only, isolated from home.`,
        'blocked': `${d.name} is blocked. No network access.`,
      };
      return {
        kind,
        deviceId: d.id,
        newTrust: t,
        summary:  summaryMap[t],
        technical: `device_trust tag → ${t.toUpperCase()} · Fingerbank NAC policy update · OVS flows adjusted per trust level`,
      };
    }

    case 'change-reach': {
      const { device, reach, newValue } = ctx;
      const d = device!;
      const reachLabel = { internet: 'internet', 'home-devices': 'other home devices', 'smart-home': 'smart home devices' }[reach!];
      return {
        kind,
        deviceId: d.id,
        reach,
        newValue,
        summary:   `${d.name} ${newValue ? 'can now reach' : 'can no longer reach'} ${reachLabel}.`,
        technical: `device_policies → custom override · OVS flow: ${reach!.replace('-', '_')} ${newValue ? 'allow' : 'drop'} · ebtables ${newValue ? 'allow' : 'block'} rule`,
      };
    }

    case 'block-device': {
      const d = ctx.device!;
      return {
        kind,
        deviceId: d.id,
        toZoneId: 'quarantine',
        summary:   `${d.name} is blocked and moved to Quarantine. No internet, no LAN. Reversible.`,
        technical: `NetworkPolicy.ISOLATED · ebtables L2 drop · manual_assignment: bubble_id=QUARANTINE · blocked-MAC list updated`,
      };
    }

    default:
      return { kind: 'change-policy', summary: 'Change pending…', technical: '' };
  }
}

// ── Mock zones ────────────────────────────────────────────────────────────────

export const INITIAL_ZONES: Zone[] = [
  {
    id:             'family',
    name:           'Family',
    type:           'family',
    appleEcosystem: true,
    isPinned:       true,
    isSystem:       false,
    description:    'Full access · AirPlay + HomeKit · printer shared',
    suggestion: {
      id:          'sug-airpods',
      text:        "Sam's new AirPods keep pairing with Sam's iPhone. Add to Family zone?",
      deviceIds:   ['airpods'],
      targetZoneId: 'family',
    },
  },
  {
    id:             'kids',
    name:           'Kids',
    type:           'kids',
    appleEcosystem: false,
    isPinned:       false,
    isSystem:       false,
    description:    'Internet only · no home devices · Strict DNS',
  },
  {
    id:             'smart-home',
    name:           'Smart Home',
    type:           'smart-home',
    appleEcosystem: true,
    isPinned:       false,
    isSystem:       false,
    description:    'Shared by family · AirPlay · HomeKit · casting',
  },
  {
    id:             'guests',
    name:           'Guests',
    type:           'guests',
    appleEcosystem: false,
    isPinned:       false,
    isSystem:       false,
    description:    'Internet only · isolated from home',
  },
  {
    id:             'quarantine',
    name:           'Quarantine',
    type:           'quarantine',
    appleEcosystem: false,
    isPinned:       true,
    isSystem:       true,
    description:    'Fully isolated — no internet, no LAN. Reversible.',
  },
];

// ── Mock devices ──────────────────────────────────────────────────────────────

export const INITIAL_DEVICES: Device[] = [
  // ── Family zone ──
  {
    id: 'iphone-sam', name: "Sam's iPhone", type: 'phone', status: 'online',
    zoneId: 'family', policy: 'full', isPinned: true, isApple: true,
    canReachInternet: true, canReachHomeDevices: true, canReachSmartHome: true,
    trust: 'trusted', lastSeen: '2s ago',
    fingerprint: 'Apple iPhone 15 · OUI + mDNS (98%)',
  },
  {
    id: 'macbook-sam', name: "Sam's MacBook", type: 'laptop', status: 'online',
    zoneId: 'family', policy: 'full', isPinned: true, isApple: true,
    canReachInternet: true, canReachHomeDevices: true, canReachSmartHome: true,
    trust: 'trusted', lastSeen: '5s ago',
    fingerprint: 'Apple MacBook Pro · DHCP + OUI (97%)',
  },
  {
    id: 'watch-sam', name: "Sam's Watch", type: 'watch', status: 'online',
    zoneId: 'family', policy: 'full', isPinned: false, isApple: true,
    canReachInternet: true, canReachHomeDevices: true, canReachSmartHome: true,
    trust: 'trusted', lastSeen: '2s ago',
    fingerprint: 'Apple Watch Series 9 · _companion-link._tcp (99%)',
  },
  {
    id: 'printer', name: 'HP LaserJet', type: 'printer', status: 'idle',
    zoneId: 'family', policy: 'lan-only', isPinned: false, isApple: false,
    canReachInternet: false, canReachHomeDevices: true, canReachSmartHome: false,
    trust: 'normal', lastSeen: '3m ago',
    fingerprint: 'HP LaserJet M404 · DHCP hostname (94%)',
  },
  // ── Kids zone ──
  {
    id: 'ipad-kids', name: "Emma's iPad", type: 'tablet', status: 'online',
    zoneId: 'kids', policy: 'internet-only', isPinned: false, isApple: true,
    canReachInternet: true, canReachHomeDevices: false, canReachSmartHome: false,
    trust: 'normal', lastSeen: '1m ago',
    fingerprint: 'Apple iPad mini 6 · DHCP + OUI (96%)',
  },
  {
    id: 'switch', name: 'Nintendo Switch', type: 'game', status: 'idle',
    zoneId: 'kids', policy: 'internet-only', isPinned: false, isApple: false,
    canReachInternet: true, canReachHomeDevices: false, canReachSmartHome: false,
    trust: 'normal', lastSeen: '12m ago',
    fingerprint: 'Nintendo Switch · DHCP hostname (91%)',
  },
  {
    id: 'laptop-kids', name: "Kids' Laptop", type: 'laptop', status: 'online',
    zoneId: 'kids', policy: 'internet-only', isPinned: false, isApple: false,
    canReachInternet: true, canReachHomeDevices: false, canReachSmartHome: false,
    trust: 'normal', lastSeen: '8s ago',
    fingerprint: 'Lenovo IdeaPad · DHCP hostname (88%)',
  },
  // ── Smart Home zone ──
  {
    id: 'homepod', name: 'HomePod', type: 'speaker', status: 'online',
    zoneId: 'smart-home', policy: 'smart-home', isPinned: false, isApple: true,
    canReachInternet: true, canReachHomeDevices: true, canReachSmartHome: true,
    trust: 'trusted', lastSeen: '1s ago',
    fingerprint: 'Apple HomePod 2 · _airplay._tcp + _raop._tcp (99%)',
  },
  {
    id: 'appletv', name: 'Apple TV', type: 'tv', status: 'online',
    zoneId: 'smart-home', policy: 'smart-home', isPinned: false, isApple: true,
    canReachInternet: true, canReachHomeDevices: true, canReachSmartHome: true,
    trust: 'trusted', lastSeen: '3s ago',
    fingerprint: 'Apple TV 4K (3rd gen) · _airplay._tcp + _hap._tcp (99%)',
  },
  {
    id: 'hue-bridge', name: 'Hue Bridge', type: 'hub', status: 'online',
    zoneId: 'smart-home', policy: 'smart-home', isPinned: false, isApple: false,
    canReachInternet: true, canReachHomeDevices: true, canReachSmartHome: true,
    trust: 'trusted', lastSeen: '4s ago',
    fingerprint: 'Signify Philips Hue Bridge · DHCP + hostname (95%)',
  },
  {
    id: 'echo', name: 'Echo Dot', type: 'speaker', status: 'online',
    zoneId: 'smart-home', policy: 'smart-home', isPinned: false, isApple: false,
    canReachInternet: true, canReachHomeDevices: false, canReachSmartHome: true,
    trust: 'normal', lastSeen: '2s ago',
    fingerprint: 'Amazon Echo Dot (5th gen) · DHCP hostname (93%)',
  },
  {
    id: 'nest-cam', name: 'Nest Camera', type: 'camera', status: 'online',
    zoneId: 'smart-home', policy: 'smart-home', isPinned: false, isApple: false,
    canReachInternet: true, canReachHomeDevices: false, canReachSmartHome: false,
    trust: 'normal', lastSeen: '1s ago',
    fingerprint: 'Google Nest Cam · DHCP + OUI (92%)',
  },
  // ── Guests zone ──
  {
    id: 'guest-iphone', name: 'Guest iPhone', type: 'phone', status: 'online',
    zoneId: 'guests', policy: 'internet-only', isPinned: false, isApple: false,
    canReachInternet: true, canReachHomeDevices: false, canReachSmartHome: false,
    trust: 'guest', lastSeen: '2m ago',
    fingerprint: 'Unknown iPhone · OUI match (72%)',
  },
  {
    id: 'guest-laptop', name: 'Guest Laptop', type: 'laptop', status: 'idle',
    zoneId: 'guests', policy: 'internet-only', isPinned: false, isApple: false,
    canReachInternet: true, canReachHomeDevices: false, canReachSmartHome: false,
    trust: 'guest', lastSeen: '8m ago',
    fingerprint: 'Unknown device · DHCP only (60%)',
  },
  // ── Quarantine zone ──
  {
    id: 'unknown-camera', name: 'Unknown Camera', type: 'camera', status: 'offline',
    zoneId: 'quarantine', policy: 'quarantine', isPinned: false, isApple: false,
    canReachInternet: false, canReachHomeDevices: false, canReachSmartHome: false,
    trust: 'blocked', lastSeen: '2h ago',
    fingerprint: 'Unknown · reached known C2 (confidence 96%)',
  },
];
