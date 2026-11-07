/**
 * setupMock — state + copy for the first-run Setup wizard (System Setup lens).
 *
 * Realizes ADR 0010 (zero-touch provisioning) + ADR 0007 E4 (setup wizard +
 * passphrase enrollment). Designed to ~/os.hookprobe.local reference. This is the
 * Layer-0 mock: the real wizard POSTs a WanIntent/LanIntent to
 * /api/provision/launch and the reconciler applies it as a plan-as-diff.
 *
 * Spec: docs/architecture/MissionControl.md §12 (Administration → Provisioning, "First run").
 */

import { createSignal } from 'solid-js';

export type StepState = 'done' | 'active' | 'todo';
export interface Step { id: string; num: number; title: string; subtitle: string; icon: string; optional?: boolean }

// The 7 steps, in order (matches the reference wizard rail).
export const STEPS: Step[] = [
  { id: 'identity', num: 1, title: 'System Identity',      subtitle: 'Name your device',        icon: '▤' },
  { id: 'wireless', num: 2, title: 'Wireless Setup',       subtitle: 'Configure Wi-Fi',         icon: '⌾' },
  { id: 'network',  num: 3, title: 'Network Settings',     subtitle: 'LAN & IP configuration',  icon: '⊞' },
  { id: 'wan',      num: 4, title: 'Internet (WAN)',       subtitle: 'Configure WAN connection', icon: '⊕' },
  { id: 'pppoe',    num: 5, title: 'PPPoE',                subtitle: 'Internet via PPPoE',      icon: '⇄', optional: true },
  { id: 'security', num: 6, title: 'Security & Encryption', subtitle: 'Protect your data',       icon: '⛨' },
  { id: 'review',   num: 7, title: 'Review & Apply',       subtitle: 'Confirm and launch',      icon: '✓' },
];

// Bottom status strip — the live device facts (mock; real build reads the manifest).
export const DEVICE = {
  hostname: 'os.hookprobe.local',
  lanIp:    '10.66.0.1',          // production LAN gateway (reconciler default; setup captive uses the same, L2-stable per ADR 0010)
  hotspot:  'HookProbe',          // L2-stable SSID: the setup AP IS the production AP (no reconnect on handoff)
  firmware: 'v1.0.0-beta.1',
  uptime:   '00:05:32',
};

// A wizard field model. Each step owns a slice; the summary panel + Review read from it.
export interface WizardModel {
  // 1 identity
  deviceName: string; timezone: string; adminPassword: string; confirmPassword: string; location: string;
  // 2 wireless
  ssid: string; wifiBand: '2.4' | '5' | '6' | 'auto'; wifiPassword: string; wifiRoaming: boolean;
  // 3 network
  lanSubnet: string; dhcp: boolean; dualStackV6: boolean;
  // 4 wan — all uplink types: dynamic(DHCP) · static · pppoe · modem(LTE/5G) · wifi(station)
  wanMode: 'dynamic' | 'static' | 'pppoe' | 'modem' | 'wifi'; wanIface: string; multiWanFailover: boolean;
  staticIp: string; staticGw: string; staticDns: string;   // static
  modemApn: string;                                          // modem (LTE/5G)
  wanWifiSsid: string; wanWifiPass: string;                  // wifi station uplink
  // 5 pppoe
  pppoeUser: string; pppoePass: string;
  // 6 security
  anchor: 'factory' | 'passphrase'; passphrase: string; recoveryKey: boolean; signedUpdatesOnly: boolean;
}

export const DEFAULTS: WizardModel = {
  deviceName: 'HookProbe-Edge01', timezone: '(UTC+05:30) Asia/Kolkata', adminPassword: '', confirmPassword: '', location: '',
  ssid: 'HookProbe', wifiBand: 'auto', wifiPassword: '', wifiRoaming: true,
  lanSubnet: '10.66.0.0/24', dhcp: true, dualStackV6: true,
  wanMode: 'dynamic', wanIface: 'eth0', multiWanFailover: false,
  staticIp: '', staticGw: '', staticDns: '1.1.1.1',
  modemApn: '', wanWifiSsid: '', wanWifiPass: '',
  pppoeUser: '', pppoePass: '',
  anchor: 'factory', passphrase: '', recoveryKey: true, signedUpdatesOnly: true,
};

// ── Capability gating (from the Platform Manifest; mock here) ──────────────────
// Wi-Fi WAN (station uplink) needs a SECOND radio: one serves the AP, one is the
// station. A single-radio box can't be AP + STA on different networks, so the
// option is greyed-with-reason, never a dead button (MissionControl §capability gating).
export const CAPS = {
  wifiRadios: 2,        // e.g. onboard brcmfmac (AP) + USB dongle (station); 1 → Wi-Fi WAN disabled
  cellular:   true,     // a USB LTE/5G modem is present / detectable
};
export const wanWifiCapable = () => CAPS.wifiRadios >= 2;
export const wanModemCapable = () => CAPS.cellular;

export type WanMode = 'dynamic' | 'static' | 'pppoe' | 'modem' | 'wifi';
export const WAN_OPTIONS: { id: WanMode; label: string; needs?: () => boolean; reason?: string }[] = [
  { id: 'dynamic', label: 'Dynamic (DHCP)' },
  { id: 'static',  label: 'Static IP' },
  { id: 'pppoe',   label: 'PPPoE' },
  { id: 'modem',   label: 'Modem (LTE/5G)', needs: wanModemCapable, reason: 'No cellular modem detected' },
  { id: 'wifi',    label: 'Wi-Fi (station)', needs: wanWifiCapable, reason: 'Needs a 2nd radio — one AP + one station' },
];
export function wanLabel(m: string): string { return WAN_OPTIONS.find(o => o.id === m)?.label ?? m.toUpperCase(); }

export const TIMEZONES = [
  '(UTC+00:00) UTC', '(UTC+01:00) Europe/Bucharest', '(UTC+05:30) Asia/Kolkata',
  '(UTC-05:00) America/New_York', '(UTC-08:00) America/Los_Angeles', '(UTC+08:00) Asia/Singapore',
];

// Password strength → 0..3 + label (mirrors the reference's meter).
export function pwStrength(p: string): { score: number; label: string } {
  let s = 0;
  if (p.length >= 8) s++;
  if (/[A-Z]/.test(p) && /[a-z]/.test(p)) s++;
  if (/\d/.test(p) && /[^A-Za-z0-9]/.test(p)) s++;
  return { score: s, label: ['Too short', 'Weak', 'Good', 'Strong'][p ? s : 0] || 'Strong' };
}

// ── Shared wizard state (island-local; a real build hydrates from the device) ──
export const [step, setStep] = createSignal(0);                 // index into STEPS
export const [model, setModel] = createSignal<WizardModel>({ ...DEFAULTS });
export const [deploying, setDeploying] = createSignal(false);   // Review → Launch progress
export const [wanReady, setWanReady] = createSignal(false);     // the WAN-readiness poll (ADR 0010)

export function patch(p: Partial<WizardModel>) { setModel({ ...model(), ...p }); }

// Per-step completion (drives the summary panel dots + the rail check marks).
export function stepStatus(idx: number): StepState {
  if (idx === step()) return 'active';
  const m = model();
  const done = [
    () => !!m.deviceName && m.adminPassword.length >= 8 && m.adminPassword === m.confirmPassword,
    () => !!m.ssid && (m.wifiPassword.length >= 8),
    () => !!m.lanSubnet,
    () => !!m.wanMode,
    () => m.wanMode !== 'pppoe' || (!!m.pppoeUser && !!m.pppoePass),
    () => m.anchor === 'factory' || m.passphrase.length >= 8,
    () => false,
  ][idx];
  return done && done() ? 'done' : 'todo';
}

// The Review "plan-as-diff": human-readable summary of what the reconciler will apply.
export function planDiff(): { label: string; value: string; tone: 'add' | 'set' }[] {
  const m = model();
  return [
    { label: 'hostname',      value: m.deviceName.toLowerCase(),                          tone: 'set' },
    { label: 'wifi ap',       value: `${m.ssid} · ${m.wifiBand === 'auto' ? 'auto-band' : m.wifiBand + 'GHz'}${m.wifiRoaming ? ' · 802.11r/k/v' : ''}`, tone: 'add' },
    { label: 'lan gateway',   value: `${m.lanSubnet} + DHCP${m.dualStackV6 ? ' · dual-stack v6 (ULA+NAT66)' : ''}`, tone: 'add' },
    { label: 'wan uplink',    value: `${wanLabel(m.wanMode)}${m.wanMode === 'wifi' && m.wanWifiSsid ? ` (${m.wanWifiSsid})` : ` on ${m.wanIface}`}${m.multiWanFailover ? ' · failover' : ''}`, tone: 'add' },
    { label: 'nat',           value: `masquerade ${m.lanSubnet} → ${m.wanIface}`,          tone: 'add' },
    { label: 'data-at-rest',  value: m.anchor === 'passphrase' ? 'dm-crypt · passphrase anchor' : 'dm-crypt · factory key', tone: 'set' },
    { label: 'updates',       value: m.signedUpdatesOnly ? 'signed-only (cosign gate)' : 'any', tone: 'set' },
  ];
}
