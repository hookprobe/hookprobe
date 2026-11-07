/**
 * protMock — Protect (§6) Layer-0 mock data.
 *
 * Spec: docs/architecture/MissionControl.md §6 — response & posture; the data-plane surface.
 * Per-interface posture (out-of-band / inline, fail-open / fail-closed);
 * active controls (firewall, isolation, quarantine — gated on manifest grants);
 * segment policies; zero-trust / compliance / risk summary;
 * plan-as-diff intents ("Make the OT VLAN fail-closed", "Isolate 10.4.2.17 now").
 *
 * Capability grants come from the signed Platform Manifest in a real build.
 * Every control that relies on a grant is shown, greyed-with-reason, or hidden
 * based solely on GRANTS — never a broken or no-op button.
 */

import type { Tone } from './missionMock';

// ── Capability grants (manifest-sourced in a real build) ─────────────────────

export interface Grants {
  /** nftables rule management */
  firewall: boolean;
  /** inline mode — isolation, quarantine, fail-closed enforcement */
  inline_control: boolean;
  /** VPN endpoint control */
  vpn: boolean;
}

/** Layer-0 mock: firewall + inline_control granted; vpn not provisioned */
export const GRANTS: Grants = {
  firewall:       true,
  inline_control: true,
  vpn:            false,  // → greyed-with-reason demonstration
};

// ── KPIs ─────────────────────────────────────────────────────────────────────

export interface ProtKpi { label: string; value: string; tone: Tone }

export const KPIS: ProtKpi[] = [
  { label: 'Blocked · 24h',       value: '2,457', tone: 'green'  },
  { label: 'Isolated hosts',       value: '2',     tone: 'amber'  },
  { label: 'Active policies',      value: '14',    tone: 'blue'   },
  { label: 'Fail-closed segments', value: '3',     tone: 'red'    },
  { label: 'Active rules',         value: '312',   tone: 'purple' },
];

// ── Per-interface posture (the key panel) ─────────────────────────────────────

export type NicRole   = 'out-of-band' | 'inline';
export type FailMode  = 'fail-open' | 'fail-closed';
export type NicStatus = 'healthy' | 'degraded' | 'down';

export interface NetInterface {
  name:        string;
  label:       string;
  role:        NicRole;
  failMode:    FailMode;
  trafficIn:   string;
  trafficOut:  string;
  pps:         string;
  status:      NicStatus;
  segment:     string;
}

export const INTERFACES: NetInterface[] = [
  {
    name: 'eth0', label: 'WAN / Uplink',
    role: 'out-of-band', failMode: 'fail-open',
    trafficIn: '487 Mbps', trafficOut: '51 Mbps', pps: '62k pps',
    status: 'healthy', segment: 'WAN',
  },
  {
    name: 'eth1', label: 'LAN / Corporate',
    role: 'inline', failMode: 'fail-open',
    trafficIn: '210 Mbps', trafficOut: '180 Mbps', pps: '28k pps',
    status: 'healthy', segment: 'Corporate',
  },
  {
    name: 'eth2', label: 'OT / Industrial',
    role: 'inline', failMode: 'fail-open',
    trafficIn: '12 Mbps', trafficOut: '4 Mbps', pps: '3.2k pps',
    status: 'healthy', segment: 'OT-VLAN',
  },
  {
    name: 'eth3', label: 'Guest Wi-Fi',
    role: 'out-of-band', failMode: 'fail-open',
    trafficIn: '8 Mbps', trafficOut: '22 Mbps', pps: '1.1k pps',
    status: 'healthy', segment: 'Guest',
  },
  {
    name: 'eth4', label: 'Quarantine VLAN',
    role: 'inline', failMode: 'fail-closed',
    trafficIn: '0.4 Mbps', trafficOut: '0.1 Mbps', pps: '48 pps',
    status: 'healthy', segment: 'Quarantine',
  },
];

// ── Firewall rules (gated on `firewall` grant) ────────────────────────────────

export type RuleAction = 'accept' | 'drop' | 'reject' | 'log';

export interface FirewallRule {
  id:      string;
  chain:   string;
  action:  RuleAction;
  src:     string;
  dst:     string;
  proto:   string;
  hits:    number;
  enabled: boolean;
}

export const FIREWALL_RULES: FirewallRule[] = [
  { id: 'R-001', chain: 'INPUT',   action: 'drop',   src: 'AS-INBOUND-209xxx', dst: 'vpn-gw-01',   proto: 'TCP/443',  hits: 4821,  enabled: true  },
  { id: 'R-002', chain: 'FORWARD', action: 'drop',   src: '0.0.0.0/0',         dst: 'OT-VLAN',     proto: 'any',      hits: 1034,  enabled: true  },
  { id: 'R-003', chain: 'FORWARD', action: 'accept', src: 'Corporate',          dst: 'WAN',         proto: 'TCP',      hits: 98241, enabled: true  },
  { id: 'R-004', chain: 'FORWARD', action: 'log',    src: 'Guest',              dst: 'Corporate',   proto: 'any',      hits: 312,   enabled: true  },
  { id: 'R-005', chain: 'FORWARD', action: 'drop',   src: 'Quarantine',         dst: 'Corporate',   proto: 'any',      hits: 9,     enabled: true  },
  { id: 'R-006', chain: 'INPUT',   action: 'accept', src: '10.0.0.0/8',         dst: 'mgmt-api',    proto: 'TCP/8443', hits: 44,    enabled: true  },
  { id: 'R-007', chain: 'FORWARD', action: 'reject', src: '0.0.0.0/0',         dst: 'DNS-Internal', proto: 'UDP/53',  hits: 2,     enabled: false },
];

// ── Isolations / quarantine (gated on `inline_control` grant) ────────────────

export type IsoStatus = 'active' | 'monitoring' | 'released';

export interface Isolation {
  host:    string;
  ip:      string;
  reason:  string;
  started: string;
  ttl:     string;
  status:  IsoStatus;
}

export const ISOLATIONS: Isolation[] = [
  { host: 'Marketing-Laptop-12', ip: '10.100.12.42', reason: 'C2 beacon (confidence 84%)',    started: '11:05', ttl: '—',  status: 'active'     },
  { host: 'IoT-Cam-3',           ip: '10.200.0.15',  reason: 'Known-malicious C2 contact',     started: '09:14', ttl: '—',  status: 'active'     },
  { host: 'LAPTOP-7',            ip: '10.100.7.20',  reason: 'YARA hit (ransomware string)',    started: '00:08', ttl: '2h', status: 'monitoring' },
];

// ── Segment policies ─────────────────────────────────────────────────────────

export type PostureMode = 'alert-only' | 'block-and-alert' | 'full-enforcement';

export interface Policy {
  segment:  string;
  posture:  PostureMode;
  failMode: FailMode;
  devices:  number;
  tone:     Tone;
}

export const POLICIES: Policy[] = [
  { segment: 'Corporate',  posture: 'block-and-alert', failMode: 'fail-open',   devices: 18, tone: 'green'  },
  { segment: 'OT-VLAN',   posture: 'block-and-alert', failMode: 'fail-open',   devices: 6,  tone: 'amber'  },
  { segment: 'Guest',      posture: 'alert-only',       failMode: 'fail-open',   devices: 4,  tone: 'blue'   },
  { segment: 'Quarantine', posture: 'full-enforcement', failMode: 'fail-closed', devices: 2,  tone: 'red'    },
  { segment: 'WAN',        posture: 'block-and-alert', failMode: 'fail-open',   devices: 1,  tone: 'green'  },
];

// ── Zero-trust / compliance / risk ───────────────────────────────────────────

export interface ZeroTrustRow { label: string; value: string; tone: Tone }

export const ZERO_TRUST: ZeroTrustRow[] = [
  { label: 'Verified devices',     value: '22 / 24', tone: 'green' },
  { label: 'Unverified / unknown', value: '2',        tone: 'amber' },
  { label: 'Micro-segmentation',   value: 'Active',   tone: 'green' },
  { label: 'Lateral movement',     value: 'Blocked',  tone: 'green' },
  { label: 'East-west inspection', value: 'Inline',   tone: 'blue'  },
  { label: 'MFA enforcement',      value: 'Partial',  tone: 'amber' },
];

export interface ComplianceRow { framework: string; score: number; status: string; tone: Tone }

export const COMPLIANCE: ComplianceRow[] = [
  { framework: 'CIS Benchmark L2', score: 91, status: 'Passing',     tone: 'green' },
  { framework: 'NIST CSF',         score: 84, status: 'Passing',     tone: 'green' },
  { framework: 'ISO 27001',        score: 76, status: 'In Progress', tone: 'amber' },
  { framework: 'PCI-DSS',          score: 68, status: 'Gaps Found',  tone: 'amber' },
];

export interface RiskRow { label: string; value: string; tone: Tone }

export const RISK: RiskRow[] = [
  { label: 'Unpatched CVEs',    value: '3 High',    tone: 'red'   },
  { label: 'Exposed services',  value: '2',         tone: 'amber' },
  { label: 'Weak cipher suites', value: '0',        tone: 'green' },
  { label: 'Stale credentials', value: '1 account', tone: 'amber' },
  { label: 'QSecBit trend',     value: '+2 (92)',   tone: 'green' },
];

// ── Plan-as-diff intents ──────────────────────────────────────────────────────

export interface ProtPlan {
  intent:    string;
  summary:   string;
  steps:     string[];
  technical: string;
}

export const PLANS: ProtPlan[] = [
  {
    intent:  'Make the OT VLAN fail-closed',
    summary: 'Switch eth2 (OT-VLAN) from fail-open to fail-closed mode. Any link failure will cut OT traffic rather than fall back to uncontrolled forwarding. Applied atomically via OVS + nftables.',
    steps: [
      'Verify OT-VLAN inline mode active (eth2)',
      'Set fail-closed on OVS bridge port br-ot',
      'Insert nftables drop rule for OT forward on link-down signal',
      'Notify OT team · confirm re-open criteria',
    ],
    technical: `ovs-vsctl set port br-ot eth2 fail-mode=secure
nft add rule inet filter forward iif eth2 oif eth2 ct state invalid drop
hookprobe policy set ot-vlan fail-mode=fail-closed`,
  },
  {
    intent:  'Isolate 10.4.2.17 now',
    summary: 'Move host 10.4.2.17 to the Quarantine VLAN immediately. All traffic except DNS and the HookProbe management API will be dropped. Re-admission requires analyst approval.',
    steps: [
      'Resolve host via ARP (→ MAC 44:d2:…)',
      'OVS: move port to Quarantine VLAN (tag 99)',
      'nftables: drop all non-management traffic for this MAC',
      'Open incident INC-AUTO-0541',
      'Notify admin',
    ],
    technical: `ovs-vsctl set port $(ovs-vsctl find port mac="44:d2:*") tag=99
nft add rule inet filter forward ether saddr 44:d2:... drop
hookprobe isolate --host 10.4.2.17 --vlan quarantine --open-incident`,
  },
];
