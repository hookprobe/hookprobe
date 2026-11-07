/**
 * investigateMock — Investigate (§5, AEGIS) Layer-0 mock data.
 *
 * Spec: docs/architecture/MissionControl.md §5 — "the differentiator": Incident Story +
 * Why AEGIS decided this (confidence, evidence, alternative hypotheses, model)
 * + ATT&CK/CVE/Sigma context + a proposed plan (diff) to approve.
 * Design tracks the reference's "AI INVESTIGATION" panel.
 */

import type { Tone } from './missionMock';

export interface StoryStep { time: string; text: string; tone: Tone }
export interface Hypothesis { text: string; confidence: number; chosen: boolean }
export interface MitreTactic { id: string; name: string }
export interface IntelRow { label: string; value: string; tone: Tone }

export interface Incident {
  id: string; title: string; target: string;
  priority: 'Critical' | 'High' | 'Medium';
  status: string; time: string;
  summary: string;
  story: StoryStep[];
  confidence: number; evidence: number; model: string;
  hypotheses: Hypothesis[];
  mitre: MitreTactic[];
  intel: IntelRow[];
  plan: { summary: string; technical: string; steps: string[] };
}

export const INCIDENTS: Incident[] = [
  {
    id: 'INC-2024-0524', title: 'Credential stuffing → VPN gateway', target: 'vpn-gw-01',
    priority: 'High', status: 'Contained', time: '12:46',
    summary: 'Someone hammered the VPN login from a rented server farm. AEGIS blocked the source and isolated the gateway before any account was taken — no breach.',
    story: [
      { time: '08:41', text: 'External scan detected against vpn-gw-01', tone: 'amber' },
      { time: '08:42', text: 'Credential-stuffing burst started (4.2k attempts/min)', tone: 'amber' },
      { time: '08:43', text: 'NAPSE classified the pattern as anomalous auth', tone: 'blue' },
      { time: '08:43', text: 'HYDRA enriched source IPs → known APT28 infrastructure', tone: 'purple' },
      { time: '08:44', text: 'AEGIS requested validation (confidence 96%)', tone: 'purple' },
      { time: '08:44', text: 'Kernel XDP dropped the source ASN at line rate', tone: 'green' },
      { time: '08:45', text: 'Gateway VLAN moved to fail-closed', tone: 'green' },
      { time: '12:46', text: 'Threat contained · no credential compromised', tone: 'green' },
    ],
    confidence: 96, evidence: 24, model: 'aegis-local · llama-3.1-70b',
    hypotheses: [
      { text: 'Credential stuffing (reused breach creds)', confidence: 96, chosen: true },
      { text: 'Password spray (low-and-slow)', confidence: 31, chosen: false },
      { text: 'Distributed brute force', confidence: 18, chosen: false },
    ],
    mitre: [
      { id: 'T1190', name: 'Exploit Public-Facing App' },
      { id: 'T1110', name: 'Brute Force' },
      { id: 'T1046', name: 'Network Service Discovery' },
      { id: 'T1021', name: 'Remote Services' },
    ],
    intel: [
      { label: 'CVE-2024-3094', value: 'Critical', tone: 'red' },
      { label: 'APT28 Campaign', value: 'High', tone: 'amber' },
      { label: 'Malicious IPs', value: '5', tone: 'amber' },
      { label: 'YARA Matches', value: '3', tone: 'blue' },
      { label: 'Sigma Rules', value: '7', tone: 'purple' },
    ],
    plan: {
      summary: 'Keep the source ASN blocked, force-rotate VPN credentials for the 3 targeted accounts, and hold the gateway fail-closed for 1 hour.',
      technical: 'nftables drop AS-INBOUND 209xxx · keycloak credential reset (3 users) · OVS fail-closed flow on vpn-gw-01 (ttl 1h) · re-open on QSecBit ≥ 90',
      steps: ['Block source ASN (already active)', 'Force credential rotation · 3 accounts', 'Gateway fail-closed · 1h', 'Notify account owners'],
    },
  },
  {
    id: 'INC-2024-0528', title: 'C2 beaconing from marketing laptop', target: 'Marketing-Laptop-12',
    priority: 'High', status: 'Investigating', time: '12:38',
    summary: 'A laptop is making regular callbacks to a suspicious host. AEGIS isolated it to the quarantine VLAN while it gathers evidence — internet cut, no lateral movement seen.',
    story: [
      { time: '11:02', text: 'Periodic 60s beacon to 185.x.x.x detected', tone: 'amber' },
      { time: '11:03', text: 'HYDRA: destination on a fresh-NRD reputation list', tone: 'purple' },
      { time: '11:05', text: 'AEGIS isolated host to Quarantine VLAN', tone: 'green' },
      { time: '12:38', text: 'Collecting process tree + DNS history', tone: 'blue' },
    ],
    confidence: 84, evidence: 11, model: 'aegis-local · llama-3.1-70b',
    hypotheses: [
      { text: 'Commodity C2 (info-stealer)', confidence: 84, chosen: true },
      { text: 'Benign telemetry false-positive', confidence: 22, chosen: false },
    ],
    mitre: [
      { id: 'T1071', name: 'Application Layer Protocol' },
      { id: 'T1571', name: 'Non-Standard Port' },
    ],
    intel: [
      { label: 'Newly-registered domain', value: 'High', tone: 'amber' },
      { label: 'Malicious IPs', value: '1', tone: 'amber' },
      { label: 'Sigma Rules', value: '2', tone: 'purple' },
    ],
    plan: {
      summary: 'Keep the laptop quarantined, capture a full pcap of the next beacon, and queue an EDR scan before re-admitting it.',
      technical: 'OVS keep host in quarantine VLAN · trigger 5-min full pcap on next beacon · enqueue endpoint scan · re-admit on clean verdict',
      steps: ['Hold quarantine', 'Capture next beacon (pcap)', 'EDR scan', 'Re-admit if clean'],
    },
  },
  {
    id: 'INC-2024-0519', title: 'Data exfil attempt · HR database', target: 'hr-db-prod',
    priority: 'Medium', status: 'Watching', time: '12:31',
    summary: 'An unusually large query ran against the HR database after hours. Likely a backup job, but AEGIS flagged it for review and is watching for repeat patterns.',
    story: [
      { time: '02:14', text: 'Large SELECT (1.2 GB) from batch service account', tone: 'amber' },
      { time: '02:15', text: 'AEGIS: matches nightly backup signature (low risk)', tone: 'blue' },
      { time: '12:31', text: 'Flagged for analyst review · watching for repeats', tone: 'amber' },
    ],
    confidence: 38, evidence: 6, model: 'aegis-local · llama-3.1-70b',
    hypotheses: [
      { text: 'Scheduled backup (benign)', confidence: 62, chosen: true },
      { text: 'Insider data exfiltration', confidence: 38, chosen: false },
    ],
    mitre: [{ id: 'T1530', name: 'Data from Cloud Storage' }, { id: 'T1041', name: 'Exfiltration over C2' }],
    intel: [{ label: 'Behavioral anomaly', value: 'Medium', tone: 'amber' }],
    plan: {
      summary: 'No automatic action. Watch for a second large off-hours query and alert the analyst if it recurs within 24h.',
      technical: 'set watch rule: SELECT > 500MB from svc-backup outside 01:00–03:00 → alert · 24h window',
      steps: ['Add watch rule (24h)', 'Alert analyst on repeat'],
    },
  },
];
