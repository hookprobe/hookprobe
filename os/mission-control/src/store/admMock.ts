/**
 * admMock — Administration (§12) Layer-0 mock data.
 *
 * Spec: docs/architecture/MissionControl.md §12 — identity, edge nodes, and the OS lifecycle
 * (Build → Deploy). Panels surface the Platform Manifest (hardware/capabilities/
 * crypto posture), bootc upgrade/rollback, storage/retention tiers, Builder,
 * Images & artifacts, Modules, Provisioning/Enrollment, and AEGIS AI model cfg.
 *
 * Real values arrive over SSE/WS from Rust/Axum (ADR 0001).
 */

import type { Tone } from './missionMock';

// ── KPIs ─────────────────────────────────────────────────────────────────────

export interface Kpi { label: string; value: string; tone: Tone }
export const KPIS: Kpi[] = [
  { label: 'Users',             value: '4',  tone: 'blue' },
  { label: 'Edge Nodes',        value: '3',  tone: 'green' },
  { label: 'Built Images',      value: '12', tone: 'purple' },
  { label: 'Modules Installed', value: '8',  tone: 'amber' },
];

// ── Identity & Access ─────────────────────────────────────────────────────────

export type UserRole   = 'Super Admin' | 'SOC Analyst' | 'Read Only' | 'API Service';
export type UserStatus = 'active' | 'inactive';

export interface UserEntry {
  name: string; email: string; role: UserRole; status: UserStatus; lastLogin: string;
}

export const USERS: UserEntry[] = [
  { name: 'Admin',    email: 'admin@hookprobe.local', role: 'Super Admin', status: 'active',   lastLogin: '1 min ago' },
  { name: 'Analyst-1', email: 'soc1@hookprobe.local', role: 'SOC Analyst', status: 'active',  lastLogin: '4 h ago' },
  { name: 'Analyst-2', email: 'soc2@hookprobe.local', role: 'SOC Analyst', status: 'inactive', lastLogin: '3 d ago' },
  { name: 'ci-bot',  email: 'ci@hookprobe.local',    role: 'API Service', status: 'active',   lastLogin: '12 s ago' },
];

export interface SsoProvider { name: string; type: string; status: 'enabled' | 'disabled' }
export const SSO_PROVIDERS: SsoProvider[] = [
  { name: 'Entra ID', type: 'OIDC/SAML', status: 'enabled' },
  { name: 'Okta',     type: 'SAML 2.0',  status: 'disabled' },
];

export const API_KEYS_COUNT = 3;
export const SECRETS_COUNT  = 7;

// ── Edge Nodes — Platform Manifest ───────────────────────────────────────────

export type NodeStatus = 'healthy' | 'needs-attention' | 'critical';
export type Channel    = 'stable' | 'edge' | 'dev';

export interface CryptoPosture {
  signing: string; kex: string; boot: string; attestation: boolean;
}

export interface StorageTier {
  name: string; window: string; used: number; total: number; unit: string;
}

export interface EdgeNode {
  hostname:     string;
  platform:     string;
  arch:         string;
  ram:          string;
  osVer:        string;
  channel:      Channel;
  upgradeAvail: boolean;
  capabilities: string[];
  crypto:       CryptoPosture;
  status:       NodeStatus;
  enrolled:     string;
  storage:      StorageTier[];
}

export const EDGE_NODES: EdgeNode[] = [
  {
    hostname:     'hp-edge-01',
    platform:     'Raspberry Pi 5',
    arch:         'arm64',
    ram:          '8 GB',
    osVer:        '2.1.4-stable',
    channel:      'stable',
    upgradeAvail: true,
    capabilities: ['ids', 'dns_filtering', 'wifi_ap', 'segmentation', 'device_trust', 'wan'],
    crypto: { signing: 'ML-DSA-65 + Ed25519', kex: 'ML-KEM-768', boot: 'LMS/XMSS', attestation: false },
    status:       'healthy',
    enrolled:     '2025-03-14',
    storage: [
      { name: 'rootfs (immutable)', window: '—',    used: 4.2, total: 8,  unit: 'GB' },
      { name: 'Events',             window: '14 d', used: 11,  total: 32, unit: 'GB' },
      { name: 'Packets (pcap)',     window: '6 h',  used: 28,  total: 32, unit: 'GB' },
      { name: 'Alerts / Evidence', window: '90 d', used: 1.4, total: 8,  unit: 'GB' },
    ],
  },
  {
    hostname:     'hp-edge-02',
    platform:     'Intel N100',
    arch:         'amd64',
    ram:          '16 GB',
    osVer:        '2.1.4-stable',
    channel:      'stable',
    upgradeAvail: false,
    capabilities: ['ids', 'dns_filtering', 'segmentation', 'device_trust', 'openvswitch', 'wan', 'multi_wan', 'edge_ai'],
    crypto: { signing: 'ML-DSA-65 + Ed25519', kex: 'ML-KEM-768', boot: 'LMS/XMSS', attestation: true },
    status:       'healthy',
    enrolled:     '2025-04-02',
    storage: [
      { name: 'rootfs (immutable)', window: '—',     used: 4.2, total: 8,   unit: 'GB' },
      { name: 'Events',             window: '30 d',  used: 48,  total: 128, unit: 'GB' },
      { name: 'Packets (pcap)',     window: '12 h',  used: 60,  total: 128, unit: 'GB' },
      { name: 'Alerts / Evidence', window: '180 d', used: 6.1, total: 32,  unit: 'GB' },
    ],
  },
  {
    hostname:     'hp-edge-03',
    platform:     'RK3588',
    arch:         'arm64',
    ram:          '4 GB',
    osVer:        '2.0.9-stable',
    channel:      'edge',
    upgradeAvail: true,
    capabilities: ['ids', 'dns_filtering', 'wifi_ap', 'device_trust', 'wan'],
    crypto: { signing: 'Ed25519', kex: 'X25519', boot: 'LMS', attestation: false },
    status:       'needs-attention',
    enrolled:     '2025-05-19',
    storage: [
      { name: 'rootfs (immutable)', window: '—',   used: 4.2, total: 8,  unit: 'GB' },
      { name: 'Events',             window: '7 d', used: 5.8, total: 16, unit: 'GB' },
      { name: 'Packets (pcap)',     window: '2 h', used: 7.4, total: 8,  unit: 'GB' },
      { name: 'Alerts / Evidence', window: '30 d', used: 0.9, total: 4, unit: 'GB' },
    ],
  },
];

// ── OS Lifecycle — Images & Artifacts ─────────────────────────────────────────

export interface OsImage {
  version:    string;
  channel:    Channel;
  platform:   string;
  builtAt:    string;
  size:       string;
  signed:     boolean;
  hasSbom:    boolean;
  hasCbom:    boolean;
  provenance: boolean;
  active:     boolean;
}

export const IMAGES: OsImage[] = [
  { version: '2.1.4',      channel: 'stable', platform: 'rpi5 / n100 / rk3588', builtAt: '2025-06-28 03:14', size: '1.2 GB', signed: true,  hasSbom: true,  hasCbom: true,  provenance: true,  active: true  },
  { version: '2.1.3',      channel: 'stable', platform: 'rpi5 / n100',           builtAt: '2025-06-14 02:08', size: '1.1 GB', signed: true,  hasSbom: true,  hasCbom: true,  provenance: true,  active: false },
  { version: '2.2.0-rc1',  channel: 'edge',   platform: 'n100',                  builtAt: '2025-06-29 00:31', size: '1.3 GB', signed: true,  hasSbom: true,  hasCbom: true,  provenance: false, active: false },
  { version: '2.2.0-dev8', channel: 'dev',    platform: 'amd64-vm',              builtAt: '2025-06-29 08:11', size: '1.4 GB', signed: false, hasSbom: false, hasCbom: false, provenance: false, active: false },
];

// ── OS Lifecycle — Modules ─────────────────────────────────────────────────────

export type ModuleRuntime = 'wasm' | 'container' | 'sysext';
export type ModuleStatus  = 'active' | 'degraded' | 'disabled';

export interface OsModule {
  name:    string;
  runtime: ModuleRuntime;
  version: string;
  grants:  string[];
  signed:  boolean;
  status:  ModuleStatus;
}

export const MODULES: OsModule[] = [
  { name: 'napse-core',       runtime: 'wasm',      version: '1.8.2', grants: ['ids', 'network_read'],          signed: true,  status: 'active'  },
  { name: 'hydra-feeds',      runtime: 'container', version: '3.1.0', grants: ['threat_intel', 'ioc_write'],    signed: true,  status: 'active'  },
  { name: 'aegis-reconciler', runtime: 'wasm',      version: '2.0.1', grants: ['policy_write', 'intent'],       signed: true,  status: 'active'  },
  { name: 'dns-shield',       runtime: 'wasm',      version: '1.4.0', grants: ['dns_filtering'],                signed: true,  status: 'active'  },
  { name: 'ovs-driver',       runtime: 'sysext',    version: '3.4.1', grants: ['openvswitch', 'segmentation'],  signed: true,  status: 'active'  },
  { name: 'hydra-anomaly',    runtime: 'container', version: '1.1.0', grants: ['edge_ai', 'wasi_nn'],           signed: true,  status: 'degraded'},
  { name: 'yara-engine',      runtime: 'wasm',      version: '4.3.2', grants: ['file_scan'],                    signed: true,  status: 'active'  },
  { name: 'qsecbit-scorer',   runtime: 'wasm',      version: '1.0.5', grants: ['security_score'],               signed: true,  status: 'active'  },
];

// ── Provisioning & Enrollment ─────────────────────────────────────────────────

export type DeployMode = 'standalone' | 'cloud-linked' | 'self-hosted';
export type ProvStepStatus = 'done' | 'active' | 'pending';

export interface ProvStep {
  label: string; status: ProvStepStatus; detail: string;
}

export const PROV_STEPS: ProvStep[] = [
  { label: 'Hardware probe', status: 'done',    detail: 'Platform Manifest written · cosign-signed' },
  { label: 'Local identity', status: 'done',    detail: 'Admin keypair generated · TPM-sealed (N100 only)' },
  { label: 'Enrollment',     status: 'done',    detail: 'cloud-linked → mssp.hookprobe.com' },
  { label: 'Fleet join',     status: 'done',    detail: 'Ring: production-01 · GitOps pull active' },
  { label: 'OS ready',       status: 'active',  detail: 'v2.1.4-stable · upgrade available' },
];

export const CURRENT_MODE: DeployMode = 'cloud-linked';

// ── AI Models (AEGIS) ─────────────────────────────────────────────────────────

export type ModelType   = 'ollama' | 'openai-compatible' | 'cloud';
export type ModelStatus = 'connected' | 'unreachable' | 'unconfigured';
export type AutonomyLevel = 'auto' | 'approval' | 'disabled';

export interface AutonomyRule { action: string; level: AutonomyLevel }

export interface AegisModel {
  name:       string;
  type:       ModelType;
  endpoint:   string;
  model:      string;
  status:     ModelStatus;
  confidence: number;    /* min confidence threshold 0–100 */
  autonomy:   AutonomyRule[];
}

export const AEGIS_MODEL: AegisModel = {
  name:       'Local Ollama',
  type:       'ollama',
  endpoint:   'http://localhost:11434',
  model:      'llama3.1:8b-instruct-q4_K_M',
  status:     'connected',
  confidence: 72,
  autonomy: [
    { action: 'DNS block (IOC)',           level: 'auto'     },
    { action: 'Credential stuffing block', level: 'auto'     },
    { action: 'Host isolation',            level: 'approval' },
    { action: 'Server isolation',          level: 'approval' },
    { action: 'Fleet policy push',         level: 'disabled' },
    { action: 'Firewall rule edit',        level: 'approval' },
  ],
};
