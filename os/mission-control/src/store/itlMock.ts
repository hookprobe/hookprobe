/**
 * itlMock — Intelligence (§8, HYDRA) Layer-0 mock data.
 *
 * Spec: docs/architecture/MissionControl.md §8 — threat intelligence as a workspace.
 * Backed by HYDRA: the 11-service ids-hydra-* threat-intel/enrichment pipeline
 * (feeds/CVE/IOC/anomaly/predictor/temporal). Ingests STIX/TAXII and MISP;
 * enrichment annotates the evidence graph. IOC → every event/endpoint it touched;
 * CVE → affected assets across scope. Intent: "Show every endpoint exposed to
 * CVE-2024-3094."
 */

import type { Tone } from './missionMock';

export type Severity    = 'critical' | 'high' | 'medium' | 'low';
export type IocType     = 'IP' | 'Domain' | 'Hash' | 'URL';
export type FeedStatus  = 'synced' | 'syncing' | 'error' | 'stale';

export interface Kpi { label: string; value: string; tone: Tone }

export interface Cve {
  id: string; severity: Severity; title: string;
  affectedAssets: number; published: string; cvss: string;
}

export interface Ioc {
  indicator: string; type: IocType; family: string;
  lastSeen: string; hits: number;
}

export interface ThreatActor {
  name: string; alias: string; origin: string;
  confidence: number; techniques: number; campaigns: string[];
}

export interface Feed {
  name: string; protocol: string; status: FeedStatus;
  lastSync: string; records: string; provider: string;
}

// ── KPI row ──────────────────────────────────────────────────────────────────

export const KPIS: Kpi[] = [
  { label: 'IOCs Tracked',  value: '14,823', tone: 'blue'   },
  { label: 'CVEs Active',   value: '2,847',  tone: 'red'    },
  { label: 'Active Feeds',  value: '11',     tone: 'green'  },
  { label: 'Campaigns',     value: '23',     tone: 'amber'  },
  { label: 'Threat Actors', value: '847',    tone: 'purple' },
];

// ── CVE list ──────────────────────────────────────────────────────────────────
//
// SUPERSEDED for real data by `itlLive.ts` (`GET /api/exploitability`, ADR 0024): the live
// exploitability board carries real VEX status + SSVC decision + EPSS per CVE, capability-grounded
// off the signed Platform Manifest. `IntelligenceApp` should render `exploitFindings()` when
// `exploitStatus() === 'live'` and fall back to this static list only while loading / on error
// (clearly labelled). Kept here as the loading/offline placeholder, not the source of truth.

export const CVES: Cve[] = [
  { id: 'CVE-2024-3094',  severity: 'critical', title: 'XZ Utils backdoor — supply-chain RCE',       affectedAssets: 7,  published: '2024-03-29', cvss: '10.0' },
  { id: 'CVE-2024-6387',  severity: 'critical', title: 'OpenSSH regreSSHion — unauthenticated RCE',  affectedAssets: 8,  published: '2024-07-01', cvss: '8.1'  },
  { id: 'CVE-2024-21762', severity: 'critical', title: 'FortiOS SSL-VPN out-of-bounds write',        affectedAssets: 3,  published: '2024-02-08', cvss: '9.6'  },
  { id: 'CVE-2024-1709',  severity: 'critical', title: 'ConnectWise ScreenConnect auth bypass',      affectedAssets: 1,  published: '2024-02-21', cvss: '10.0' },
  { id: 'CVE-2024-4577',  severity: 'high',     title: 'PHP CGI argument injection RCE',             affectedAssets: 4,  published: '2024-06-06', cvss: '9.8'  },
  { id: 'CVE-2023-44487', severity: 'high',     title: 'HTTP/2 Rapid Reset — distributed DoS',      affectedAssets: 12, published: '2023-10-10', cvss: '7.5'  },
];

// ── IOC matches ───────────────────────────────────────────────────────────────

export const IOCS: Ioc[] = [
  { indicator: '185.220.101.47',        type: 'IP',     family: 'Cobalt Strike C2',     lastSeen: '12:44', hits: 27  },
  { indicator: 'malware-cdn.eu.net',    type: 'Domain', family: 'APT28 watering hole',  lastSeen: '12:31', hits: 4   },
  { indicator: '91.92.248.35',          type: 'IP',     family: 'Brute-force origin',   lastSeen: '11:22', hits: 412 },
  { indicator: 'phish.secure-login.pw', type: 'Domain', family: 'Credential phishing',  lastSeen: '10:58', hits: 8   },
  { indicator: 'cdn-evil.ru/payload',   type: 'URL',    family: 'LockBit payload CDN',  lastSeen: '11:47', hits: 3   },
  { indicator: '5d41402abc4b2a76b9eb',  type: 'Hash',   family: 'Emotet dropper',       lastSeen: '12:02', hits: 1   },
];

// ── Threat actors / campaigns ─────────────────────────────────────────────────

export const THREAT_ACTORS: ThreatActor[] = [
  { name: 'APT28',         alias: 'Fancy Bear',    origin: 'RU', confidence: 94, techniques: 42, campaigns: ['Credential Access', 'Spearphishing'] },
  { name: 'Lazarus Group', alias: 'Hidden Cobra',  origin: 'KP', confidence: 87, techniques: 38, campaigns: ['Ransomware', 'Crypto theft'] },
  { name: 'APT29',         alias: 'Cozy Bear',     origin: 'RU', confidence: 78, techniques: 56, campaigns: ['C2 beacon', 'SolarWinds follow-on'] },
  { name: 'FIN7',          alias: 'Carbon Spider', origin: '??', confidence: 71, techniques: 29, campaigns: ['POS malware', 'BlackBasta'] },
];

// ── Feed status ───────────────────────────────────────────────────────────────

export const FEEDS: Feed[] = [
  { name: 'MISP Community',   protocol: 'MISP',      status: 'synced',  lastSync: '5m ago',  records: '847,231', provider: 'misp-project.org'             },
  { name: 'Threat Intel Std', protocol: 'TAXII 2.1', status: 'synced',  lastSync: '12m ago', records: '234,512', provider: 'taxiiserver.io'               },
  { name: 'AlienVault OTX',   protocol: 'API',       status: 'synced',  lastSync: '18m ago', records: '1.2M',    provider: 'otx.alienvault.com'           },
  { name: 'CISA KEV',         protocol: 'API',       status: 'synced',  lastSync: '1h ago',  records: '1,147',   provider: 'cisa.gov'                     },
  { name: 'Emerging Threats', protocol: 'RSS',       status: 'stale',   lastSync: '4h ago',  records: '92,040',  provider: 'rules.emergingthreats.net'    },
];
