/**
 * dnsMock — Shield (Pillar 1) mock data + types (Layer 0).
 *
 * Maps 1:1 to the real V1 dnsXai engine (shared/dnsXai/engine.py, live as
 * guardian-dnsxai DoH :5353):
 *   - DomainCategory enum → BlockCategory (advertising/tracking/analytics/
 *     social-tracker/malware/cryptominer)
 *   - WhitelistSource enum → ListSource (system = never block · user · ml-learned)
 *   - ML ensemble (neural + LightGBM) → avgInferenceMs + per-category counts
 *   - privacy presets / level → ProtectionLevel (relaxed/balanced/strict)
 *
 * Real backend will serve these over SSE/WS from Rust/Axum (ADR 0001); the
 * shape here matches dnsXai's /api/stats + whitelist/blocklist endpoints.
 */

// ── Types ───────────────────────────────────────────────────────────────────

export type BlockCategory =
  | 'advertising' | 'tracking' | 'analytics'
  | 'social-tracker' | 'malware' | 'cryptominer';

export type ProtectionLevel = 'relaxed' | 'balanced' | 'strict';

/** dnsXai WhitelistSource: SYSTEM never-block · USER-defined · ML-learned (false-positive recovery) */
export type ListSource = 'system' | 'user' | 'ml-learned';

export interface CategoryStat {
  key:     BlockCategory;
  label:   string;
  blocked: number;
  /** rendered red — an active threat class, not just privacy */
  threat:  boolean;
}

export interface ListEntry {
  domain:   string;
  source:   ListSource;
  addedBy?: string;
}

export interface ShieldChange {
  kind:      'set-level' | 'add-allow' | 'remove-allow' | 'add-block' | 'remove-block';
  summary:   string;     // plain-English (Layer 1)
  technical: string;     // dnsXai artifact (Layer 2 — collapsed)
  level?:    ProtectionLevel;
  domain?:   string;
}

// ── Labels / level copy ──────────────────────────────────────────────────────

export const CATEGORY_LABELS: Record<BlockCategory, string> = {
  advertising:      'Advertising',
  tracking:         'Tracking',
  analytics:        'Analytics',
  'social-tracker': 'Social trackers',
  malware:          'Malware',
  cryptominer:      'Cryptominers',
};

export const SOURCE_LABELS: Record<ListSource, string> = {
  system:       'System',
  user:         'You',
  'ml-learned': 'AI-learned',
};

export const LEVEL_INFO: Record<ProtectionLevel, { label: string; blurb: string }> = {
  relaxed:  { label: 'Relaxed',  blurb: 'Ads and known malware only — fewest false positives.' },
  balanced: { label: 'Balanced', blurb: 'Ads, trackers and malware. Recommended for most homes.' },
  strict:   { label: 'Strict',   blurb: 'Everything: ads, trackers, analytics, social trackers, malware and cryptominers.' },
};

// ── Initial mock data ────────────────────────────────────────────────────────

/** Per-category breakdown — sums to blockedToday (4,812), matching the landing card. */
export const INITIAL_CATEGORIES: CategoryStat[] = [
  { key: 'advertising',    label: CATEGORY_LABELS.advertising,      blocked: 2841, threat: false },
  { key: 'tracking',       label: CATEGORY_LABELS.tracking,         blocked: 1203, threat: false },
  { key: 'analytics',      label: CATEGORY_LABELS.analytics,        blocked: 498,  threat: false },
  { key: 'social-tracker', label: CATEGORY_LABELS['social-tracker'], blocked: 258, threat: false },
  { key: 'malware',        label: CATEGORY_LABELS.malware,          blocked: 12,   threat: true  },
  { key: 'cryptominer',    label: CATEGORY_LABELS.cryptominer,      blocked: 0,    threat: true  },
];

export const INITIAL_ALLOW: ListEntry[] = [
  { domain: 'captive.apple.com',   source: 'system' },
  { domain: 'mesh.hookprobe.com',  source: 'system' },
  { domain: 'analytics.google.com', source: 'user', addedBy: 'You' },
];

export const INITIAL_BLOCK: ListEntry[] = [
  { domain: 'tiktok.com',           source: 'user', addedBy: 'You' },
  { domain: 'instagram.com',        source: 'user', addedBy: 'You' },
  { domain: 'doubleclick.net',      source: 'system' },
  { domain: 'telemetry.roku.com',   source: 'ml-learned' },
];

export const SHIELD_TOTALS = {
  blockedToday:   4_812,
  queriesToday:   38_407,
  avgInferenceMs: 1.8,
};

// ── Plan-as-diff factory ─────────────────────────────────────────────────────

export function buildShieldChange(
  kind: ShieldChange['kind'],
  p: { level?: ProtectionLevel; domain?: string },
): ShieldChange {
  switch (kind) {
    case 'set-level':
      return {
        kind, level: p.level,
        summary:   `Protection set to ${LEVEL_INFO[p.level!].label}. ${LEVEL_INFO[p.level!].blurb}`,
        technical: `dnsXai filter level → ${p.level} · DomainCategory thresholds updated · resolver reload (no downtime)`,
      };
    case 'add-allow':
      return {
        kind, domain: p.domain,
        summary:   `"${p.domain}" will be allowed on all devices — never blocked, even by a list.`,
        technical: `whitelist += ${p.domain} (source: user) · dnsXai cache purge for domain · reload`,
      };
    case 'remove-allow':
      return {
        kind, domain: p.domain,
        summary:   `"${p.domain}" removed from your allow list — normal filtering resumes for it.`,
        technical: `whitelist -= ${p.domain} · dnsXai cache purge · reload`,
      };
    case 'add-block':
      return {
        kind, domain: p.domain,
        summary:   `"${p.domain}" will be blocked on all devices.`,
        technical: `blocklist += ${p.domain} (source: user) · DomainCategory override → BLOCKED · reload`,
      };
    case 'remove-block':
      return {
        kind, domain: p.domain,
        summary:   `"${p.domain}" removed from your block list.`,
        technical: `blocklist -= ${p.domain} · reload`,
      };
  }
}
