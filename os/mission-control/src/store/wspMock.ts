/**
 * wspMock — Workspace (§2) Layer-0 mock data.
 *
 * Spec: docs/architecture/MissionControl.md §2 — your recent and saved work in one place,
 * scoped to the operator; everything links back to live graph objects.
 * Panels: Recent Incidents, Recent Reports, Saved Searches, AI Conversations,
 * Bookmarks / Favorites, Draft Playbooks.
 *
 * Real values arrive over SSE/WS from Rust/Axum (ADR 0001); shapes here
 * are what those feeds will carry.
 */

import type { Tone } from './missionMock';

// ── Types ────────────────────────────────────────────────────────────────────

export type IncPriority = 'critical' | 'high' | 'medium' | 'low';
export type ReportType  = 'executive' | 'incident' | 'compliance' | 'threat';
export type SearchScope = 'fleet' | 'site' | 'device' | 'all';
export type BookmarkKind = 'incident' | 'asset' | 'detection' | 'report' | 'playbook';
export type PlaybookStage = 'draft' | 'review' | 'approved';

export interface RecentIncident {
  id: string; title: string; target: string;
  priority: IncPriority; status: string; time: string;
}

export interface RecentReport {
  id: string; title: string; type: ReportType;
  customer: string; time: string;
}

export interface SavedSearch {
  id: string; query: string; scope: SearchScope;
  hits: number; savedAt: string;
}

export interface AiConversation {
  id: string; title: string; turns: number;
  context: string; lastAt: string;
}

export interface Bookmark {
  id: string; label: string; href: string;
  kind: BookmarkKind; pinned: boolean; time: string;
}

export interface DraftPlaybook {
  id: string; name: string; stage: PlaybookStage;
  triggers: string; lastEdit: string; steps: number;
}

// ── Priority / tone helpers ──────────────────────────────────────────────────

export function incPriorityTone(p: IncPriority): Tone {
  return p === 'critical' ? 'red' : p === 'high' ? 'amber' : p === 'medium' ? 'blue' : 'grey';
}

export function reportTypeTone(t: ReportType): Tone {
  return t === 'executive' ? 'purple' : t === 'incident' ? 'red' : t === 'compliance' ? 'green' : 'blue';
}

export function searchScopeTone(s: SearchScope): Tone {
  return s === 'fleet' ? 'purple' : s === 'site' ? 'blue' : s === 'device' ? 'green' : 'grey';
}

export function bookmarkKindTone(k: BookmarkKind): Tone {
  return k === 'incident' ? 'red' : k === 'detection' ? 'amber' : k === 'playbook' ? 'purple' : k === 'report' ? 'blue' : 'green';
}

export function playbookStageTone(s: PlaybookStage): Tone {
  return s === 'approved' ? 'green' : s === 'review' ? 'amber' : 'grey';
}

// ── Data ─────────────────────────────────────────────────────────────────────

export const RECENT_INCIDENTS: RecentIncident[] = [
  { id: 'INC-0531', title: 'Credential stuffing burst',     target: 'vpn-gw-01',          priority: 'high',     status: 'Contained',    time: '12:42' },
  { id: 'INC-0528', title: 'C2 beacon (60s interval)',      target: 'Marketing-Laptop-12', priority: 'high',     status: 'Investigating', time: '12:38' },
  { id: 'INC-0524', title: 'Suspicious token manipulation', target: 'DC-01',               priority: 'critical', status: 'Contained',    time: '12:18' },
  { id: 'INC-0519', title: 'Data exfiltration attempt',     target: 'HR-Database',         priority: 'medium',   status: 'Watching',     time: '12:31' },
  { id: 'INC-0512', title: 'Ransomware string match',       target: 'LAPTOP-7',            priority: 'critical', status: 'Contained',    time: '11:58' },
  { id: 'INC-0506', title: 'Internal port sweep detected',  target: 'IoT-Cam-3',           priority: 'low',      status: 'Closed',       time: '11:47' },
];

export const RECENT_REPORTS: RecentReport[] = [
  { id: 'RPT-0088', title: 'Weekly Executive Summary',         type: 'executive',  customer: 'Vodafone',       time: 'Today 09:00' },
  { id: 'RPT-0087', title: 'Credential Stuffing Post-Mortem',  type: 'incident',   customer: 'Globex Corp',    time: 'Today 08:30' },
  { id: 'RPT-0086', title: 'SOC2 Gap Analysis — Q2 2026',      type: 'compliance', customer: 'Stark Industries', time: 'Yesterday' },
  { id: 'RPT-0085', title: 'Ransomware Campaign — TTP Report', type: 'threat',     customer: 'All tenants',    time: 'Mon 14:00' },
  { id: 'RPT-0084', title: 'Monthly CISO Dashboard',           type: 'executive',  customer: 'Soylent Corp',   time: 'Mon 08:00' },
  { id: 'RPT-0083', title: 'Lateral Movement Incident Brief',  type: 'incident',   customer: 'Initech',        time: 'Sun 16:45' },
];

export const SAVED_SEARCHES: SavedSearch[] = [
  { id: 'SS-01', query: 'severity:critical source:suricata last:24h',    scope: 'fleet',  hits: 23,  savedAt: 'Today' },
  { id: 'SS-02', query: 'technique:T1110 verdict:blocked last:7d',        scope: 'fleet',  hits: 412, savedAt: 'Yesterday' },
  { id: 'SS-03', query: 'asset:DC-01 event_type:auth_failure',            scope: 'site',   hits: 88,  savedAt: 'Mon' },
  { id: 'SS-04', query: 'ioc:185.x.x.7 AND ioc:209.x.x.14',              scope: 'all',    hits: 7,   savedAt: 'Mon' },
  { id: 'SS-05', query: 'process:lsass.exe NOT device:DC-*',              scope: 'device', hits: 3,   savedAt: 'Sun' },
  { id: 'SS-06', query: 'dns_category:c2 confidence:>90 last:3d',         scope: 'fleet',  hits: 156, savedAt: 'Fri' },
];

export const AI_CONVERSATIONS: AiConversation[] = [
  { id: 'C-044', title: 'Why is Vodafone risk increasing?',         turns: 8,  context: 'fleet',  lastAt: '12:39' },
  { id: 'C-043', title: 'Summarise last night\'s incidents',        turns: 4,  context: 'site',   lastAt: '09:04' },
  { id: 'C-042', title: 'Explain the C2 beacon pattern',            turns: 11, context: 'incident', lastAt: 'Yesterday' },
  { id: 'C-041', title: 'Generate Stark Industries CISO report',    turns: 6,  context: 'report', lastAt: 'Yesterday' },
  { id: 'C-040', title: 'Find Linux servers missing patches',        turns: 5,  context: 'fleet',  lastAt: 'Mon' },
  { id: 'C-039', title: 'ATT&CK coverage gaps for lateral movement', turns: 9, context: 'detect', lastAt: 'Mon' },
];

export const BOOKMARKS: Bookmark[] = [
  { id: 'BK-01', label: 'INC-0524 — Privilege Escalation (DC-01)',  href: '/investigate/queue', kind: 'incident',  pinned: true,  time: 'Today' },
  { id: 'BK-02', label: 'Marketing-Laptop-12 asset graph',           href: '/network/map',       kind: 'asset',     pinned: true,  time: 'Today' },
  { id: 'BK-03', label: 'Credential stuffing detection rule',        href: '/detect/feed',       kind: 'detection', pinned: false, time: 'Yesterday' },
  { id: 'BK-04', label: 'RPT-0088 Executive Summary',                href: '/investigate/queue', kind: 'report',    pinned: false, time: 'Yesterday' },
  { id: 'BK-05', label: 'Auto-contain C2 playbook (v3)',             href: '/automate/playbooks',kind: 'playbook',  pinned: true,  time: 'Mon' },
  { id: 'BK-06', label: 'Soylent Corp — QSecBit 28 alert',           href: '/investigate/queue', kind: 'incident',  pinned: false, time: 'Mon' },
];

export const DRAFT_PLAYBOOKS: DraftPlaybook[] = [
  { id: 'PB-012', name: 'Auto-Contain Credential Stuffing',   stage: 'approved', triggers: 'T1110 + blocked:false + burst:>50/min',  lastEdit: 'Today 11:30',     steps: 6 },
  { id: 'PB-011', name: 'Ransomware Early-Warning Response',  stage: 'review',   triggers: 'YARA match + confidence:>85%',            lastEdit: 'Today 09:10',     steps: 8 },
  { id: 'PB-010', name: 'Lateral Movement Containment',       stage: 'draft',    triggers: 'T1021 from non-admin + cross-subnet',     lastEdit: 'Yesterday 17:40', steps: 5 },
  { id: 'PB-009', name: 'IOC Enrichment Auto-Notify',         stage: 'approved', triggers: 'MISP feed match + severity:high',         lastEdit: 'Mon 14:20',       steps: 4 },
  { id: 'PB-008', name: 'DNS Tunneling Block + Alert',        stage: 'review',   triggers: 'T1572 + dns_entropy:>3.5 + sustained:2m', lastEdit: 'Mon 10:05',       steps: 5 },
];
