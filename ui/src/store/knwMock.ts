/**
 * knwMock — Knowledge (§11) Layer-0 mock data.
 *
 * Spec: docs/MissionControl.md §11 — the growth engine: Blog CMS, SEO AI,
 * keyword research, page/video generator, runbooks, SOP, wiki, AI Writer.
 * Content + security knowledge share the same AI layer and evidence graph —
 * a post-incident write-up, a runbook, and a blog post are lenses on the
 * same material. Drives marketing/SEO from inside the platform.
 *
 * Real values will stream from Rust/Axum (ADR 0001) over SSE/WS; shapes
 * here are what those feeds will carry.
 */

import type { Tone } from './missionMock';

export type ContentStatus = 'published' | 'draft' | 'review';
export type ContentType   = 'post' | 'runbook' | 'sop' | 'wiki' | 'doc';
export type KwDifficulty  = 'easy' | 'medium' | 'hard';

export interface ContentItem {
  id:        string;
  title:     string;
  type:      ContentType;
  status:    ContentStatus;
  seoScore:  number;   // 0-100; rendered with tone (green ≥80, amber ≥60, red <60)
  updatedAt: string;
  author:    string;
}

export interface SeoKeyword {
  keyword:    string;
  volume:     string;          // e.g. "8,100/mo"
  rank:       number | null;   // null = not yet ranking
  delta:      number;          // negative = rank improved (went up)
  difficulty: KwDifficulty;
}

export interface AiSuggestion {
  id:       string;
  prompt:   string;
  category: 'incident' | 'runbook' | 'seo' | 'blog';
}

export interface Kpi { label: string; value: string; tone: Tone }

export const KPIS: Kpi[] = [
  { label: 'Published',         value: '48',     tone: 'green'  },
  { label: 'Drafts',            value: '14',     tone: 'amber'  },
  { label: 'Avg SEO Score',     value: '74',     tone: 'blue'   },
  { label: 'Keywords Tracked',  value: '1,240',  tone: 'purple' },
  { label: 'Avg Rank',          value: '#12',    tone: 'green'  },
];

export const CONTENT_ITEMS: ContentItem[] = [
  { id: 'c1', title: 'Post-Incident Report: Brute Force Burst 2026-06-29',  type: 'runbook', status: 'review',    seoScore: 88, updatedAt: '10m ago', author: 'AEGIS AI' },
  { id: 'c2', title: 'How HookProbe Blocks Ransomware Before Encryption',   type: 'post',    status: 'published', seoScore: 91, updatedAt: '2h ago',  author: 'Admin'    },
  { id: 'c3', title: 'Zero-Trust Network Segmentation — Getting Started',   type: 'post',    status: 'published', seoScore: 85, updatedAt: '1d ago',  author: 'Admin'    },
  { id: 'c4', title: 'NAPSE Suricata Rule Tuning SOP',                      type: 'sop',     status: 'draft',     seoScore: 42, updatedAt: '3d ago',  author: 'Admin'    },
  { id: 'c5', title: 'DNS Tunneling Detection: Analyst Wiki',                type: 'wiki',    status: 'published', seoScore: 78, updatedAt: '4d ago',  author: 'Admin'    },
  { id: 'c6', title: 'Deploying HookProbe OS on Raspberry Pi 5',            type: 'doc',     status: 'published', seoScore: 94, updatedAt: '5d ago',  author: 'Admin'    },
  { id: 'c7', title: 'SOC on a Budget: FortiSOC vs HookProbe OS 2026',      type: 'post',    status: 'draft',     seoScore: 67, updatedAt: '6d ago',  author: 'Admin'    },
];

export const SEO_KEYWORDS: SeoKeyword[] = [
  { keyword: 'open source SIEM',              volume: '8,100/mo', rank: 6,    delta: -2, difficulty: 'hard'   },
  { keyword: 'network detection response',    volume: '5,400/mo', rank: 11,   delta: +1, difficulty: 'hard'   },
  { keyword: 'raspberry pi firewall',         volume: '4,900/mo', rank: 3,    delta: -4, difficulty: 'medium' },
  { keyword: 'hookprobe os review',           volume: '1,200/mo', rank: 1,    delta:  0, difficulty: 'easy'   },
  { keyword: 'edge soc linux',               volume: '2,700/mo', rank: 14,   delta: -1, difficulty: 'medium' },
  { keyword: 'suricata rules tutorial',       volume: '6,600/mo', rank: 22,   delta: -5, difficulty: 'hard'   },
  { keyword: 'post incident report template', volume: '3,300/mo', rank: 8,    delta: -2, difficulty: 'medium' },
];

export const AI_SUGGESTIONS: AiSuggestion[] = [
  { id: 's1', prompt: 'Generate a post-incident write-up for the brute-force burst at 12:46', category: 'incident' },
  { id: 's2', prompt: 'Draft a runbook for DNS tunneling response',                            category: 'runbook'  },
  { id: 's3', prompt: 'Write a SEO blog post targeting "edge soc linux"',                     category: 'seo'      },
];
