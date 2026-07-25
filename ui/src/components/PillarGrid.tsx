/**
 * PillarGrid — the five customer pillars as a bento grid (Layer 0, calm landing).
 *
 * Five pillars (v2-customer-experience.md §0):
 *   1. Shield        — DNS ad/tracker/malware blocking   (manifest: dns_filtering)
 *   2. My Network    — device map + Bubbles/zones        (manifest: segmentation, device_trust)
 *   3. Get Online    — WAN/Wi-Fi status + wizard         (manifest: wan, wifi_ap)
 *   4. Security      — incident status + autonomous acts (AEGIS/NAPSE/QSecBit)
 *   5. Timeline & Export — traceability + export         (evidence graph + Telemetry Fabric)
 *
 * Capability-gating rule (MissionControl.md §Cross-cutting):
 *   In this Layer-0 mock all five are granted (simulate full-featured hardware).
 *   Real implementation reads from the signed Platform Manifest; absent grants
 *   render the card greyed with a reason string, never a broken button.
 *
 * "Everything is clickable" — every card href drills into the route map.
 * Stub routes are intentional placeholders; real pages land in Phase 2.
 */

import type { Component } from 'solid-js';
import { shield, network, connectivity, security, timeline } from '../store/mock';

// ── PillarCard — reusable bento cell ────────────────────────────────────────

interface CardProps {
  ctx:        string;
  title:      string;
  icon:       string;
  kpi:        string;
  kpiClass?:  string;
  sub:        string;
  detail?:    string;
  badge:      string;
  badgeClass: string;
  href:       string;
  action:     string;
}

const PillarCard: Component<CardProps> = (props) => (
  <a
    href={props.href}
    class="pillar-card hp-terminal"
    aria-label={`${props.title}: ${props.sub}`}
  >
    <div class="hp-terminal-bar pillar-term-bar">
      <span class="hp-dot red" aria-hidden="true" />
      <span class="hp-dot yellow" aria-hidden="true" />
      <span class="hp-dot green" aria-hidden="true" />
      <span class="hp-terminal-title">hookprobe@edge ~ {props.ctx}</span>
    </div>
    <div class="pillar-card-body">
    <div class="pillar-card-header">
      <span class="pillar-card-icon" aria-hidden="true">{props.icon}</span>
      <span class={`pillar-card-badge ${props.badgeClass}`}>{props.badge}</span>
    </div>

    <div class="pillar-card-label">{props.title}</div>

    <div class={`pillar-card-kpi${props.kpiClass ? ` ${props.kpiClass}` : ''}`}>
      {props.kpi}
    </div>

    <div class="pillar-card-sub">{props.sub}</div>

    {props.detail && (
      <div class="pillar-card-detail">{props.detail}</div>
    )}

    <div class="pillar-card-action" aria-hidden="true">
      {props.action}
      <svg
        width="11" height="11" viewBox="0 0 24 24"
        fill="none" stroke="currentColor" stroke-width="2"
        stroke-linecap="round" stroke-linejoin="round"
      >
        <path d="M5 12h14M12 5l7 7-7 7" />
      </svg>
    </div>
    </div>
  </a>
);

// ── PillarGrid — bento layout ────────────────────────────────────────────────

const PillarGrid: Component = () => {
  // Reading signals inside JSX → fine-grained reactive; if a signal changes
  // only the specific DOM text nodes update (no VDOM diff — that's SolidJS).
  return (
    <div class="pillar-wrapper">

      {/* Row 1 — two wide cards (the two most-touched by Sam daily) */}
      <div class="pillar-row-2">

        {/* ── Pillar 1: Shield (DNS / ad-blocker) ── */}
        <PillarCard
          ctx="shield"
          title="Shield"
          icon="🛡"
          kpi={shield().adsBlocked.toLocaleString()}
          sub={`ads, trackers & ${shield().malwareStopped} malware sites blocked today`}
          detail="dnsXai resolver · protecting all devices · on since setup"
          badge="Active"
          badgeClass="badge--green"
          href="/network/dns"
          action="Manage"
        />

        {/* ── Pillar 2: My Network (device map + Bubbles) ── */}
        <PillarCard
          ctx="network"
          title="My Network"
          icon="🌐"
          kpi={`${network().devices} devices`}
          sub={`${network().online} online · ${network().zones} zones`}
          detail="Family · Smart Home · Guests · 1 in Quarantine"
          badge="All mapped"
          badgeClass="badge--blue"
          href="/network/map"
          action="Open map"
        />

      </div>

      {/* Row 2 — three narrower cards */}
      <div class="pillar-row-3">

        {/* ── Pillar 3: Get Online (router / Wi-Fi) ── */}
        <PillarCard
          ctx="wan"
          title="Get Online"
          icon="⚡"
          kpi={connectivity().online ? 'Online' : 'Offline'}
          kpiClass={connectivity().online ? 'kpi--green' : 'kpi--amber'}
          sub={`${connectivity().wanStatus} · ${connectivity().aps} APs`}
          detail={`↓ ${connectivity().downMbps} Mbps · ↑ ${connectivity().upMbps} Mbps`}
          badge={connectivity().online ? 'Connected' : 'Check WAN'}
          badgeClass={connectivity().online ? 'badge--green' : 'badge--amber'}
          href="/network/wan"
          action="Settings"
        />

        {/* ── Pillar 4: Security (SIEM/SOC understood + controlled) ── */}
        <PillarCard
          ctx="security"
          title="Security"
          icon="🔐"
          kpi={security().openIncidents === 0 ? 'All clear' : `${security().openIncidents} open`}
          kpiClass={security().openIncidents === 0 ? 'kpi--green' : ''}
          sub={
            security().openIncidents === 0
              ? 'All incidents contained'
              : `${security().openIncidents} incident${security().openIncidents !== 1 ? 's' : ''} need attention`
          }
          detail={`${security().autonomousActions} actions taken autonomously today`}
          badge={security().allContained ? 'Contained' : 'Needs you'}
          badgeClass={security().allContained ? 'badge--green' : 'badge--amber'}
          href="/investigate/queue"
          action="Review"
        />

        {/* ── Pillar 5: Timeline & Export ── */}
        <PillarCard
          ctx="timeline"
          title="Timeline & Export"
          icon="📋"
          kpi={`${timeline().retentionDays}d`}
          sub="fully traceable · export ready"
          detail={`${timeline().storedGb} GB stored · number → event → packet → raw`}
          badge="Ready"
          badgeClass="badge--grey"
          href="/observe/events"
          action="Open"
        />

      </div>
    </div>
  );
};

export default PillarGrid;
