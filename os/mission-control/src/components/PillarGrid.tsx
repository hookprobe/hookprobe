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
import { shield, network, connectivity, security, timeline, substrate, deviceStats } from '../store/mock';

/** The device (heqk) has no source for these tiles yet — never show demo numbers as its own. */
const unreported = () => substrate() === 'heqk';
/** The AP's own WAN facts (heqk AP image only; null on the passive sensor). */
const devWan = () => deviceStats()?.wan ?? null;
const hhmm = (sec: number) => new Date(sec * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const NA = { kpi: '—', sub: 'Not reported by this device yet', badge: 'No data', badgeClass: 'badge--grey' };

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
          kpi={unreported() ? (devWan() ? (devWan()!.blocklist > 0 ? devWan()!.dnsBlocked : devWan()!.dnsInspected).toLocaleString() : NA.kpi) : shield().adsBlocked.toLocaleString()}
          sub={unreported() ? (devWan() ? (devWan()!.blocklist > 0 ? `blocked of ${devWan()!.dnsInspected.toLocaleString()} DNS queries` : 'DNS queries inspected by the IDS') : NA.sub) : `ads, trackers & ${shield().malwareStopped} malware sites blocked today`}
          detail={unreported() ? (devWan() ? (devWan()!.blocklist > 0 ? `blocklist: ${devWan()!.blocklist.toLocaleString()} domains · answered on this device` : 'every client resolves through this device · no blocklist loaded') : undefined) : 'dnsXai resolver · protecting all devices · on since setup'}
          badge={unreported() ? (devWan() ? (devWan()!.blocklist > 0 ? 'Active' : 'Inspecting') : NA.badge) : 'Active'}
          badgeClass={unreported() ? (devWan() ? (devWan()!.blocklist > 0 ? 'badge--green' : 'badge--blue') : NA.badgeClass) : 'badge--green'}
          href="/network/dns"
          action="Manage"
        />

        {/* ── Pillar 2: My Network (device map + Bubbles) ── */}
        <PillarCard
          ctx="network"
          title="My Network"
          icon="🌐"
          kpi={unreported() ? (deviceStats() ? `${deviceStats()!.hostsActive} devices` : NA.kpi) : `${network().devices} devices`}
          sub={unreported() ? (deviceStats() ? 'active on this network · last 10 min' : NA.sub) : `${network().online} online · ${network().zones} zones`}
          detail={unreported() ? (deviceStats() ? 'passive: seen by the sensor, nothing is scanned' : undefined) : 'Family · Smart Home · Guests · 1 in Quarantine'}
          badge={unreported() ? (deviceStats() ? 'Live' : NA.badge) : 'All mapped'}
          badgeClass={unreported() ? (deviceStats() ? 'badge--green' : NA.badgeClass) : 'badge--blue'}
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
          kpi={unreported() ? (devWan() ? (devWan()!.up ? 'Online' : 'Offline') : NA.kpi) : connectivity().online ? 'Online' : 'Offline'}
          kpiClass={unreported() ? (devWan() ? (devWan()!.up ? 'kpi--green' : 'kpi--amber') : undefined) : connectivity().online ? 'kpi--green' : 'kpi--amber'}
          sub={unreported() ? (devWan() ? `${devWan()!.mode.toUpperCase()} · ${devWan()!.clients} Wi-Fi client${devWan()!.clients === 1 ? '' : 's'}` : NA.sub) : `${connectivity().wanStatus} · ${connectivity().aps} APs`}
          detail={unreported() ? (devWan() ? `WAN ${devWan()!.ip}${devWan()!.ipv6 ? ' · IPv6' : ''} · ${devWan()!.pktsOut.toLocaleString()} out / ${devWan()!.pktsIn.toLocaleString()} in` : undefined) : `↓ ${connectivity().downMbps} Mbps · ↑ ${connectivity().upMbps} Mbps`}
          badge={unreported() ? (devWan() ? (devWan()!.up ? 'Connected' : 'Check WAN') : NA.badge) : connectivity().online ? 'Connected' : 'Check WAN'}
          badgeClass={unreported() ? (devWan() ? (devWan()!.up ? 'badge--green' : 'badge--amber') : NA.badgeClass) : connectivity().online ? 'badge--green' : 'badge--amber'}
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
          detail={unreported() ? 'detections, verdicts & incidents from this device' : `${security().autonomousActions} actions taken autonomously today`}
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
          kpi={unreported() ? (deviceStats() ? `${deviceStats()!.detections}` : NA.kpi) : `${timeline().retentionDays}d`}
          sub={unreported() ? (deviceStats() ? `detections kept (newest ${deviceStats()!.detectionsCap})` : NA.sub) : 'fully traceable · export ready'}
          detail={unreported() ? (deviceStats() ? [
            deviceStats()!.oldestDetection > 0 ? `since ${hhmm(deviceStats()!.oldestDetection)}` : '',
            deviceStats()!.sealedCap > 0 ? `newest ${deviceStats()!.sealedCap} sealed across reboot` : 'not kept across reboot',
          ].filter(Boolean).join(' · ') : undefined) : `${timeline().storedGb} GB stored · number → event → packet → raw`}
          badge={unreported() ? (deviceStats() ? 'Bounded' : NA.badge) : 'Ready'}
          badgeClass="badge--grey"
          href="/observe/events"
          action="Open"
        />

      </div>
    </div>
  );
};

export default PillarGrid;
