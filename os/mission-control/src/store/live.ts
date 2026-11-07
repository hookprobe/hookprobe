/**
 * live — Mission Control's real-data layer for the standalone Layer-0 landing (`/`).
 *
 * Wires the EXISTING mock signals (`store/mock.ts`) to the real `hookprobe-api` read-API
 * (ADR 0001: Rust/Axum, read-only over `crates/hookprobe-evidence`'s SQLite evidence graph) —
 * this is the "one real UI workspace off mocks end-to-end" proof: Organism Status orb +
 * Security pillar / "needs you" queue on the calm landing page.
 *
 * Fetch-and-subscribe, never a hard dependency: if the API is unreachable (a dev box with no
 * `evidence.db` / no `hookprobe-api` running, or a device that hasn't first-booted yet), every
 * signal this module would update simply keeps its `store/mock.ts` default — the existing
 * Layer-0 mock experience is the graceful fallback, never a broken screen (same "capability-
 * gated, never a broken button" posture MissionControl.md asks of the whole UI).
 *
 * What's wired here:
 *  - Organism Status orb: `GET /api/qsecbit` → the resilience% + heartbeat sparkline.
 *    QSECBIT's `score` is a RISK score in `[0,1]`, LOWER = healthier (see
 *    `modules/qsecbit/src/lib.rs`'s `QsecbitOutput` doc comment: "A resilience percentage can
 *    be derived as `(1.0 − score) * 100.0`") — `resiliencePct` below applies exactly that.
 *  - Security pillar / "needs you": `GET /api/incidents` → open-incident count.
 *  - Live updates: `GET /api/stream` (SSE) → qsecbit/incident deltas as they land, so the orb
 *    and the incident count update without a page reload ("Living, not refreshing").
 *
 * What's NOT wired (stays on mock — no ingest path into the evidence graph yet for these):
 *  Shield (ads/malware blocked counts), My Network (device/zone counts), Get Online (WAN/Wi-Fi
 *  status), Timeline & Export's retention/storage figures, and `autonomousActions` (no
 *  `responses`-table read-API endpoint yet). The Mission Control (`/mission`) MSSP dashboard and
 *  the Investigate incident-story/hypotheses narrative also stay fully mocked — see the
 *  hookprobe-api build report for the complete list.
 */

import { setQsecbit, setHeartbeat, setSecurity, setLastChecked, security } from './mock';
import {
  fetchJson, openStream, parseStreamPayload,
  type QsecbitScoreRow, type QsecbitResponse, type IncidentRow, type IncidentsResponse,
} from './api';

/** qsecbit's `score` is risk in `[0,1]`, lower = healthier; Mission Control shows resilience%. */
function resiliencePct(score: number): number {
  return Math.max(0, Math.min(100, Math.round((1 - score) * 100)));
}

/** `EvidenceGraph::list_qsecbit` orders newest-first; the sparkline wants chronological order. */
function applyQsecbitHistory(history: QsecbitScoreRow[]): void {
  if (history.length === 0) {
    return;
  }
  const chrono = [...history].reverse().map((r) => resiliencePct(r.score));
  // A 1-point sparkline renders as a dot, not a line — pad so `heartbeat`'s consumers (which all
  // assume >=2 points, e.g. OrganismOrb's polyline) never receive a degenerate array.
  setHeartbeat(chrono.length >= 2 ? chrono.slice(-20) : [...chrono, ...chrono]);
  setQsecbit(resiliencePct(history[0].score));
}

function applyIncidents(incidents: IncidentRow[]): void {
  const open = incidents.filter((i) => i.status !== 'resolved' && i.status !== 'closed');
  setSecurity({
    openIncidents: open.length,
    allContained: open.length === 0,
    // no `responses`-table read-API endpoint yet (see this module's doc comment) — keep the
    // existing mock value rather than fabricate a number with no backing data.
    autonomousActions: security().autonomousActions,
  });
}

let started = false;

/**
 * Call once from `App.tsx`'s `onMount` (client-only — fetch/EventSource don't exist during
 * Astro's build-time pre-render). Idempotent: a second call is a no-op, so it's safe to call
 * unconditionally. Returns `true` if the initial fetch succeeded (live data is now driving the
 * signals — the caller should skip starting its own mock random-walk), `false` if the API was
 * unreachable (the caller's mock fallback should run as before).
 */
export async function startLiveUpdates(): Promise<boolean> {
  if (started) {
    return true;
  }

  try {
    const [qsecbitRes, incidentsRes] = await Promise.all([
      fetchJson<QsecbitResponse>('/api/qsecbit?limit=20'),
      fetchJson<IncidentsResponse>('/api/incidents?limit=50'),
    ]);
    applyQsecbitHistory(qsecbitRes.history ?? []);
    applyIncidents(incidentsRes.incidents ?? []);
    setLastChecked('just now');
    started = true;
  } catch (e) {
    // API unreachable (dev box, or a device that hasn't first-booted yet) — stay on the mock
    // values already seeded in store/mock.ts. Never throw into the caller; a dashboard must
    // render something even when its data source is down.
    // eslint-disable-next-line no-console
    console.debug('[hookprobe] live API unavailable, staying on mock data:', e);
    return false;
  }

  try {
    const es = openStream();
    es.addEventListener('update', (ev) => {
      const message = ev as MessageEvent<string>;
      const payload = parseStreamPayload(message.data);
      if (!payload) {
        console.debug('[hookprobe] malformed SSE payload, ignoring this tick');
        return;
      }
      if (payload.qsecbit && payload.qsecbit.length > 0) {
        const latest = payload.qsecbit[payload.qsecbit.length - 1];
        const pct = resiliencePct(latest.score);
        setQsecbit(pct);
        setHeartbeat((prev) => [...prev.slice(1), pct]);
        setLastChecked('just now');
      }
      if (payload.incidents && payload.incidents.length > 0) {
        // Re-fetch the authoritative open-incident list rather than hand-accumulating deltas
        // (a status change on an EXISTING incident wouldn't show up as a "new" SSE row anyway).
        fetchJson<IncidentsResponse>('/api/incidents?limit=50')
          .then((r) => applyIncidents(r.incidents ?? []))
          .catch(() => {
            /* transient — the next tick will retry */
          });
      }
    });
    es.onerror = () => {
      // EventSource auto-reconnects on transient network errors; nothing to do here except not
      // let an unhandled error surface as a console exception on every retry.
    };
  } catch (e) {
    console.debug('[hookprobe] SSE stream failed to open, staying on the last fetched values:', e);
  }

  return true;
}
