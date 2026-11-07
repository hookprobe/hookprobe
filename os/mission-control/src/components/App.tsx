/**
 * App — root Solid island for Mission Control Layer 0.
 *
 * Single client:load island rendered by src/pages/index.astro.
 * All state lives here or in store/mock.ts; no cross-island state issues.
 *
 * Responsibilities:
 *   - Start the heartbeat interval (client-only, respects prefers-reduced-motion)
 *   - Wire ⌘K / Ctrl+K + Escape keyboard shortcuts
 *   - Compose: TopBar · OrganismOrb · PillarGrid · Needs-you · CommandPalette
 *
 * Note on hydration: Astro pre-renders this to static HTML at build time.
 * Solid hydrates it on the client. The heartbeat interval starts in onMount
 * (client-only) so SSR output and initial client render match exactly.
 */

import { type Component, onMount, onCleanup } from 'solid-js';
import {
  copilotOpen, setCopilotOpen,
  copilotQuery, setCopilotQuery,
  setHeartbeat, security,
} from '../store/mock';
import { startLiveUpdates } from '../store/live';

import TopBar         from './TopBar';
import OrganismOrb    from './OrganismOrb';
import PillarGrid     from './PillarGrid';
import CommandPalette from './CommandPalette';

const App: Component = () => {
  onMount(() => {
    // ── Heartbeat interval ──────────────────────────────────────────────────
    // Shift the sparkline left and append a new value every 2 seconds.
    // Skipped entirely when the user prefers reduced motion — the static
    // orb still displays the current score (motion is never load-bearing).
    const noMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    let heartbeatIv: ReturnType<typeof setInterval> | undefined;

    // Try the real evidence-graph read-API first (store/live.ts). If it's reachable, real
    // qsecbit/incident data now drives the signals via its own SSE subscription, and the mock
    // random-walk below must NOT run (it would immediately overwrite real values with noise).
    // If the API is unreachable (dev box, pre-first-boot device), fall back to the original
    // Layer-0 mock random walk exactly as before — never a broken orb.
    void startLiveUpdates().then((live) => {
      if (live || noMotion) {
        return;
      }
      heartbeatIv = setInterval(() => {
        setHeartbeat((prev) => {
          const next = prev.slice(1);
          const last  = next[next.length - 1] ?? 90;
          // Random walk staying close to the current QSecBit region
          const delta = (Math.random() - 0.45) * 8;
          const val   = Math.max(60, Math.min(100, last + delta));
          return [...next, Math.round(val)];
        });
      }, 2000);
    });

    // ── Keyboard shortcuts ──────────────────────────────────────────────────
    const handleKey = (e: KeyboardEvent) => {
      // ⌘K / Ctrl+K → toggle copilot
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setCopilotOpen((v) => !v);
      }
      // Escape → close copilot
      if (e.key === 'Escape' && copilotOpen()) {
        setCopilotOpen(false);
      }
    };

    window.addEventListener('keydown', handleKey);

    onCleanup(() => {
      if (heartbeatIv !== undefined) clearInterval(heartbeatIv);
      window.removeEventListener('keydown', handleKey);
    });
  });

  return (
    <>
      {/* ── Persistent chrome ─────────────────────────────────────────────── */}
      <TopBar onOpenCopilot={() => setCopilotOpen(true)} />

      {/* ── Main content ──────────────────────────────────────────────────── */}
      <main class="main-content">

        {/* The Organism orb — the ONE bold element */}
        <OrganismOrb />

        {/* Five pillar bento cards */}
        <PillarGrid />

        {/*
         * Needs-you queue — empty state (spec §2.2):
         *   "If empty, say so and show what the system handled autonomously
         *    — with a link to why (glass-box, not black-box)."
         */}
        <div class="needs-section" role="region" aria-label="Action queue">
          <div class="needs-body">
            <div class="needs-label">Needs you</div>
            {/* security().openIncidents comes from the real /api/incidents count once
                startLiveUpdates() succeeds (see store/live.ts); falls back to the Layer-0
                mock value (0) when the API is unreachable — never a broken/blank message. */}
            <p class="needs-msg">
              {security().openIncidents === 0
                ? 'Nothing to approve. Everything detected today was handled automatically.'
                : `${security().openIncidents} incident${security().openIncidents !== 1 ? 's' : ''} need your review.`}
            </p>
          </div>
          <a href="/investigate/queue" class="needs-link">
            See what we did &amp; why
            <svg
              aria-hidden="true"
              width="12" height="12" viewBox="0 0 24 24"
              fill="none" stroke="currentColor" stroke-width="2"
              stroke-linecap="round" stroke-linejoin="round"
            >
              <path d="M5 12h14M12 5l7 7-7 7" />
            </svg>
          </a>
        </div>

        {/*
         * Bottom bar (spec §2.2 "More:" row).
         * "Pro view ⤢" promotes to Layer 2 — the full 13-workspace bento.
         * Stub routes; real destinations land in Phase 2.
         */}
        <div class="bottom-bar">
          <span>More:</span>
          <a href="/network/wan">Get Online</a>
          <span class="bottom-sep" aria-hidden="true">·</span>
          <a href="/observe/events">Timeline &amp; Export</a>
          <span class="bottom-sep" aria-hidden="true">·</span>
          <button class="pro-view-btn" aria-label="Switch to Pro view (all 13 workspaces)">
            Pro view ⤢
          </button>
        </div>

      </main>

      {/* ── AI Copilot overlay ────────────────────────────────────────────── */}
      <CommandPalette
        open={copilotOpen()}
        query={copilotQuery()}
        onQuery={setCopilotQuery}
        onClose={() => { setCopilotOpen(false); setCopilotQuery(''); }}
      />
    </>
  );
};

export default App;
