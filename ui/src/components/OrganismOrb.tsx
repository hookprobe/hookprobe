/**
 * OrganismOrb — the signature element of Mission Control.
 *
 * Spec (MissionControl.md §Design language):
 *   "Signature element: the Organism Status — a glowing orb with the live
 *    QSecBit score and a heartbeat sparkline. It is the one bold thing;
 *    everything around it stays quiet."
 *
 * Spec (v2-customer-experience.md §2.2):
 *   "Plain-language verdict first. The QSecBit number is secondary to the
 *    sentence."
 *
 * Accessibility:
 *   - aria-label on SVG carries the numeric + status meaning
 *   - Verdict sentence is role="status" (live region for screen readers)
 *   - Color is never the only signal (PROTECTED text + icon)
 *   - Motion degrades gracefully via CSS prefers-reduced-motion
 *
 * Reactivity:
 *   - qsecbit and heartbeat are Solid signals; fine-grained DOM updates
 *     via createMemo mean only the arc dasharray + polyline points change
 *     when the interval fires — no full re-render.
 */

import { type Component, createMemo } from 'solid-js';
import { qsecbit, heartbeat, lastChecked } from '../store/mock';

const R  = 88;    // arc radius (px)
const CX = 110;   // SVG center x
const CY = 110;   // SVG center y
const C  = 2 * Math.PI * R; // circumference ≈ 552.9

const OrganismOrb: Component = () => {
  /** Length of the filled arc segment (reactive) */
  const arcFilled = createMemo(() => (qsecbit() / 100) * C);

  /**
   * SVG polyline `points` attribute for the heartbeat sparkline.
   * Input: array of values in [60, 100].
   * Maps to a 160×24 viewBox so the sparkline stays compact but readable.
   */
  const sparkPoints = createMemo(() => {
    const data   = heartbeat();
    const W = 160, H = 24;
    const min = 60, range = 40; // values live in [60, 100]
    return data
      .map((v, i) => {
        const x = ((i / (data.length - 1)) * W).toFixed(1);
        const y = (H - ((v - min) / range) * H).toFixed(1);
        return `${x},${y}`;
      })
      .join(' ');
  });

  return (
    <section class="hero-section hp-terminal" aria-labelledby="organism-verdict">
      <div class="hp-terminal-bar">
        <span class="hp-dot red" aria-hidden="true" />
        <span class="hp-dot yellow" aria-hidden="true" />
        <span class="hp-dot green" aria-hidden="true" />
        <span class="hp-terminal-title">hookprobe@edge ~ status</span>
      </div>
      <div class="hero-body">
      <div class="hero-cmd" aria-hidden="true">
        <span class="hp-prompt">$</span><span class="hp-cmd">hookprobe status</span> <span class="hp-blink">_</span>
      </div>
      {/* ── Radial gauge ── */}
      <div class="orb-wrapper">
        <svg
          class="orb-svg"
          viewBox="0 0 220 220"
          width="220"
          height="220"
          role="img"
          aria-label={`QSecBit security score ${qsecbit()} out of 100 — network protected`}
        >
          <defs>
            {/* Green → purple gradient matches the color language */}
            <linearGradient id="orbGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%"   stop-color="#00B4FF" />
              <stop offset="100%" stop-color="#00FF9D" />
            </linearGradient>
          </defs>

          {/* Background track */}
          <circle
            cx={CX} cy={CY} r={R}
            fill="none"
            stroke="rgba(255,255,255,0.05)"
            stroke-width="10"
          />

          {/* Score arc — reactive via arcFilled memo */}
          <circle
            cx={CX} cy={CY} r={R}
            fill="none"
            stroke="url(#orbGrad)"
            stroke-width="10"
            stroke-linecap="round"
            stroke-dasharray={`${arcFilled()} ${C}`}
            transform={`rotate(-90 ${CX} ${CY})`}
          />

          {/* Score — bold number (secondary to the verdict sentence) */}
          <text
            x={CX} y={CY - 8}
            text-anchor="middle"
            dominant-baseline="middle"
            class="orb-score-text"
          >
            {qsecbit()}
          </text>

          {/* "QSECBIT" label — the one place the technical name is shown */}
          <text
            x={CX} y={CY + 22}
            text-anchor="middle"
            class="orb-label-text"
          >
            QSECBIT
          </text>
        </svg>
      </div>

      {/* ── Verdict + sparkline ── */}
      <div class="verdict-block">
        {/*
         * Plain-language verdict first (v2-customer-experience.md §2.2).
         * role="status" → polite live region; screen readers announce updates.
         * Color-not-sole-signal: "PROTECTED" text + shield meaning is explicit.
         */}
        <div
          id="organism-verdict"
          class="verdict-status"
          role="status"
          aria-live="polite"
        >
          YOU'RE PROTECTED
        </div>

        <p class="verdict-message">Nothing needs you right now.</p>

        <div class="verdict-meta">
          <span>Last checked {lastChecked()}</span>
          <span aria-hidden="true">·</span>
          <span>heartbeat</span>
          {/* Sparkline — aria-hidden; the numeric score carries the meaning */}
          <div class="sparkline-wrap" aria-hidden="true">
            <svg
              class="sparkline-svg"
              viewBox="0 0 160 24"
              width="72"
              height="11"
            >
              <polyline
                points={sparkPoints()}
                fill="none"
                stroke="#00FF9D"
                stroke-width="1.6"
                stroke-linecap="round"
                stroke-linejoin="round"
                opacity="0.75"
              />
            </svg>
          </div>
        </div>

        {/* Drills into evidence graph (v2-customer-experience.md §2.2 "What happened today") */}
        <a href="/investigate/queue" class="verdict-cta">
          What happened today
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
      </div>
    </section>
  );
};

export default OrganismOrb;
