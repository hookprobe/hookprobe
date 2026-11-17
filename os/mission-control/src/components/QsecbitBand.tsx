/**
 * QsecbitBand — the QSECBIT status band on Mission Control and, behind "Dig deeper", its sliding
 * window: samples per band, the band shifts, and the detections behind each drop.
 *
 *   🟢 GREEN  All clear · Protected      risk < 0.30   (resilience 71–100)
 *   🟡 AMBER  Monitoring · Stay alert    risk < 0.70   (resilience 31–70)
 *   🔴 RED    Under attack · Defending   risk ≥ 0.70   (resilience 0–30)
 *
 * Thresholds are the device's own (`mcstate.rs::band`); the band string the device sends wins.
 * The device sends no sub-scores, so a shift is explained by the detections in the 5 minutes
 * before it, never by invented components.
 */
import { type Component, For, Show, createMemo } from 'solid-js';
import { formatTime } from '../store/api';
import { BAND_TEXT, bandShifts, explainShift, rowBand, shiftSignals, windowStats, type Band, type DetectionRowX } from '../store/explain';
import type { QsecbitScoreRow } from '../store/api';

/** Preview only (no device): a labelled sample history, newest first. */
export const SAMPLE_QS: QsecbitScoreRow[] = [
  { ts: 1_700_003_600, score: 0.08, band: 'GREEN' },
  { ts: 1_700_002_700, score: 0.22, band: 'GREEN' },
  { ts: 1_700_001_800, score: 0.41, band: 'AMBER' },
  { ts: 1_700_000_900, score: 0.12, band: 'GREEN' },
];

const ORDER: Band[] = ['GREEN', 'AMBER', 'RED'];
const RANGE: Record<Band, string> = { GREEN: 'resilience 71–100', AMBER: 'resilience 31–70', RED: 'resilience 0–30' };

interface Props { history: QsecbitScoreRow[]; dets: DetectionRowX[]; sample: boolean; loaded: boolean }

export const QsecbitBanner: Component<Props> = (p) => {
  const latest = () => [...p.history].sort((a, b) => b.ts - a.ts)[0];
  const band = () => (latest() ? rowBand(latest()!) : null);
  const w = createMemo(() => windowStats(p.history));
  return (
    <Show when={band()} fallback={
      <div class="qs-band" role="status"><span class="qs-band-word">QSecBit</span><span class="pcard-note">{p.loaded ? 'No score yet: the device has not scored its risk window.' : 'Waiting for the device score…'}</span></div>
    }>
      <div class={`qs-band qs-band--${band()}`} role="status" aria-label={`QSecBit ${band()}: ${BAND_TEXT[band()!].line}`}>
        <span aria-hidden="true">{BAND_TEXT[band()!].mark}</span>
        <span class="qs-band-word">{band()}</span>
        <span>{BAND_TEXT[band()!].line}</span>
        <span class="pcard-note">{p.sample ? 'Sample data' : `updated ${formatTime(latest()!.ts)}`}</span>
        <span class="qs-band-score" title="Resilience = 100 − risk × 100">{w().latest ?? '—'}</span>
      </div>
    </Show>
  );
};

/** The sliding-window breakdown, for the Dig-deeper drawer. */
export const QsecbitDeep: Component<Props> = (p) => {
  const w = createMemo(() => windowStats(p.history));
  const shifts = createMemo(() => bandShifts(p.history).slice(0, 5));
  return (
    <>
      <section aria-label="Sliding window">
        <p class="l0-label">Sliding window · {w().n} sample{w().n === 1 ? '' : 's'}{w().n ? ` · ${formatTime(w().fromTs)} – ${formatTime(w().toTs)}` : ''}</p>
        <Show when={w().n > 0} fallback={<p class="pcard-note">No samples yet.</p>}>
          <span class="prow"><span>Resilience now</span><span>{w().latest}</span></span>
          <span class="prow"><span>Lowest · highest · average</span><span>{w().min} · {w().max} · {w().mean}</span></span>
          <div class="qs-bands">
            <For each={ORDER}>{(b) => (
              <span><b>{BAND_TEXT[b].mark} {b}</b><span>{BAND_TEXT[b].line}</span><span class="pcard-note">{RANGE[b]} · {w().inBand[b]} sample{w().inBand[b] === 1 ? '' : 's'}</span></span>
            )}</For>
          </div>
        </Show>
      </section>

      <section aria-label="Why the band changed">
        <p class="l0-label">Why the band changed</p>
        <Show when={shifts().length > 0} fallback={<p class="pcard-note">The band has not changed in this window.</p>}>
          <For each={shifts()}>{(s) => {
            const sig = shiftSignals(s, p.dets);
            return (
              <div class="qs-shift">
                <span class="prow"><span><b>{s.from} → {s.to}</b></span><span>{p.sample ? 'sample' : formatTime(s.ts)}</span></span>
                <span>{explainShift(s, sig)}</span>
                <Show when={sig.length > 0}>
                  <For each={sig.slice(0, 3)}>{(g) => <span class="prow"><span>{g.label}</span><span>×{g.count}{g.mitre ? ` · ${g.mitre}` : ''}</span></span>}</For>
                </Show>
              </div>
            );
          }}</For>
        </Show>
      </section>
      <p class="pcard-note">QSecBit scores risk over the device's recent window (0 = calm, 1 = under attack); resilience is 100 − risk × 100. The bands are the device's own thresholds.</p>
    </>
  );
};
