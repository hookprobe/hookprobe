/**
 * qsecbitLive — the QSECBIT history for the band and its sliding window (`GET /api/qsecbit`).
 * `live.ts` keeps only the resilience sparkline; the band view needs the raw samples (ts, risk,
 * band) to find band shifts. Polled every 15 s; empty when no device answers.
 */
import { createSignal } from 'solid-js';
import { fetchJson, type QsecbitResponse, type QsecbitScoreRow } from './api';

/** Newest first, as the device returns it. */
export const [qsHistory, setQsHistory] = createSignal<QsecbitScoreRow[]>([]);
export const [qsLoaded, setQsLoaded] = createSignal(false);

async function read(): Promise<void> {
  try {
    const r = await fetchJson<QsecbitResponse>('/api/qsecbit?limit=1000');
    setQsHistory(Array.isArray(r.history) ? r.history : []);
    setQsLoaded(true);
  } catch {
    /* keep the last good history; the band says when it has none */
  }
}

let timer: ReturnType<typeof setInterval> | null = null;
export function startQsecbitLive(): void {
  if (timer) return;
  void read();
  timer = setInterval(() => void read(), 15_000);
}
