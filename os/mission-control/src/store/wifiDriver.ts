/**
 * wifiDriver — `/api/health` `wifi_driver` (ADR 0065: the Wi-Fi driver out of the kernel; shape agreed with the heqk
 * session 2026-11-15). Every value is a measured counter. Nothing is shown until the device reports the field.
 *
 *   bus:      { state: running|backoff|absent|handed_to_wifiheal, restarts, faults, last_fault_ts|null }
 *   security: { state: running|backoff|absent, restarts, faults, full_wipes, last_fault_ts|null, pmksa_entries } | null
 *
 * "absent" = the EL0 server did not load and the in-kernel fallback is serving: Wi-Fi works without fault isolation.
 * On metal that once happened silently, so it is always a warning. full_wipes > 0 = every station had to re-authenticate.
 */
import { createSignal } from 'solid-js';

export interface WifiBus { state: string; restarts: number; faults: number; last_fault_ts: number | null }
export interface WifiSec extends WifiBus { full_wipes: number; pmksa_entries: number }
export interface WifiDriver { bus: WifiBus; security: WifiSec | null }

export const [wifiDriver, setWifiDriver] = createSignal<WifiDriver | null>(null);

const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);
const ts = (v: unknown) => (typeof v === 'number' && v > 0 ? v : null);

/** Accepts only the agreed shape (a missing or malformed field shows nothing rather than a guess). */
export function parseWifiDriver(v: unknown): WifiDriver | null {
  if (!v || typeof v !== 'object') return null;
  const o = v as Record<string, any>;
  if (!o.bus || typeof o.bus.state !== 'string') return null;
  const bus: WifiBus = { state: o.bus.state, restarts: num(o.bus.restarts), faults: num(o.bus.faults), last_fault_ts: ts(o.bus.last_fault_ts) };
  const s = o.security;
  const security: WifiSec | null = s && typeof s.state === 'string'
    ? { state: s.state, restarts: num(s.restarts), faults: num(s.faults), full_wipes: num(s.full_wipes), last_fault_ts: ts(s.last_fault_ts), pmksa_entries: num(s.pmksa_entries) }
    : null;
  return { bus, security };
}

function at(t: number | null): string {
  if (!t) return '';
  const d = new Date(t * 1000);
  const same = d.toDateString() === new Date().toDateString();
  return same ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false }) : d.toLocaleDateString();
}
const times = (n: number) => (n === 1 ? 'once' : `${n} times`);

export interface DriverLine { level: 'warn' | 'note'; text: string }

/** What the operator should know, most serious first. Empty = running, no faults. */
export function driverLines(w: WifiDriver): DriverLine[] {
  const out: DriverLine[] = [];
  const b = w.bus, last = b.last_fault_ts ? ` · last fault ${at(b.last_fault_ts)}` : '';
  if (b.state === 'absent') out.push({ level: 'warn', text: 'Wi-Fi is running inside the kernel: the isolated Wi-Fi driver did not start. Wi-Fi works, but a driver fault is no longer contained.' });
  else if (b.state === 'handed_to_wifiheal') out.push({ level: 'warn', text: `The Wi-Fi driver kept failing (${b.faults} faults); Wi-Fi recovery took over and is reloading the radio firmware${last}.` });
  else if (b.state === 'backoff') out.push({ level: 'warn', text: `The Wi-Fi driver hit a fault and is restarting (restart ${b.restarts + 1})${last}.` });
  else if (b.state !== 'running') out.push({ level: 'warn', text: `Wi-Fi driver state: ${b.state}.` });
  else if (b.restarts > 0) out.push({ level: 'note', text: `The Wi-Fi driver restarted ${times(b.restarts)} after a fault${last}.` });

  const s = w.security;
  if (s) {
    const sl = s.last_fault_ts ? ` · last ${at(s.last_fault_ts)}` : '';
    if (s.state === 'absent') out.push({ level: 'warn', text: 'Wi-Fi security is running inside the kernel: the isolated security server did not start.' });
    else if (s.state === 'backoff') out.push({ level: 'warn', text: `The Wi-Fi security server hit a fault and is restarting${sl}.` });
    if (s.full_wipes > 0) out.push({ level: 'warn', text: `Wi-Fi security was reset ${times(s.full_wipes)}: every device had to reconnect${sl}.` });
    else if (s.state === 'running' && s.restarts > 0) out.push({ level: 'note', text: `The Wi-Fi security server restarted ${times(s.restarts)}${sl}.` });
  }
  return out;
}
