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

/**
 * The Wi-Fi self-heal (kernel wifiheal.rs, /api/health): `wifi_heal` {state ok|recovering|degraded: …|rebooting, last_class,
 * kicks, bounces, reloads, after_wifi_reboot}, `wifi_boot` ("ok" or why Wi-Fi has been off since power-on), and `wifi_files`
 * ("ok", "not-loaded", "no-volume" or kind:file, only on builds that load the vendor files from the boot volume).
 */
export interface WifiHeal { state: string; last_class: string; kicks: number; bounces: number; reloads: number; after_wifi_reboot: boolean }
export interface WifiSelfHeal { heal: WifiHeal | null; boot: string | null; files: string | null }
export const [wifiSelfHeal, setWifiSelfHeal] = createSignal<WifiSelfHeal | null>(null);

export function parseWifiSelfHeal(h: Record<string, unknown>): WifiSelfHeal | null {
  const x = h.wifi_heal as Record<string, unknown> | undefined;
  const heal = x && typeof x.state === 'string'
    ? { state: x.state, last_class: typeof x.last_class === 'string' ? x.last_class : '', kicks: num(x.kicks), bounces: num(x.bounces), reloads: num(x.reloads), after_wifi_reboot: x.after_wifi_reboot === true }
    : null;
  const boot = typeof h.wifi_boot === 'string' ? h.wifi_boot : null;
  const files = typeof h.wifi_files === 'string' ? h.wifi_files : null;
  return heal || boot || files ? { heal, boot, files } : null;
}

/** wifiheal.rs BootFault::text, by name. */
const BOOT: Record<string, string> = {
  'no-chip': 'the Wi-Fi chip did not answer at power-on',
  'firmware-not-started': 'the Wi-Fi firmware did not start',
  'no-control': 'the Wi-Fi firmware started but does not answer control requests',
  'ap-start-failed': 'the access point could not be started',
  'vendor-files': "the Wi-Fi chip's vendor files are missing or were refused",
};
const CLASS: Record<string, string> = { congestion: 'congestion', 'station-sleep': 'a sleeping device', 'firmware-crash': 'a firmware crash', 'tx-freeze': 'a transmit freeze', 'bus-faults': 'bus faults' };
const FILE_KIND: Record<string, string> = { missing: 'is missing', size: 'has the wrong size', digest: 'is not the expected file' };

export function healLines(w: WifiSelfHeal): DriverLine[] {
  const out: DriverLine[] = [];
  const h = w.heal;
  if (w.boot && w.boot !== 'ok') out.push({ level: 'warn', text: `Wi-Fi has been off since start-up: ${BOOT[w.boot] ?? w.boot}. Wired LAN, WAN and management keep running.` });
  if (h) {
    if (h.state.startsWith('degraded')) out.push({ level: 'warn', text: 'Wi-Fi is off after a failed recovery and stays off until the next restart. Wired LAN, WAN and management keep running.' });
    else if (h.state === 'recovering') out.push({ level: 'warn', text: `Wi-Fi is recovering from ${CLASS[h.last_class] ?? h.last_class}; devices may drop for a moment.` });
    else if (h.state === 'rebooting') out.push({ level: 'warn', text: 'Wi-Fi recovery is restarting the device.' });
    else if (h.state !== 'ok') out.push({ level: 'warn', text: `Wi-Fi self-heal: ${h.state}.` });
  }
  if (w.files && !['ok', 'not-loaded'].includes(w.files)) {
    const [kind, file] = w.files.split(':');
    out.push({ level: 'warn', text: w.files === 'no-volume' ? 'The Wi-Fi vendor files could not be read: no firmware volume on the boot disk.' : `The Wi-Fi ${file ?? ''} file ${FILE_KIND[kind] ?? kind}.` });
  }
  if (h) {
    const parts = [h.kicks && `${h.kicks} nudge${h.kicks === 1 ? '' : 's'}`, h.bounces && `${h.bounces} radio restart${h.bounces === 1 ? '' : 's'}`, h.reloads && `${h.reloads} firmware reload${h.reloads === 1 ? '' : 's'}`].filter(Boolean);
    if (parts.length) out.push({ level: 'note', text: `Wi-Fi repaired itself since start-up: ${parts.join(', ')}${h.last_class && h.last_class !== 'healthy' ? ` (last: ${CLASS[h.last_class] ?? h.last_class})` : ''}.` });
    if (h.after_wifi_reboot) out.push({ level: 'note', text: 'This start-up follows a restart by Wi-Fi recovery.' });
  }
  return out;
}
