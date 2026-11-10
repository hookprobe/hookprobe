/**
 * story — "what happened", in plain words (Home's "What happened today", the Timeline & Export
 * screen). Built from the device's own records: incidents (/api/incidents), detections
 * (/api/detections) and devices that joined (/api/devices first_seen). Every item links to the
 * evidence it came from (FR-06). With no device answering, a labelled sample story is used.
 */
import { createMemo } from 'solid-js';
import { incidents, startInvestigateLive } from './investigateLive';
import { detections, startDetectLive } from './detectLive';
import { devices, refetch as refetchDevices } from './obsLive';
import { substrate } from './mock';
import { healthChecked } from './health';
import { incidentHref } from './routes';

export type StoryCat = 'Security' | 'Devices' | 'Shield' | 'Network';
export interface StoryEvent { ts: number; cat: StoryCat; title: string; sub: string; href: string; id: string }

let started = false;
export function startStory(): void {
  if (started) return;
  started = true;
  startInvestigateLive();
  startDetectLive();
  void refetchDevices();
}

/** 'sample' only when no device answered at all (preview build). */
export const storySource = (): 'live' | 'sample' | 'loading' =>
  substrate() ? 'live' : healthChecked() ? 'sample' : 'loading';

function devName(d: { label?: string | null; mdns_name?: string | null; hostname?: string | null; model?: string | null; ip: string }): string {
  return d.label || d.mdns_name || d.hostname || d.model || d.ip;
}

const live = createMemo<StoryEvent[]>(() => {
  const out: StoryEvent[] = [];
  for (const i of incidents()) {
    out.push({ id: `inc-${i.id}`, ts: i.ts, cat: 'Security', title: i.title, sub: `${i.device_ip} · ${i.priority} priority · ${i.status}`, href: incidentHref(i.id) });
  }
  // One line per rule and source (the device already collapses repeats; keep the newest).
  const seen = new Set<string>();
  for (const d of [...detections()].sort((a, b) => b.ts - a.ts)) {
    const k = `${d.rule_id}|${d.src_ip}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push({ id: `det-${d.id}`, ts: d.ts, cat: 'Security', title: d.rule_msg, sub: `${d.src_ip} → ${d.dst_ip}${d.dst_port ? `:${d.dst_port}` : ''}`, href: '/detect/feed' });
  }
  for (const d of devices()) {
    if (!d.first_seen) continue;
    const nm = devName(d);
    out.push({ id: `dev-${d.id}`, ts: d.first_seen, cat: 'Devices', title: 'New device joined', sub: nm === d.ip ? `Unnamed device · ${d.ip}` : `${nm} · ${d.ip}`, href: '/network/devices' });
  }
  return out.sort((a, b) => b.ts - a.ts);
});

function sample(): StoryEvent[] {
  const day = new Date(); day.setHours(0, 0, 0, 0);
  const at = (dayOffset: number, h: number, m: number) => day.getTime() / 1000 - dayOffset * 86400 + h * 3600 + m * 60;
  return [
    { id: 's1', ts: at(0, 16, 30), cat: 'Network', title: 'Wi-Fi channel changed', sub: 'Less interference on 5 GHz', href: '/network/wan' },
    { id: 's2', ts: at(0, 13, 5), cat: 'Security', title: 'Kitchen camera isolated', sub: 'Contacted a malware host · handled automatically', href: '/investigate/queue' },
    { id: 's3', ts: at(0, 10, 40), cat: 'Devices', title: 'New device joined', sub: 'Unnamed phone · waiting for a zone', href: '/network/zones' },
    { id: 's4', ts: at(0, 7, 12), cat: 'Shield', title: 'Blocked 1,204 trackers', sub: 'Mostly from the smart TV', href: '/network/dns' },
    { id: 's5', ts: at(1, 22, 14), cat: 'Security', title: 'Login attempts blocked', sub: '38 attempts on the router admin page from outside', href: '/investigate/queue' },
    { id: 's6', ts: at(1, 9, 2), cat: 'Network', title: 'Update installed', sub: 'HookProbe OS · no restart needed', href: '/admin/identity' },
  ];
}

export const storyEvents = (): StoryEvent[] => (storySource() === 'sample' ? sample() : live());

/** Before 2020 = the device clock is not set yet (heqk counts from boot until NTP syncs). */
const UNSYNCED_BEFORE = 1577836800;
export const isUnsynced = (ts: number) => ts < UNSYNCED_BEFORE;

/** Local-midnight epoch seconds for `ts`'s day (0 for every unsynced timestamp: one group). */
export function dayKey(ts: number): number {
  if (isUnsynced(ts)) return 0;
  const d = new Date(ts * 1000); d.setHours(0, 0, 0, 0);
  return d.getTime() / 1000;
}

export function dayLabel(key: number): string {
  if (key === 0) return 'Since this device started (its clock is not set yet)';
  const today = dayKey(Date.now() / 1000);
  if (key === today) return 'Today';
  if (key === today - 86400) return 'Yesterday';
  return new Date(key * 1000).toLocaleDateString([], { weekday: 'long', day: 'numeric', month: 'short' });
}

/** Clock time, or time since boot while the device clock is unset. */
export const hhmm = (ts: number) => {
  if (isUnsynced(ts)) {
    const m = Math.floor(ts / 60);
    return `+${Math.floor(m / 60)}h${String(m % 60).padStart(2, '0')}`;
  }
  return new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
};

/** Events since local midnight (everything since boot while the device clock is unset). */
export const todayEvents = (): StoryEvent[] => {
  const t = dayKey(Date.now() / 1000);
  return storyEvents().filter((e) => isUnsynced(e.ts) || e.ts >= t);
};
