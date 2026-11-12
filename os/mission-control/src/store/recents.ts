/**
 * recents — Workspace's "recent and saved work" (wireframe "Workspace"; requirements doc §2).
 * The device has no per-user work store, so this lives in THIS browser (a per-viewer convenience:
 * recently opened screens and incidents, and the items you pin). Workspace says so on screen.
 * Every read/write is guarded: storage can be blocked (private window) and the page still works.
 */
import { createSignal } from 'solid-js';

export type WorkType = 'Screen' | 'Incident' | 'Device' | 'Search';
export interface WorkItem { key: string; type: WorkType; title: string; href: string; scope: string; at: number; pinned?: boolean }

const KEY = 'hp.workspace.v1';
const MAX = 40;

function read(): WorkItem[] {
  try { const v = JSON.parse(localStorage.getItem(KEY) ?? '[]'); return Array.isArray(v) ? v : []; } catch { return []; }
}
function write(items: WorkItem[]): void {
  try { localStorage.setItem(KEY, JSON.stringify(items)); } catch { /* storage blocked: kept for this page only */ }
}

export const [workItems, setWorkItems] = createSignal<WorkItem[]>([]);
export function loadWork(): void { setWorkItems(read()); }

/** Record a visit (newest first; pinned items are never evicted). */
export function remember(item: Omit<WorkItem, 'at' | 'pinned'>): void {
  const items = read();
  // one row per thing: a screen reached by several routes (My Network: /network/zones, /map, /devices) is one row
  const same = (x: WorkItem) => x.key === item.key || (x.type === item.type && x.title === item.title);
  const old = items.find(same);
  const next = [{ ...item, at: Date.now(), pinned: old?.pinned ?? false }, ...items.filter((x) => !same(x))];
  const kept = [...next.filter((x) => x.pinned), ...next.filter((x) => !x.pinned)].slice(0, MAX);
  write(kept);
  setWorkItems(kept);
}

export function togglePin(key: string): void {
  const items = read().map((x) => (x.key === key ? { ...x, pinned: !x.pinned } : x));
  write(items);
  setWorkItems(items);
}

export function clearUnpinned(): void {
  const items = read().filter((x) => x.pinned);
  write(items);
  setWorkItems(items);
}

/** Page titles for screens (the rail labels). */
export const SCREEN_TITLE: [RegExp, string][] = [
  [/^\/$/, 'Home'], [/^\/mission/, 'Mission Control'], [/^\/network\/dns/, 'Shield'], [/^\/network\/(zones|map|devices)/, 'My Network'],
  [/^\/network\/wan/, 'Get Online'], [/^\/observe\/events/, 'Timeline & Export'], [/^\/observe\/live/, 'Observe'], [/^\/detect/, 'Detect'],
  [/^\/investigate\/queue/, 'Investigate'], [/^\/protect/, 'Protect'], [/^\/automate/, 'Automate'], [/^\/intelligence/, 'Intelligence'],
  [/^\/customers/, 'Customers'], [/^\/business/, 'Business'], [/^\/knowledge/, 'Knowledge'], [/^\/admin/, 'Administration'], [/^\/setup/, 'System setup'],
];
export function screenTitle(path: string): string | null {
  for (const [re, t] of SCREEN_TITLE) if (re.test(path)) return t;
  return null;
}
