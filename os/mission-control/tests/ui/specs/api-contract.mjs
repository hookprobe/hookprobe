// API contract: the UI and its mocks must use the keys the kernel actually writes. Metal MB28b found the UI reading a
// boolean `live` the device never sends ("applies":"live" is what it writes) — and every spec mock had the same made-up
// key, so hundreds of checks passed against a fiction. This reads the activate reply format from the kernel source.
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..', '..', '..', '..');

export default async function (t) {
  const { ok } = t;
  const http = readFileSync(join(ROOT, 'os/kernel/kernel/src/http.rs'), 'utf8');
  // the activate reply: the write! that carries "applies" (http.rs, /api/upload/activate)
  const line = http.split('\n').find((l) => l.includes('\\"applies\\":') && l.includes('\\"needs_confirm\\":')) ?? '';
  const keys = [...line.matchAll(/\\"([a-z_]+)\\":/g)].map((m) => m[1]);
  ok(['applies', 'needs_confirm', 'window_s'].every((k) => keys.includes(k)) && !keys.includes('live'), `kernel activate reply writes ${keys.join(', ')} (no boolean "live")`);

  const ui = readFileSync(join(ROOT, 'os/mission-control/src/store/packUpload.ts'), 'utf8');
  ok(/a\.applies === 'live'/.test(ui) && /needs_confirm/.test(ui), 'the UI reads "applies" and "needs_confirm" from the activate reply');

  // every mocked activate reply that claims a live apply uses the kernel's shape
  const bad = [];
  for (const f of readdirSync(HERE).filter((x) => x.endsWith('.mjs') && x !== 'api-contract.mjs')) {
    const src = readFileSync(join(HERE, f), 'utf8');
    for (const l of src.split('\n').filter((x) => x.includes("'/api/upload/activate'") && /live/.test(x))) {
      if (!/applies: 'live'/.test(l) || /\blive: true/.test(l)) bad.push(f);
    }
  }
  ok(bad.length === 0, `spec mocks of a live activate use "applies: 'live'" like the kernel${bad.length ? ` (not: ${[...new Set(bad)].join(', ')})` : ''}`);

  // /api/health wifi_driver (ADR 0065; contract agreed with the heqk session 2026-11-15): the keys the kernel writes are the
  // keys the UI parses and the keys the spec mocks use.
  const at = http.indexOf('\\"wifi_driver\\"');
  const block = at >= 0 ? http.slice(at, http.indexOf('\n            }\n', at)) : '';
  const wkeys = [...new Set([...block.matchAll(/\\"([a-z_]+)\\":/g)].map((m) => m[1]))];
  const WANT = ['wifi_driver', 'bus', 'state', 'restarts', 'faults', 'last_fault_ts', 'security', 'full_wipes', 'pmksa_entries'];
  ok(WANT.every((k) => wkeys.includes(k)) && wkeys.every((k) => WANT.includes(k)), `kernel /api/health wifi_driver writes exactly the agreed keys (${wkeys.join(', ') || 'none found'})`);
  ok(/epoch_ms\(bt\) \/ 1000/.test(block), 'kernel wifi_driver last_fault_ts is epoch seconds (or null before the clock syncs)');
  const wd = readFileSync(join(ROOT, 'os/mission-control/src/store/wifiDriver.ts'), 'utf8');
  const read = ['state', 'restarts', 'faults', 'last_fault_ts', 'full_wipes', 'pmksa_entries'].filter((k) => !new RegExp(`\\.${k}\\b`).test(wd));
  ok(read.length === 0 && /o\.bus/.test(wd) && /o\.security/.test(wd), `the UI parses every wifi_driver key${read.length ? ` (missing: ${read.join(', ')})` : ''}`);
  const mock = readFileSync(join(HERE, 'wifi-driver-health.mjs'), 'utf8');
  const mkeys = [...new Set([...mock.matchAll(/\b([a-z_]+):/g)].map((m) => m[1]))].filter((k) => /restarts|faults|last_fault_ts|full_wipes|pmksa_entries|state|bus|security/.test(k));
  ok(mkeys.every((k) => WANT.includes(k)), `wifi_driver mocks use only kernel keys (${mkeys.join(', ')})`);

  // /api/health wifi_heal / wifi_boot (kernel wifiheal.rs): the keys and the boot-fault names the UI maps to text
  const hl = http.split('\n').find((l) => l.includes('\\"wifi_heal\\":{{')) ?? '';
  const hkeys = [...hl.matchAll(/\\"([a-z_]+)\\":/g)].map((m) => m[1]);
  const HWANT = ['wifi_heal', 'state', 'last_class', 'kicks', 'bounces', 'reloads', 'after_wifi_reboot'];
  ok(HWANT.every((k) => hkeys.includes(k)) && /\\"wifi_boot\\":/.test(http), `kernel /api/health writes wifi_heal (${hkeys.join(', ')}) and wifi_boot`);
  const heal = readFileSync(join(ROOT, 'os/kernel/kernel/src/wifiheal.rs'), 'utf8');
  const names = [...heal.matchAll(/BootFault::\w+ => "([a-z-]+)",/g)].map((m) => m[1]);
  const unmapped = names.filter((x) => !wd.includes(`'${x}':`));
  ok(names.length >= 5 && unmapped.length === 0, `the UI has text for every kernel Wi-Fi boot fault (${names.join(', ')})${unmapped.length ? `; missing: ${unmapped.join(', ')}` : ''}`);
}
