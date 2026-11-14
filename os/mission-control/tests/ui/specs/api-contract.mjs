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
}
