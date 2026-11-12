// Post-build: move Astro's per-page inline scripts (the island runtime, ~4.9 KB, repeated in every page) into one
// shared, content-addressed file each, and reference it with <script src> at the same position.
//
// Why: Mission Control is embedded in the heqk kernel image, whose AP payload has a hard size limit (the HBoot load
// window, `ap-size-gate` in os/kernel/validate.sh). Twenty-odd copies of the same runtime cost ~50 KB gzipped.
// A classic (non-async, non-module) external script blocks and runs in document order exactly like the inline one,
// so behaviour is unchanged; only identical scripts that appear on at least two pages are moved.
import { readdirSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { createHash } from 'node:crypto';

const dist = new URL('../dist/', import.meta.url).pathname;
const pages = [];
const walk = (d) => { for (const f of readdirSync(d)) { const p = join(d, f); if (statSync(p).isDirectory()) walk(p); else if (f.endsWith('.html')) pages.push(p); } };
walk(dist);

// Attribute-less inline scripts only (Astro's own output), any case, whitespace allowed before the closing '>'.
const INLINE = /<script\s*>([\s\S]*?)<\/script\s*>/gi;
const count = new Map();
for (const p of pages) for (const m of readFileSync(p, 'utf8').matchAll(INLINE)) count.set(m[1], (count.get(m[1]) ?? 0) + 1);

const files = new Map();
for (const [body, n] of count) {
  if (n < 2 || body.length < 100) continue;
  const name = `_astro/inline-${createHash('sha256').update(body).digest('hex').slice(0, 12)}.js`;
  writeFileSync(join(dist, name), body);
  files.set(body, name);
}

let saved = 0;
for (const p of pages) {
  const html = readFileSync(p, 'utf8');
  const out = html.replace(INLINE, (all, body) => (files.has(body) ? `<script src="/${files.get(body)}"></script>` : all));
  if (out !== html) { saved += html.length - out.length; writeFileSync(p, out); }
}
console.log(`shared-inline-scripts: ${files.size} script(s) shared across ${pages.length} pages, ${saved} bytes removed from HTML (${relative(process.cwd(), dist)})`);
