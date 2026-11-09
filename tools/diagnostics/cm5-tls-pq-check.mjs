// cm5-tls-pq-check — Mission Control HTTPS on metal negotiates the post-quantum hybrid key exchange.
// Real Chromium (the mc-e2e Playwright install) loads the device's Mission Control; Chrome's DevTools protocol
// reports the negotiated TLS 1.3 key-exchange group, which must be X25519MLKEM768 (heqk tlsprov, ML-KEM-768).
//   node tools/diagnostics/cm5-tls-pq-check.mjs [https://192.168.200.146]
import { createRequire } from 'node:module';
const require = createRequire(new URL('../../os/kernel/tools/mc-e2e/package.json', import.meta.url));
const { chromium } = require('playwright');
const url = process.argv[2] || 'https://192.168.200.146';
const browser = await chromium.launch();
const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
const page = await ctx.newPage();
const cdp = await ctx.newCDPSession(page);
await cdp.send('Network.enable');
let group = null, proto = null;
cdp.on('Network.responseReceived', (e) => {
  const s = e.response.securityDetails;
  if (s && !group) { group = s.keyExchangeGroup || s.keyExchange; proto = s.protocol; }
});
try { await page.goto(url + '/', { waitUntil: 'load', timeout: 20000 }); } catch (e) { console.log('load:', e.message); }
await browser.close();
console.log(`TLS: ${proto} key exchange ${group}`);
const ok = group === 'X25519MLKEM768';
console.log(`TLS-PQ: ${ok ? 'PASS' : 'FAIL'}`);
process.exit(ok ? 0 : 1);
