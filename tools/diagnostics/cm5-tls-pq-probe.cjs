// cm5-tls-pq-probe — Mission Control's TLS 1.3 key exchange without a browser (pi4 assessment L-03). Offers exactly ONE
// group per connection: a TLS 1.3 server can only choose a group the client offered, so a completed handshake with
// only X25519MLKEM768 offered IS the post-quantum hybrid (node >= 22 with OpenSSL >= 3.5; this Node reports no key
// details for hybrid groups — the device's [MC-TLS hb] pq_hybrid= counter is the device-side confirmation).
//
// The device certificate is VERIFIED against the unit's local CA (ADR 0051) and the name heqk.local, so a pass also
// proves the chain and the name, and a man in the middle cannot pass. `--insecure` skips verification, for a bench
// device whose CA is not at hand; it says so on stderr (CodeQL #1373: verification used to be off unconditionally).
//
//   node tools/diagnostics/cm5-tls-pq-probe.cjs [host] --ca <ca.pem>      (or HEQK_MC_CA=<ca.pem>)
//   node tools/diagnostics/cm5-tls-pq-probe.cjs [host] --insecure
//   (--port N for a forwarded port, e.g. QEMU's)
const fs = require('fs');
const tls = require('tls');

const args = process.argv.slice(2);
const flag = (name) => { const i = args.indexOf(name); return i >= 0 ? args.splice(i, 2)[1] : undefined; };
const insecure = args.includes('--insecure') && (args.splice(args.indexOf('--insecure'), 1), true);
const caPath = flag('--ca') || process.env.HEQK_MC_CA;
const port = Number(flag('--port') || 443);
const host = args[0] || '192.168.200.146';
if (!caPath && !insecure) {
  console.error('cm5-tls-pq-probe: pass --ca <the unit\'s local CA, PEM> (or HEQK_MC_CA), or --insecure to skip certificate checks');
  process.exit(2);
}
const ca = caPath ? fs.readFileSync(caPath) : undefined;
if (insecure) console.error('cm5-tls-pq-probe: WARNING --insecure: the device certificate is NOT verified');

function probe(group) {
  return new Promise((res) => {
    const opts = { host, port, servername: 'heqk.local', ecdhCurve: group, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' };
    if (ca) opts.ca = ca;
    // verification stays on unless the operator asked for --insecure on the command line
    opts.rejectUnauthorized = !insecure;
    const s = tls.connect(opts, () => {
      const k = s.getEphemeralKeyInfo ? s.getEphemeralKeyInfo() : {};
      const who = insecure ? 'certificate NOT verified' : `certificate verified for heqk.local (${s.getPeerCertificate().subject?.CN || '?'})`;
      res(`offered ${group}: OK ${s.getProtocol()} ${s.getCipher().name} key exchange ${JSON.stringify(k)}; ${who}`); s.end();
    });
    s.on('error', (e) => res(`offered ${group}: FAILED (${e.code || e.message})`));
    s.setTimeout(10000, () => { res(`offered ${group}: TIMEOUT`); s.destroy(); });
  });
}
(async () => { for (const g of ['X25519MLKEM768', 'X25519']) console.log(await probe(g)); })();
