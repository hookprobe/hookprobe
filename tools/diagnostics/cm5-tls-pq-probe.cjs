// cm5-tls-pq-probe — Mission Control's TLS 1.3 key exchange without a browser (pi4 assessment L-03). Offers exactly ONE
// group per connection: a TLS 1.3 server can only choose a group the client offered, so a completed handshake with
// only X25519MLKEM768 offered IS the post-quantum hybrid (node >= 22 with OpenSSL >= 3.5; this Node reports no key
// details for hybrid groups — the device's [MC-TLS hb] pq_hybrid= counter is the device-side confirmation).
//   node tools/diagnostics/cm5-tls-pq-probe.cjs [host]
const tls = require('tls');
function probe(group) {
  return new Promise((res) => {
    const s = tls.connect({ host: process.argv[2] || '192.168.200.146', port: 443, servername: 'heqk.local', rejectUnauthorized: false,
      ecdhCurve: group, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' }, () => {
      const k = s.getEphemeralKeyInfo ? s.getEphemeralKeyInfo() : {};
      res(`offered ${group}: OK ${s.getProtocol()} ${s.getCipher().name} key exchange ${JSON.stringify(k)}`); s.end();
    });
    s.on('error', (e) => res(`offered ${group}: FAILED (${e.code || e.message})`));
    s.setTimeout(10000, () => { res(`offered ${group}: TIMEOUT`); s.destroy(); });
  });
}
(async () => { for (const g of ['X25519MLKEM768', 'X25519']) console.log(await probe(g)); })();
