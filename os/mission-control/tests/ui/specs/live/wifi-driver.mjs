// Live leg, READ-ONLY: the device's /api/health wifi_driver (ADR 0065) has the agreed shape, and the Wi-Fi settings page
// shows it. Whatever state the device reports (QEMU has no radio; the CM5 runs el0-wifi), the UI must render it honestly.
const BUS = ['running', 'backoff', 'absent', 'handed_to_wifiheal'];
const SEC = ['running', 'backoff', 'absent'];

export default async function (t) {
  const { page, ok, go, vis } = t;
  await go('/network/wifi', 2500);
  const h = await page.evaluate(async () => { try { const r = await fetch('/api/health', { credentials: 'same-origin' }); return r.ok ? await r.json() : null; } catch { return null; } });
  const w = h?.wifi_driver;
  if (w === undefined) { ok(true, 'wifi_driver: not reported by this build (the UI shows nothing)'); return; }

  const n = (v) => Number.isInteger(v) && v >= 0;
  const tsOk = (v) => v === null || (Number.isInteger(v) && v > 1577836800);
  const b = w?.bus;
  ok(!!b && BUS.includes(b.state) && n(b.restarts) && n(b.faults) && tsOk(b.last_fault_ts),
    `wifi_driver.bus has the agreed shape (state ${b?.state}, restarts ${b?.restarts}, faults ${b?.faults}, last_fault_ts ${b?.last_fault_ts})`);
  const s = w?.security;
  ok(s === null || (SEC.includes(s.state) && n(s.restarts) && n(s.faults) && n(s.full_wipes) && tsOk(s.last_fault_ts) && (s.pmksa_entries === null || n(s.pmksa_entries))),
    `wifi_driver.security is null or has the agreed shape (${s === null ? 'null' : `state ${s.state}, full_wipes ${s.full_wipes}`})`);

  const card = page.locator('[aria-label="Wi-Fi driver"]');
  ok(await vis(card), 'Wi-Fi settings: the device-reported Wi-Fi driver health is shown');
  if (b?.state === 'absent') ok(/running inside the kernel/.test(await card.innerText()), 'Wi-Fi settings: "absent" (in-kernel fallback) is stated');
}
