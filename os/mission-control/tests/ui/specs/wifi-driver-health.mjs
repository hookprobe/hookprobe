// ADR 0065: the Wi-Fi driver runs out of the kernel and reports its health on /api/health `wifi_driver` (shape agreed with
// the heqk session 2026-11-15). Nothing shows until the device reports it; "absent" (the in-kernel fallback is serving,
// which once happened silently on metal) and full_wipes are always clear warnings; a healthy driver adds no noise to Mission.
export default async function (t) {
  const { page, ok, go, vis } = t;
  let health = { substrate: 'heqk', mode: 'standalone' };
  const json = (b) => ({ status: 200, contentType: 'application/json', body: JSON.stringify(b) });
  await page.route('**/api/health', (r) => r.fulfill(json(health)));
  const card = page.locator('[aria-label="Wi-Fi health"]');
  const bus = (state, restarts = 0, faults = 0) => ({ state, restarts, faults, last_fault_ts: faults ? Math.floor(Date.now() / 1000) - 120 : null });

  await go('/mission', 1500);
  ok(await card.count() === 0, 'no wifi_driver field: nothing is shown (never invented)');

  health = { ...health, wifi_driver: { bus: bus('running'), security: null } };
  await go('/mission', 1500);
  ok(await card.count() === 0, 'Mission: a healthy driver adds no noise');
  await go('/network/wifi', 1500);
  ok(await vis(card.locator('text=no faults since start-up')), 'Wi-Fi settings: a healthy driver is stated calmly');

  health = { ...health, wifi_driver: { bus: bus('absent'), security: null } };
  await go('/mission', 1500);
  ok(await vis(card.locator('text=Wi-Fi is running inside the kernel')) && (await card.getAttribute('role')) === 'alert', 'Mission: "absent" (in-kernel fallback) is a clear warning');

  health = { ...health, wifi_driver: { bus: bus('running', 2, 2), security: { ...bus('running', 1, 1), full_wipes: 1, pmksa_entries: 0 } } };
  await go('/mission', 1500);
  const txt = await card.innerText();
  ok(/restarted 2 times after a fault/.test(txt) && /reset once: every device had to reconnect/.test(txt), 'Mission: restarts noted; a security reset (every device reconnected) is a warning');

  health = { ...health, wifi_driver: { bus: bus('handed_to_wifiheal', 3, 3), security: null } };
  await go('/mission', 1500);
  ok(await vis(card.locator('text=Wi-Fi recovery took over')), 'Mission: hand-over to Wi-Fi recovery is stated');

  // no Wi-Fi on this device (QEMU: wifi_ap denied, bus/security "absent" with no history): nothing to say
  health = { substrate: 'heqk', mode: 'standalone', capabilities: ['ids', 'dns'], wifi_driver: { bus: bus('absent'), security: { ...bus('absent'), full_wipes: 0, pmksa_entries: null } } };
  await go('/mission', 1500);
  const noRadioMission = await card.count();
  await go('/network/wifi', 1500);
  ok(noRadioMission === 0 && await card.count() === 0, 'no Wi-Fi radio (wifi_ap not granted) + "absent": no Wi-Fi driver warning (QEMU showed "Wi-Fi works" on a radio-less device)');
  health = { ...health, wifi_driver: { bus: bus('handed_to_wifiheal', 3, 3), security: null } };
  await go('/mission', 1500);
  ok(await vis(card.locator('text=Wi-Fi recovery took over')), 'Wi-Fi down after a failed recovery (wifi_ap denied): the hand-over is still stated');
  health = { substrate: 'heqk', mode: 'standalone', capabilities: ['ids', 'dns', 'wifi_ap'], wifi_driver: { bus: bus('absent'), security: null } };
  await go('/mission', 1500);
  ok(await vis(card.locator('text=Wi-Fi is running inside the kernel')), 'Wi-Fi up (wifi_ap granted) + "absent": the in-kernel fallback warning shows');

  health = { ...health, wifi_driver: { bus: 'garbage' } };
  await go('/mission', 1500);
  ok(await card.count() === 0, 'a malformed field shows nothing rather than a guess');
  await page.unroute('**/api/health');
}
