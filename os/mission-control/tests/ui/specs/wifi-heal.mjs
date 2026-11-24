// Wi-Fi self-heal (kernel wifiheal.rs, /api/health wifi_heal / wifi_boot / wifi_files): when recovery turns Wi-Fi off for
// the boot, or Wi-Fi never came up, the operator saw only "No Wi-Fi access point on this device or build". Now the
// "Wi-Fi health" card says what happened; a healthy device (QEMU: heal ok, boot ok, zero counts) shows nothing.
export default async function (t) {
  const { page, ok, go, vis } = t;
  const okHeal = { state: 'ok', last_class: 'healthy', kicks: 0, bounces: 0, reloads: 0, after_wifi_reboot: false };
  let health = { substrate: 'heqk', mode: 'standalone', wifi_boot: 'ok', wifi_heal: okHeal };
  const json = (b) => ({ status: 200, contentType: 'application/json', body: JSON.stringify(b) });
  await page.route('**/api/health', (r) => r.fulfill(json(health)));
  const card = page.locator('[aria-label="Wi-Fi health"]');
  const say = async (s) => (await card.count()) > 0 && (await card.innerText()).includes(s);

  await go('/mission', 1500);
  ok(await card.count() === 0, 'healthy self-heal (as QEMU reports): nothing shown');

  health = { ...health, wifi_heal: { ...okHeal, state: 'degraded: Wi-Fi off after a failed recovery (wired LAN, WAN and management keep running)', last_class: 'firmware-crash', reloads: 1, after_wifi_reboot: true } };
  await go('/mission', 1500);
  ok(await say('Wi-Fi is off after a failed recovery') && (await card.getAttribute('role')) === 'alert', 'degraded: Wi-Fi off for the boot is a clear warning (wired keeps running)');
  ok(await say('1 firmware reload') && await say('a firmware crash') && await say('follows a restart by Wi-Fi recovery'), 'degraded: what the self-heal tried, and that this boot follows its restart');

  health = { ...health, wifi_heal: { ...okHeal, state: 'recovering', last_class: 'tx-freeze', kicks: 2 } };
  await go('/mission', 1500);
  ok(await say('Wi-Fi is recovering from a transmit freeze') && await say('2 nudges'), 'recovering: the fault class and the nudges are stated');

  health = { ...health, wifi_heal: okHeal, wifi_boot: 'ap-start-failed' };
  await go('/network/wifi', 1500);
  ok(await say('Wi-Fi has been off since start-up: the access point could not be started'), 'boot fault: why Wi-Fi is off since power-on (the kernel text)');

  health = { ...health, wifi_boot: 'ok', wifi_files: 'missing:firmware' };
  await go('/mission', 1500);
  ok(await say('The Wi-Fi firmware file is missing'), 'vendor files: a missing firmware file is stated');

  health = { ...health, wifi_files: 'not-loaded' };
  await go('/mission', 1500);
  ok(await card.count() === 0, 'vendor files "not-loaded" is not a fault: nothing shown');
  await page.unroute('**/api/health');
}
