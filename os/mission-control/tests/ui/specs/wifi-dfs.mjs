// Metal 2026-11-14 night (docs/design/metal-evidence/20261114-night.md §2): the CM5 AP serves on DFS channel 52 after the
// ~60 s radar check, via auto-channel on HEQK_AP_DFS builds. WIFI.TXT still refuses an explicit DFS channel (wificfg.rs:
// channel=52 → BadChannel), so the picker stays 36–48, and the note no longer blames the radio firmware.
export default async function (t) {
  const { page, ok, go } = t;
  await go('/network/wifi', 1500);
  const chips = await page.locator('button.l0-chip').allInnerTexts();
  ok(!chips.some((c) => c.trim() === '52') && chips.some((c) => c.trim() === '48'), 'Wi-Fi channels: 36–48 offered, DFS 52 not (the device refuses it in WIFI.TXT)');
  const note = await page.locator('main').innerText();
  ok(/radar/.test(note) && !/aren't supported by the radio firmware/.test(note), 'Wi-Fi: the DFS note says what really happens (Auto may use DFS on enabled builds, ~1 min radar check)');
}
