// First-run setup (/setup) and Feedback & diagnostics (/admin/feedback): the conversation reaches a
// real signed WAN.TXT + WIFI.TXT (preview → boot-card files), and the diagnostics export carries
// product health only.
import { readFileSync } from 'node:fs';

export default async function (t) {
  const { page, ok, go, vis } = t;
  const dl = async (label) => {
    const [d] = await Promise.all([page.waitForEvent('download'), page.locator('button, a').filter({ hasText: new RegExp('^' + label.replace('.', '\\.') + '$') }).first().click()]);
    return readFileSync(await d.path());
  };

  await go('/setup');
  ok(await vis(page.locator('h1', { hasText: "Let's get you online" })), 'setup: greets with the three-question promise');
  ok(!(await vis(page.locator('nav[aria-label="Workspaces"], .app-rail'))), 'setup: no rail (a conversation, not the console)');
  await page.click('button:has-text("Start")'); await page.waitForTimeout(200);
  ok(await vis(page.locator('text=Step 1 of 3 · Internet')), 'setup: step 1 asks about the internet');

  // PPPoE branch validates like the device, then back to automatic.
  await page.click('text=I have a PPPoE login');
  ok(await page.locator('button:has-text("Continue")').isDisabled(), 'setup: PPPoE without a login cannot continue');
  await page.click('text=Use automatic instead');
  await page.click('button:has-text("Yes, use it")'); await page.waitForTimeout(200);

  ok(await vis(page.locator('text=Step 2 of 3 · Wi-Fi')), 'setup: step 2 asks for Wi-Fi');
  await page.fill('input[placeholder="HookProbe-Home"]', 'Popescu-Home');
  await page.fill('input[type=password]', 'short');
  ok(await page.locator('button:has-text("Continue")').isDisabled(), 'setup: short Wi-Fi password refused like the device');
  await page.fill('input[type=password]', 'Correct horse battery 9');
  ok(await page.locator('.setup-meter span.is-on').count() === 3, 'setup: strength meter fills for a strong password');
  await page.click('button:has-text("Continue")'); await page.waitForTimeout(200);

  ok(await vis(page.locator('text=Step 3 of 3 · Your key')), 'setup: step 3 creates the signing key');
  ok(await page.locator('button:has-text("Continue")').isDisabled(), 'setup: cannot continue without a key');
  await page.click('text=Create a key in this browser'); await page.waitForTimeout(800);
  await page.click('button:has-text("Continue")'); await page.waitForTimeout(200);

  ok(await vis(page.locator('.plan-diff-line--added', { hasText: 'wifi: "Popescu-Home"' })), 'setup: review shows the plan as a diff');
  await page.click('button:has-text("Launch")'); await page.waitForTimeout(1500);
  ok(await vis(page.locator('text=Your settings are signed.')), 'setup (preview): signed, honestly not applied');
  const wifi = await dl('WIFI.TXT');
  const sig = await dl('WIFI.SIG');
  ok(wifi.toString() === 'ssid=Popescu-Home\npsk=Correct horse battery 9\nsecurity=wpa3-transition\n', 'setup: WIFI.TXT is exactly the device grammar');
  ok(sig.length === 512 && sig.subarray(0, 8).toString('latin1') === 'HQWSIG1\0', 'setup: WIFI.SIG is a device-format signature');
  const wan = await dl('WAN.TXT');
  ok(wan.toString().startsWith('HQWAN1\nmode=dhcp'), 'setup: WAN.TXT asks for automatic internet');

  // Feedback & diagnostics.
  await go('/admin/feedback');
  ok(await page.locator('[aria-label="Product-health beacon"] input[type=checkbox]').isDisabled(), 'feedback: beacon off and greyed');
  ok(await vis(page.locator('#beacon-why')), 'feedback: greyed beacon says why');
  ok(/not reported by this device/.test(await page.locator('[aria-label="Beacon preview"] pre').textContent()), 'feedback: unmeasured fields say so, nothing invented');
  const diag = JSON.parse((await dl('Export diagnostics file')).toString());
  ok(diag.schema === 'hookprobe.diagnostics/1' && 'capabilities' in diag, 'feedback: diagnostics file exports');
  const flat = JSON.stringify(diag);
  ok(!/"ip"|gateway|"mac"|detections"|incident|owner_key/i.test(flat), 'feedback: diagnostics carry no addresses, detections or keys');
}
