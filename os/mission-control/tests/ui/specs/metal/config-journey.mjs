// METAL, OPT-IN — this spec CHANGES the device's configuration (then puts it back). It is never part of g3 / mc-e2e;
// the heqk session runs it in a metal batch, over the management VLAN (the Wi-Fi step drops AP clients):
//
//   UI_SPEC_DIR=specs/metal UI_LIVE_TOKEN=<device password> UI_INSECURE_TLS=1 \
//   MC_SIGNING_KEY_PEM="$(cat owner-signing-key.pem)" MC_WIFI_PSK='<current Wi-Fi password>' \
//   [MC_PPPOE_PASS='<ISP password, if the internet is PPPoE>'] [MC_METAL_WIFI=1 MC_WIFI_PSK_NEW='<temporary password>'] \
//   node os/mission-control/tests/ui/run.mjs os/kernel/tools/mc-e2e/node_modules https://<mgmt ip>
// (run.mjs directly: run.sh serves a local build; here the UI comes from the device itself.)
//
// A bundle re-sends every section it carries and the device never shows secrets back: when it carries Wi-Fi (a Wi-Fi
// section in force, or the Wi-Fi journey) MC_WIFI_PSK is needed, and MC_PPPOE_PASS when the internet uses PPPoE.
//   1) firewall: add one harmless rule → Review and apply live → trial banner → Roll back → the policy in force is
//      byte-for-byte the one before.
//   2) Wi-Fi (MC_METAL_WIFI=1): Get Online → Change password → signed bundle → "Keep the new Wi-Fi" → committed;
//      then the original password the same way.
const env = (k) => process.env[k] ?? '';

export default async function (t) {
  const { page, ok, go, vis, base } = t;
  page.setDefaultTimeout(20000);
  const cfg = async () => (await page.request.get(`${base}/api/config`)).json();
  const until = async (pred, ms = 150000) => { const end = Date.now() + ms; let c; do { c = await cfg(); if (pred(c)) return c; await page.waitForTimeout(3000); } while (Date.now() < end); return c; };
  const token = env('UI_LIVE_TOKEN'), psk = env('MC_WIFI_PSK');
  if (!env('MC_SIGNING_KEY_PEM')) { ok(false, 'MC_SIGNING_KEY_PEM is required (see the header)'); return; }
  if (env('MC_METAL_WIFI') === '1' && (!psk || !env('MC_WIFI_PSK_NEW'))) { ok(false, 'the Wi-Fi journey needs MC_WIFI_PSK and MC_WIFI_PSK_NEW'); return; }

  t.at = 'import the owner signing key';
  await go('/admin/identity', 2500);
  await page.click('[aria-label="Settings"] >> text=Signing key'); await page.waitForTimeout(500);
  if (await vis(page.locator('text=Import a backup'))) {
    await page.click('text=Import a backup'); await page.fill('textarea', env('MC_SIGNING_KEY_PEM'));
    await page.click('.pcard[aria-label="Signing key"] button:text-is("Import")'); await page.waitForTimeout(1500);
  }
  const before = await cfg();
  ok(before.sections && before.envelope?.owner_enrolled, `device reports the sections in force and trusts a signing key (generation ${before.generation}, state ${before.state})`);

  // ── 1) firewall: apply live, then roll back ──
  t.at = 'firewall: add a rule and review';
  await go('/protect/policies', 3000);
  if (!(await vis(page.locator('button:has-text("+ Rule")')))) {
    ok(false, 'firewall editor not editable on this device (policy has statements the editor does not parse) — journey 1 skipped');
  } else {
    await page.click('button:has-text("+ Rule")'); await page.waitForTimeout(300);
    await page.click('button:has-text("Review and apply live")'); await page.waitForTimeout(800);
    const d = page.locator('.drawer', { hasText: 'Apply all three together' });
    ok(await vis(d.locator('[aria-label="policy changes"] .plan-diff-line--added')), 'review: the new rule shows as a + line, the rest of the firewall unchanged');
    if (env('MC_PPPOE_PASS')) await d.locator('label:has-text("PPPoE password (again)") input').fill(env('MC_PPPOE_PASS'));
    // only when the bundle carries Wi-Fi (the bench's bundle in force has no Wi-Fi section: it is left out, #1141)
    if (await vis(d.locator('label:has-text("Wi-Fi password (again)")'))) {
      if (!psk) { ok(false, 'this bundle carries Wi-Fi: set MC_WIFI_PSK (the current Wi-Fi password)'); return; }
      await d.locator('label:has-text("Wi-Fi password (again)") input').fill(psk);
    }
    t.at = 'firewall: sign and send';
    await t.shot('before-send', true);
    // say WHY the button is not there / not enabled instead of timing out on the click
    const send = d.locator('button:has-text("Sign and upload the bundle"), button:has-text("Sign the bundle")');
    const why = {
      button: await send.count() ? (await send.first().isDisabled() ? 'disabled' : 'enabled') + ` "${(await send.first().textContent())?.trim()}"` : 'absent',
      problems: await d.locator('[aria-label="Bundle problems"] li').allInnerTexts(),
      keyPanel: await d.locator('.pcard[aria-label="Signing key"]').count() > 0,
      mismatch: await d.locator('text=the key in this browser is a different one').count() > 0,
    };
    if (why.button !== `enabled "Sign and upload the bundle"`) { ok(false, `send not possible: ${JSON.stringify(why)}`); return; }
    await send.first().click();
    await t.approve({ key: token });
    const trial = await until((c) => c.state === 'trial');
    ok(trial.state === 'trial' && trial.generation > before.generation, `applied live as a trial (generation ${before.generation} → ${trial.generation})`);
    await page.keyboard.press('Escape');
    t.at = 'firewall: roll back from the banner';
    await page.waitForSelector('.hp-banner--trial button:has-text("Roll back now")', { timeout: 30000 });
    await page.click('.hp-banner--trial button:has-text("Roll back now")');
    await t.approve({ reason: 'metal journey: roll back' });
    const after = await until((c) => c.state !== 'trial' && (c.live?.phase ?? 'idle') === 'idle');
    ok(after.policy_text === before.policy_text, `rolled back: the firewall in force is byte-for-byte the one before (state ${after.state})`);
  }

  // ── 2) Wi-Fi password: change and keep, then restore ──
  if (env('MC_METAL_WIFI') !== '1') { ok(true, 'Wi-Fi journey not requested (MC_METAL_WIFI=1 to run it)'); return; }
  for (const [from, to, label] of [[psk, env('MC_WIFI_PSK_NEW'), 'change'], [env('MC_WIFI_PSK_NEW'), psk, 'restore']]) {
    t.at = `wifi ${label}: send`;
    const g0 = (await cfg()).generation;
    await go('/network/wan', 3000);
    await page.click('section[aria-label="Wi-Fi"] button:has-text("Change password")'); await page.waitForTimeout(1500);
    const sheet = page.locator('[role=dialog][aria-labelledby="wifi-sheet-title"]');
    await sheet.locator('label:has-text("New Wi-Fi password") input').fill(to);
    if (env('MC_PPPOE_PASS') && await vis(sheet.locator('label:has-text("Internet (PPPoE) password")'))) await sheet.locator('label:has-text("Internet (PPPoE) password") input').fill(env('MC_PPPOE_PASS'));
    await sheet.locator('label:has-text("Device password") input').fill(token);
    await sheet.locator('button:has-text("Change password")').click();
    await sheet.locator('text=Wi-Fi changed').waitFor({ timeout: 60000 });
    t.at = `wifi ${label}: keep`;
    await t.shot(`wifi-${label}-sent`, true);
    if (await vis(sheet.locator('button:has-text("Keep the new Wi-Fi")'))) {
      await sheet.locator('button:has-text("Keep the new Wi-Fi")').click();
    } else {
      ok(false, `wifi ${label}: the result sheet offered no "Keep the new Wi-Fi" (text: ${(await sheet.innerText()).replace(/\s+/g, ' ').slice(0, 160)}) — keeping from the banner`);
      await page.keyboard.press('Escape'); await page.waitForTimeout(300);
      await page.click('.hp-banner--trial button:has-text("Keep it")');
    }
    await t.approve({ reason: `metal journey: ${label} Wi-Fi` });
    const c = await until((x) => x.state === 'committed' && x.generation > g0);
    ok(c.state === 'committed' && c.generation > g0, `Wi-Fi ${label}: kept from the result sheet, committed as generation ${c.generation} (from ${from ? 'the previous password' : '?'})`);
    await page.keyboard.press('Escape');
  }
}
