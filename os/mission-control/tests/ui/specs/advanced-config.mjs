// Advanced signed configuration (ADR 0058): signing key in the browser, the three editors, the exact
// files, and signatures the device would accept — verified here exactly as os/kernel's wificfg.rs /
// policysig.rs check them, and byte-for-byte against os/kernel/tools/policy-sign.py when available.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', '..');

function edVerify(pubHex, msg, sig) {
  // raw 32-byte Ed25519 public key → SPKI DER
  const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(pubHex, 'hex')]);
  return verify(null, msg, createPublicKey({ key: der, format: 'der', type: 'spki' }), sig);
}
const u64 = (b, o) => Number(b.readBigUInt64LE(o));

export default async function (t) {
  const { page, ok, go, vis } = t;
  const dl = async (label) => {
    const [d] = await Promise.all([page.waitForEvent('download'), page.click(`text=${label}`)]);
    return readFileSync(await d.path());
  };

  // 1. Create a signing key in Administration.
  await go('/admin/identity');
  await page.click('[aria-label="Settings"] >> text=Signing key'); await page.waitForTimeout(300);
  await page.click('text=Create a key in this browser'); await page.waitForTimeout(800);
  const pubHex = (await page.locator('.prow', { hasText: 'Public key' }).locator('span').nth(1).textContent()).trim();
  ok(/^[0-9a-f]{64}$/.test(pubHex), 'signing key created in the browser (32-byte public key)');
  const pem = (await dl('Download backup (PEM)')).toString();
  ok(pem.includes('BEGIN PRIVATE KEY'), 'PEM backup downloads');

  // 2. Wi-Fi editor: validation mirrors the device.
  await go('/network/wifi');
  ok(await vis(page.locator('.tab[aria-current="page"]', { hasText: 'Wi-Fi' })), 'wifi editor: Wi-Fi tab active');
  await page.fill('input[placeholder="HookProbe-Home"]', 'Popescu-Home');
  await page.fill('input[type=password]', 'short');
  ok(await vis(page.locator('[aria-label="Problems"] >> text=Password: 8–63')), 'wifi: short password refused like the device');
  await page.fill('input[type=password]', 'correct horse battery');
  await page.click('[aria-label="Channel"] >> text=40');
  ok(await page.locator('button:has-text("Review and sign")').isEnabled(), 'wifi: valid form enables Review and sign');
  ok(/ssid=Popescu-Home/.test(await page.locator('aside pre').textContent()), 'wifi: draft shows the exact file (secret hidden)');
  ok(!/correct horse/.test(await page.locator('aside pre').textContent()), 'wifi: password hidden in the draft');
  await page.fill('aside input[inputmode=numeric]', '7');

  // 3. Review → sign → (preview) boot-card files.
  await page.click('button:has-text("Review and sign")'); await page.waitForTimeout(300);
  ok(await vis(page.locator('.drawer .plan-diff-line--added', { hasText: 'ssid=Popescu-Home' })), 'review: the change as a diff');
  await page.click('text=Looks right · sign it'); await page.waitForTimeout(200);
  await page.click('text=Sign in this browser'); await page.waitForTimeout(800);
  ok(await vis(page.locator('.drawer >> text=Copy both files to the device')), 'preview: signed files offered for the boot card');
  const txt = await dl('Download WIFI.TXT');
  const sig = await dl('Download WIFI.SIG');
  ok(txt.toString() === 'ssid=Popescu-Home\npsk=correct horse battery\nchannel=40\nsecurity=wpa3-transition\n', 'WIFI.TXT is exactly the device grammar');

  // 4. Verify like wificfg.rs::check_sig.
  const len = u64(sig, 16), gen = u64(sig, 8);
  const d = createHash('sha256').update(txt.subarray(0, len)).digest();
  const msg = Buffer.concat([Buffer.from('HQWIF1'), sig.subarray(8, 16), sig.subarray(16, 24), d]);
  ok(sig.length === 512 && sig.subarray(0, 8).toString('latin1') === 'HQWSIG1\0' && gen === 7 && len === txt.length && d.equals(sig.subarray(24, 56)) && edVerify(pubHex, msg, sig.subarray(56, 120)) && sig.subarray(120).every((b) => b === 0),
    'WIFI.SIG verifies exactly as the device checks it (magic, generation, length, sha256, Ed25519, zero pad)');

  // 5. Byte-identical with the reference signer (Ed25519 is deterministic).
  let py = false;
  try { execFileSync('python3', ['-I', '-c', 'import cryptography'], { stdio: 'ignore' }); py = true; } catch { /* not installed */ }
  if (py) {
    const dir = mkdtempSync(join(tmpdir(), 'hp-sig-'));
    writeFileSync(join(dir, 'k.pem'), pem); writeFileSync(join(dir, 'WIFI.TXT'), txt);
    execFileSync('python3', ['-I', join(ROOT, 'os/kernel/tools/policy-sign.py'), 'sign-wifi', join(dir, 'k.pem'), join(dir, 'WIFI.TXT'), '7', join(dir, 'WIFI.SIG')], { stdio: 'ignore' });
    ok(readFileSync(join(dir, 'WIFI.SIG')).equals(sig), 'browser signature is byte-identical to policy-sign.py sign-wifi');
  } else {
    console.log('  note  advanced-config: python cryptography not installed — byte-for-byte check vs policy-sign.py skipped');
  }

  // 6. Internet editor: PPPoE on VLAN 6 builds the exact WAN.TXT; device rules enforced.
  await go('/network/wan/advanced');
  await page.click('[aria-label="Connection type"] >> text=PPPoE');
  await page.fill('input[placeholder="from your ISP letter"]', 'user@isp');
  await page.locator('label:has-text("PPPoE password") input').fill('s3cret');
  await page.locator('label.prow:has-text("ISP VLAN") input[type=checkbox]').check();
  await page.fill('input[placeholder="6"]', '6');
  ok((await page.locator('aside pre').textContent()).startsWith('HQWAN1\nmode=pppoe\npppoe_user=user@isp\npppoe_pass=••••••••\nvlan=6'), 'wan: PPPoE on VLAN 6 builds the exact WAN.TXT');
  await page.locator('label.prow:has-text("Management VLAN") input[type=checkbox]').check();
  await page.fill('input[placeholder="99"]', '6');
  ok(await vis(page.locator('[aria-label="Problems"] >> text=must differ from the ISP VLAN')), 'wan: management VLAN equal to the ISP VLAN refused like the device');

  // 7. Firewall editor: POLICY.TXT is staged to exactly 4096 bytes and signs as HQPSIG1.
  await go('/protect/policies');
  await page.click('text=+ From template: block device-to-device traffic'); await page.waitForTimeout(200);
  ok(/interface lan acl in LAN_IN/.test(await page.locator('aside pre').textContent()), 'firewall: template adds the LAN rule and binding');
  await page.click('button:has-text("Review and sign")'); await page.waitForTimeout(300);
  await page.click('text=Looks right · sign it'); await page.click('text=Sign in this browser'); await page.waitForTimeout(800);
  const ptxt = await dl('Download POLICY.TXT');
  const psig = await dl('Download POLICY.SIG');
  const pd = createHash('sha256').update(ptxt).digest();
  const pmsg = Buffer.concat([Buffer.from('HQPOL1'), psig.subarray(8, 16), pd]);
  ok(ptxt.length === 4096 && ptxt.subarray(0, 6).toString() === 'HQPOL1' && ptxt[4095] === 0x0a, 'POLICY.TXT staged to exactly 4096 bytes, newline-padded');
  ok(psig.subarray(0, 8).toString('latin1') === 'HQPSIG1\0' && pd.equals(psig.subarray(16, 48)) && edVerify(pubHex, pmsg, psig.subarray(48, 112)), 'POLICY.SIG verifies exactly as policysig.rs checks it');

  // 8. Get Online links to the editors.
  await go('/network/wan');
  await page.click('button:has-text("Advanced")'); await page.waitForTimeout(150);
  ok(await page.locator('a[href="/network/wan/advanced"]').count() >= 1 && await page.locator('a[href="/network/wifi"]').count() >= 1 && await page.locator('a[href="/protect/policies"]').count() >= 1, 'get online: Advanced links to the three editors');
}
