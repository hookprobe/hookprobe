/**
 * The configuration bundle (HQCFG1, ADR 0059) as the device reports it, shared by the Advanced editor and the
 * Layer 0 Wi-Fi sheet. A bundle is the WHOLE configuration: over a bundle in force, a section left out is removed,
 * so a change re-sends every section in force (kernel #1055 serves them; secrets only as `<key>_set`).
 */
import { configView } from './configState';
import { anchorView } from './anchor';
import { uploadView, uploadPack, type UploadResult, type UploadStep } from './packUpload';
import { ownerKey, signBundle, ownerKeyId } from './signing';
import { buildBundle, fromLegacy } from './hqcfg';
import { buildWan, buildWifi, wanFormFrom, wifiFormFrom, unknownKeys, WAN_KEYS, WIFI_KEYS, type WifiForm } from './configBuild';
import { networkView } from './networkLive';

export const bundleInForce = () => { const c = configView(); return !!c && (c.state === 'trial' || c.state === 'committed') && c.generation > 0; };
export const takesBundles = () => !!uploadView()?.types.some((t) => t.type === 'config');
export const bundleGen = () => Math.max(configView()?.generation ?? 0, configView()?.floor ?? 0, uploadView()?.types.find((t) => t.type === 'config')?.generation ?? 0) + 1;
export const deviceIdHex = () => { const h = anchorView()?.device_id; return h && /^[0-9a-f]{32}$/i.test(h) && /[1-9a-f]/i.test(h) ? h : ''; };
export const deviceIdBytes = () => (deviceIdHex() ? Uint8Array.from(deviceIdHex().match(/../g)!, (x) => parseInt(x, 16)) : new Uint8Array(16));

/** Why a home user cannot change the Wi-Fi from the simple sheet right now ('' = they can). */
export function wifiBlock(): string {
  const a = anchorView(), k = ownerKey();
  if (!takesBundles()) return 'This device does not take signed settings over the network yet.';
  if (bundleInForce() && !configView()?.sections) return 'This device does not report its settings in force, so the change has to be made in the advanced editor.';
  if (unknownKeys(configView()?.wan_keys, WAN_KEYS).length || unknownKeys(configView()?.wifi_keys, WIFI_KEYS).length)
    return 'This device has settings this screen cannot keep, so a change from here would remove them. Change the Wi-Fi with a signed file made offline instead.';
  if (!a?.owner_enrolled) return 'Wi-Fi changes are signed with your signing key, and this device does not trust one yet.';
  if (!k) return 'Wi-Fi changes are signed with your signing key, and it is not in this browser.';
  if (a.owner_key !== k.pubHex) return 'The signing key in this browser is not the one this device trusts.';
  return '';
}

/** The Wi-Fi in force, password blank (the device never serves it). */
export function wifiNow(): WifiForm {
  const c = configView();
  if (c?.sections?.wifi?.present && c.wifi_keys) return wifiFormFrom(c.wifi_keys);
  const w = networkView()?.wifi;
  return { ssid: w?.ssid ?? '', psk: '', security: w && /wpa3/i.test(w.security) ? 'wpa3-transition' : 'wpa2', channel: w?.channel ? String(w.channel) : 'auto', maxClients: '' };
}

/** The internet section in force carries a PPPoE password, which must be typed again to re-send it. */
export const needsPppoePass = () => { const c = configView(); return !!(c?.sections?.wan?.present && c.wan_keys?.mode === 'pppoe'); };

/** Every section in force, with the Wi-Fi replaced: internet re-sent with its retyped password, the firewall byte-for-byte. */
export function wifiSections(wifi: WifiForm, pppoePass: string): { wan?: string; wifi: string; policy?: string } {
  const c = configView(), s = c?.sections;
  return {
    ...(s?.wan?.present && c?.wan_keys ? { wan: fromLegacy('wan', buildWan({ ...wanFormFrom(c.wan_keys), pppoePass })) } : {}),
    wifi: fromLegacy('wifi', buildWifi(wifi)),
    ...(s?.policy?.present && c?.policy_text ? { policy: fromLegacy('policy', c.policy_text) } : {}),
  };
}

/** Sign the bundle with the signing key in this browser and send it; the device applies it live as a trial. */
export async function sendBundle(sections: { wan?: string; wifi?: string; policy?: string }, deviceKey: string, progress: (s: UploadStep, n: number) => void = () => undefined): Promise<UploadResult> {
  const b = buildBundle(sections, bundleGen(), await ownerKeyId(), deviceIdBytes());
  const sig = await signBundle(b);
  return uploadPack('config', new File([new Uint8Array(sig), new Uint8Array(b)], 'config.pack'), () => deviceKey, progress);
}
