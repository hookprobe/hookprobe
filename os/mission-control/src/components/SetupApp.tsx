/**
 * SetupApp — first-run setup (`/setup`; ADR 0010; wireframes "Phone · First-run setup" and "Setup step:
 * create your signing key"; requirements doc §Zero-touch setup portal). Mobile-first, centred, no rail:
 * a conversation, not a form.
 *
 *   Hi → 1 Internet (what the device sees on its WAN port) → 2 Wi-Fi (name + password) → 3 Your key
 *   (the owner's signing key, in this browser) → Review (the plan as a diff) → Launch
 *
 * Launch is real: WAN.TXT and WIFI.TXT are built exactly as the device parses them, signed in the browser
 * (ADR 0058) and uploaded. A device that cannot take them over the network yet says so, and the signed
 * files are handed over for the boot card — the setup never pretends to have applied anything.
 * No `/api/provision/launch` is used: heqk does not serve it (gap G48).
 */
import { type Component, For, Show, createMemo, createSignal, onMount } from 'solid-js';
import { substrate, deviceStats } from '../store/mock';
import { healthChecked, loadHealth } from '../store/health';
import { networkView, startNetworkLive } from '../store/networkLive';
import { uploadPack, refreshUploads } from '../store/packUpload';
import { ownerKey, loadOwnerKey, signPack, PACKS, download } from '../store/signing';
import { buildWan, buildWifi, checkWifi, checkWan, type WanForm } from '../store/configBuild';
import SampleDataNotice from './SampleDataNotice';
import SigningKeyPanel from './SigningKeyPanel';
import RestartButton from './RestartButton';

type Step = 'hi' | 'internet' | 'wifi' | 'key' | 'review' | 'launch' | 'done';
const ORDER: Step[] = ['hi', 'internet', 'wifi', 'key', 'review', 'launch', 'done'];
interface Out { name: string; txt: Uint8Array; sig: Uint8Array; sigName: string; result: string; staged: boolean }

function strength(pw: string): number {
  let s = 0;
  if (pw.length >= 12) s++;
  if (pw.length >= 16) s++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw) && /\d|[^A-Za-z0-9]/.test(pw)) s++;
  return s;
}

const field = { font: 'inherit', 'font-size': '16px', 'min-height': '48px', padding: '0 14px', background: 'var(--hp-surface)', color: 'var(--hp-text-primary)', border: '1px solid var(--hp-border)', 'border-radius': 'var(--hp-radius)', width: '100%', 'box-sizing': 'border-box' } as const;

const SetupApp: Component = () => {
  const [step, setStep] = createSignal<Step>('hi');
  const [mode, setMode] = createSignal<'dhcp' | 'pppoe'>('dhcp');
  const [user, setUser] = createSignal('');
  const [pass, setPass] = createSignal('');
  const [ssid, setSsid] = createSignal('');
  const [psk, setPsk] = createSignal('');
  const [outs, setOuts] = createSignal<Out[]>([]);
  const [busy, setBusy] = createSignal('');

  onMount(() => { void loadHealth(); startNetworkLive(); void loadOwnerKey(); void refreshUploads(); });

  const sample = () => healthChecked() && !substrate();
  const wanUp = () => networkView()?.wan?.up ?? deviceStats()?.wan?.up ?? false;
  const wanMode = () => networkView()?.wan?.mode ?? deviceStats()?.wan?.mode ?? '';
  const sees = () => (sample() ? 'I see a cable on the internet port already getting an address.'
    : wanUp() ? `I see the internet port already ${wanMode() === 'dhcp' ? 'getting an address automatically' : `connected (${wanMode()})`}.`
    : 'I don’t see an internet connection on the internet port yet.');

  const wanForm = (): WanForm => ({ mode: mode(), ip: '', gw: '', dns: '', pppoeUser: user(), pppoePass: pass(), vlanOn: false, vlan: '', vlanOuter: '', pcp: '', mgmtOn: false, mgmtVlan: '', mgmtIp: '', mgmtGw: '' });
  const wifiForm = () => ({ ssid: ssid(), psk: psk(), security: 'wpa3-transition' as const, channel: 'auto', maxClients: '' });
  const wanErrors = createMemo(() => (mode() === 'pppoe' ? checkWan(wanForm()) : []));
  const wifiErrors = createMemo(() => checkWifi(wifiForm()));
  const go = (s: Step) => setStep(s);
  const idx = () => ORDER.indexOf(step());

  const launch = async () => {
    go('launch');
    const res: Out[] = [];
    let files: [string, string, string, typeof PACKS.wan, string][];
    try {
      files = [
        ['WAN.TXT', 'WAN.SIG', 'wan', PACKS.wan, buildWan(wanForm())],
        ['WIFI.TXT', 'WIFI.SIG', 'wifi', PACKS.wifi, buildWifi(wifiForm())],
      ];
    } catch (e) { setBusy(e instanceof Error ? e.message : String(e)); go('review'); return; }
    for (const [name, sigName, type, kind, text] of files) {
      setBusy(`Signing ${name}…`);
      const txt = new TextEncoder().encode(text);
      try {
        const sig = await signPack(kind, 1, txt);
        if (sample()) { res.push({ name, txt, sig, sigName, result: 'signed (preview: no device)', staged: false }); continue; }
        setBusy(`Sending ${name} to the device…`);
        try {
          const r = await uploadPack(type, new File([new Uint8Array(sig), new Uint8Array(txt)], `${type}.pack`), () => window.prompt('Enter the owner key from your card:', ''), () => undefined);
          res.push({ name, txt, sig, sigName, result: r.staged ? 'staged for the next restart' : 'applied', staged: true });
        } catch (e) {
          const m = e instanceof Error ? e.message : String(e);
          res.push({ name, txt, sig, sigName, result: /: type$/.test(m) ? 'the device can’t take it over the network yet' : m, staged: false });
        }
      } catch (e) {
        res.push({ name, txt, sig: new Uint8Array(), sigName, result: e instanceof Error ? e.message : String(e), staged: false });
      }
    }
    setOuts(res); setBusy(''); go('done');
  };

  const allStaged = () => outs().length > 0 && outs().every((o) => o.staged);

  return (
    <div class="setup-wrap">
      <header class="setup-head">
        <Show when={idx() > 0 && idx() < 5} fallback={<span style={{ 'font-weight': 700 }}>HookProbe</span>}>
          <button class="hp-btn" style={{ 'min-height': '44px', border: 0, background: 'none' }} onClick={() => go(ORDER[idx() - 1])} aria-label="Back">← Back</button>
        </Show>
        <ol class="setup-dots" aria-label={`Step ${Math.min(Math.max(idx(), 1), 4)} of 4`}>
          <For each={[1, 2, 3, 4]}>{(i) => <li class={i <= Math.min(idx(), 4) ? 'is-on' : ''} />}</For>
        </ol>
      </header>
      <SampleDataNotice />

      <main class="setup-main">
        <Show when={step() === 'hi'}>
          <div class="setup-grow" />
          <div class="setup-orb" role="img" aria-label="HookProbe" />
          <h1 class="setup-h1">Hi. Let's get you online.</h1>
          <p class="setup-p">Three quick questions. Nothing to type unless you want to.</p>
          <div class="setup-grow" />
          <button class="hp-btn hp-btn--primary setup-cta" onClick={() => go('internet')}>Start</button>
        </Show>

        <Show when={step() === 'internet'}>
          <p class="l0-label">Step 1 of 3 · Internet</p>
          <div class="setup-bubble">{sees()} {wanUp() || sample() ? 'Use it as your internet?' : 'Plug the cable from your modem into the internet port, or use your ISP login.'}</div>
          <Show when={mode() === 'pppoe'}>
            <label class="l0-card-sub">PPPoE username<input style={field} value={user()} onInput={(e) => setUser(e.currentTarget.value)} autocomplete="off" placeholder="from your ISP letter" /></label>
            <label class="l0-card-sub">PPPoE password<input style={field} type="password" value={pass()} onInput={(e) => setPass(e.currentTarget.value)} autocomplete="new-password" /></label>
            <For each={wanErrors()}>{(e) => <p class="plan-diff-warn" style={{ margin: 0 }}>{e}</p>}</For>
          </Show>
          <div class="setup-grow" />
          <Show when={mode() === 'dhcp'} fallback={
            <button class="hp-btn hp-btn--primary setup-cta" disabled={wanErrors().length > 0} onClick={() => go('wifi')}>Continue</button>
          }>
            <button class="hp-btn hp-btn--primary setup-cta" onClick={() => go('wifi')}>{wanUp() || sample() ? 'Yes, use it' : 'Continue with automatic'}</button>
          </Show>
          <button class="hp-btn setup-cta" onClick={() => setMode(mode() === 'pppoe' ? 'dhcp' : 'pppoe')}>{mode() === 'pppoe' ? 'Use automatic instead' : 'I have a PPPoE login'}</button>
          <a class="setup-link" href="/network/wan/advanced">Advanced (static address, VLANs)</a>
        </Show>

        <Show when={step() === 'wifi'}>
          <p class="l0-label">Step 2 of 3 · Wi-Fi</p>
          <div class="setup-bubble">Name your Wi-Fi and pick a password.</div>
          <label class="l0-card-sub">Wi-Fi name<input style={field} value={ssid()} onInput={(e) => setSsid(e.currentTarget.value)} placeholder={networkView()?.wifi?.ssid ?? 'HookProbe-Home'} /></label>
          <label class="l0-card-sub">Password<input style={field} type="password" value={psk()} onInput={(e) => setPsk(e.currentTarget.value)} placeholder="At least 12 characters" autocomplete="new-password" /></label>
          <div class="setup-meter" role="img" aria-label={`Password strength ${strength(psk())} of 3`}>
            <For each={[1, 2, 3]}>{(i) => <span class={i <= strength(psk()) ? 'is-on' : ''} />}</For>
          </div>
          <Show when={ssid() || psk()}><For each={wifiErrors()}>{(e) => <p class="plan-diff-warn" style={{ margin: 0 }}>{e}</p>}</For></Show>
          <p class="pcard-note">WPA3 for devices that support it, WPA2 for the rest.</p>
          <div class="setup-grow" />
          <button class="hp-btn hp-btn--primary setup-cta" disabled={wifiErrors().length > 0} onClick={() => go('key')}>Continue</button>
        </Show>

        <Show when={step() === 'key'}>
          <p class="l0-label">Step 3 of 3 · Your key</p>
          <div class="setup-bubble">Create your signing key. Big changes — like your internet login or Wi-Fi — only apply when you sign them with this key.</div>
          <SigningKeyPanel compact />
          <div class="setup-grow" />
          <button class="hp-btn hp-btn--primary setup-cta" disabled={!ownerKey()} onClick={() => go('review')}>Continue</button>
        </Show>

        <Show when={step() === 'review'}>
          <p class="l0-label">Review</p>
          <div class="setup-bubble">Here's what I'll set up. Nothing changes until you tap Launch.</div>
          <Show when={busy()}><p class="plan-diff-warn" role="alert" style={{ margin: 0 }}>{busy()}</p></Show>
          <div class="plan-diff-lines">
            <div class="plan-diff-line plan-diff-line--added"><span class="plan-diff-mark">+</span>internet: {mode() === 'pppoe' ? `PPPoE as ${user()}` : 'automatic (DHCP)'}</div>
            <div class="plan-diff-line plan-diff-line--added"><span class="plan-diff-mark">+</span>wifi: "{ssid()}" · WPA3 + WPA2</div>
            <div class="plan-diff-line plan-diff-line--added"><span class="plan-diff-mark">+</span>signed with your key {ownerKey()?.pubHex.slice(0, 8)}…</div>
          </div>
          <p class="pcard-note" style={{ margin: 0 }}>Your Wi-Fi password{mode() === 'pppoe' ? ' and PPPoE password are' : ' is'} stored in the signed file in clear: anyone holding the device's boot card can read {mode() === 'pppoe' ? 'them' : 'it'}. Not protected at rest yet.</p>
          <p class="setup-p" style={{ 'font-size': '14px' }}>The new settings apply when the device restarts. Afterwards, join "{ssid()}" with your new password.</p>
          <div class="setup-grow" />
          <button class="hp-btn hp-btn--primary setup-cta" onClick={() => void launch()}>Launch</button>
        </Show>

        <Show when={step() === 'launch'}>
          <div class="setup-grow" />
          <div class="setup-orb setup-orb--busy" role="img" aria-label="Working" />
          <h1 class="setup-h1">Setting things up…</h1>
          <p class="setup-p" role="status">{busy()}</p>
          <div class="setup-grow" />
        </Show>

        <Show when={step() === 'done'}>
          <Show when={allStaged()} fallback={
            <>
              <h1 class="setup-h1" style={{ 'font-size': '24px' }}>Your settings are signed.</h1>
              <For each={outs()}>{(o) => <p class="l0-card-sub" style={{ margin: 0 }}>{o.name}: {o.result}</p>}</For>
              <p class="setup-p" style={{ 'font-size': '14px' }}>{sample() ? 'Preview: no device is connected.' : 'This device can’t take them over the network yet.'} Copy these files to the device's boot card, replacing the old ones, then restart it.</p>
              <div style={{ display: 'grid', gap: '8px' }}>
                <For each={outs().filter((o) => o.sig.length)}>{(o) => (
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button class="hp-btn" style={{ flex: 1 }} onClick={() => download(o.name, o.txt, 'text/plain')}>{o.name}</button>
                    <button class="hp-btn" style={{ flex: 1 }} onClick={() => download(o.sigName, o.sig)}>{o.sigName}</button>
                  </div>
                )}</For>
              </div>
            </>
          }>
            <div class="setup-grow" />
            <div class="setup-orb setup-orb--done" role="img" aria-label="Done">✓</div>
            <h1 class="setup-h1">Ready. Restart to go online.</h1>
            <p class="setup-p">Your internet and Wi-Fi settings are staged. After the restart, join "{ssid()}". You can change any of this later in Get Online.</p>
            <RestartButton primary label="Restart and go online" />
          </Show>
          <div class="setup-grow" />
          <a class="hp-btn hp-btn--primary setup-cta" href="/">Open HookProbe</a>
        </Show>
      </main>
    </div>
  );
};

export default SetupApp;
