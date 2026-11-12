/**
 * ShellApp — Administration → Shell (`/admin/shell`; canvas board "AdminShell"; ADR 0059 D9, operator decision R6 = D).
 * A console for hsh, HookProbe's native management shell, over this signed-in session: POST /api/hsh?seq=<next_seq>
 * with the command line (and, for a privileged command, an HQMGMT1 envelope signed here as the second line).
 *
 * The session always runs at role view: hsh reads state through the same management ABI as Mission Control. The only
 * privileged commands (config confirm / rollback) are authorised by the owner-signed envelope, never by the session.
 * Builds without hsh (prod-mc) answer 405: the console says so and stays disabled.
 */
import { type Component, For, Show, createSignal } from 'solid-js';
import AppShell from './AppShell';
import { fetchJson } from '../store/api';
import { envelopeFor, MSG } from '../store/envelope';
import { approve } from '../store/approve';

const COMMANDS = ['help', 'version', 'info', 'uptime', 'interface show wan', 'qsecbit status', 'config status', 'owner status', 'security posture', 'owner challenge', 'config confirm', 'config rollback'];
const PRIVILEGED: Record<string, number> = { 'config confirm': MSG.CFG_CONFIRM, 'config rollback': MSG.CFG_ROLLBACK };

const ShellApp: Component = () => {
  const [lines, setLines] = createSignal<string[]>(['HEQK Management Environment · type help', '']);
  const [cmd, setCmd] = createSignal('');
  const [busy, setBusy] = createSignal(false);
  const [unavailable, setUnavailable] = createSignal('');
  let screen: HTMLPreElement | undefined;

  const print = (...l: string[]) => { setLines([...lines(), ...l]); queueMicrotask(() => screen && (screen.scrollTop = screen.scrollHeight)); };

  const send = async (raw: string) => {
    const line = raw.trim();
    if (!line || busy()) return;
    setCmd(''); setBusy(true);
    try {
      let env = '';
      const msg = PRIVILEGED[line];
      if (msg !== undefined) {
        if (!(await approve({ title: line === 'config confirm' ? 'Keep the configuration on trial?' : 'Roll back the configuration on trial?', body: 'Signed with your signing key: the shell session itself has no authority to change anything.', confirm: line === 'config confirm' ? 'Keep' : 'Roll back', destructive: line !== 'config confirm' }))) { print(`hsh> ${line}`, 'cancelled', ''); return; }
        env = await envelopeFor((e) => ({ msg, generation: e.generation, digest: e.digest }));
      }
      for (let attempt = 0; attempt < 2; attempt++) {
        const s = await fetchJson<{ csrf: string; next_seq: number }>('/api/session');
        const r = await fetch(`/api/hsh?seq=${s.next_seq}`, { method: 'POST', credentials: 'same-origin', headers: { 'X-HQ-CSRF': s.csrf, 'content-type': 'text/plain' }, body: env ? `${line}\n${env}` : line });
        if (r.status === 405 || r.status === 404) { setUnavailable('This build has no management shell (it ships in the access-point product). Everything it shows is also in Mission Control.'); print(`hsh> ${line}`, 'not available in this build', ''); return; }
        if (r.status === 409 && attempt === 0) continue; // stale session sequence: read it again once
        const text = await r.text();
        if (!r.ok) {
          let why = text;
          try { why = (JSON.parse(text) as { refused?: string }).refused ?? text; } catch { /* plain text */ }
          print(`hsh> ${line}`, `refused: ${why}`, ''); return;
        }
        print(`hsh> ${line}`, text.replace(/\s+$/, ''), ''); return;
      }
    } catch (e) {
      print(`hsh> ${line}`, `error: ${e instanceof Error ? e.message : String(e)}`, '');
    } finally { setBusy(false); }
  };

  return (
    <AppShell path="/admin/identity">
      <main class="pro-main" aria-label="Management shell">
        <div class="pro-head">
          <div>
            <p class="pro-crumb"><a href="/admin/identity">Administration</a> / Shell</p>
            <h1 class="pro-title">Management shell (hsh)</h1>
            <p class="pro-sub">HookProbe's own command line, inside the device. It reads the same state as Mission Control and changes nothing by itself.</p>
          </div>
        </div>
        <div class="shell-info" role="note"><span><b>Role:</b> view (read-only)</span><span><b>Transport:</b> this signed-in session</span><span><b>Audit:</b> every command is journaled (first two words)</span></div>
        <Show when={unavailable()}><p class="gate-reason">{unavailable()}</p></Show>
        <div class="shell-grid">
          <section class="shell-console" aria-label="Shell">
            <pre class="shell-screen" ref={screen} aria-live="polite">{lines().join('\n')}</pre>
            <form class="shell-input" onSubmit={(e) => { e.preventDefault(); void send(cmd()); }}>
              <label for="hsh-line" class="shell-prompt">hsh&gt;</label>
              <input id="hsh-line" value={cmd()} onInput={(e) => setCmd(e.currentTarget.value)} placeholder="type a command, or pick one" autocomplete="off" spellcheck={false} disabled={!!unavailable()} />
              <button type="button" class="hp-btn" onClick={() => setLines([''])}>Clear</button>
            </form>
          </section>
          <aside class="shell-cmds" aria-label="Commands in this build">
            <p class="l0-label">Commands</p>
            <For each={COMMANDS}>{(c) => <button class="shell-cmd" disabled={busy() || !!unavailable()} onClick={() => void send(c)}>{c}</button>}</For>
            <p class="pcard-note">Read-only by default. <code>config confirm</code> and <code>config rollback</code> are signed with your signing key here; the session alone cannot change anything.</p>
          </aside>
        </div>
      </main>
    </AppShell>
  );
};

export default ShellApp;
