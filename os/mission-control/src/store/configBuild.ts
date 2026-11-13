/**
 * configBuild — the three signed configuration files, built from forms (ADR 0058; requirements doc
 * §Configuration journey). Every validation mirrors the device's own parser so a file the browser signs
 * is a file the device accepts:
 *   WAN.TXT     os/kernel/hal/src/lib.rs  parse_wan_cfg + parse_wan_link
 *   WIFI.TXT    os/kernel/kernel/src/wificfg.rs
 *   POLICY.TXT  os/kernel/hal/src/policy.rs  parse_policy (4096 B, staged with '\n' padding)
 */

export interface WanForm {
  mode: 'dhcp' | 'static' | 'pppoe';
  ip: string; gw: string; dns: string;
  pppoeUser: string; pppoePass: string;
  vlanOn: boolean; vlan: string; vlanOuter: string; pcp: string;
  mgmtOn: boolean; mgmtVlan: string; mgmtIp: string; mgmtGw: string;
  /** mgmt_floor: the management-access floor (admins' network that can always reach the device), e.g. 10.0.99.0/24. */
  mgmtFloor: string;
}
export interface WifiForm { ssid: string; psk: string; security: 'wpa2' | 'wpa3' | 'wpa3-transition'; channel: string; maxClients: string }

export interface AclRow { name: string; seq: string; action: 'allow' | 'block' | 'drop'; proto: string; src: string; dst: string; port: string }
export interface PrefixRow { name: string; seq: string; action: 'permit' | 'deny'; prefix: string; ge: string; le: string }
export interface BindRow { iface: 'lan' | 'eth1' | 'wan' | 'mgmt'; kind: 'acl' | 'prefix-list'; dir: 'in' | 'out'; name: string }
export interface RouteRow { dst: string; from: string; via: 'lan' | 'eth1' | 'wan' | 'mgmt'; gw: string; metric: string }
export interface PolicyForm { prefixes: PrefixRow[]; acls: AclRow[]; defaults: { name: string; action: 'allow' | 'block' | 'drop' }[]; binds: BindRow[]; routes: RouteRow[] }

const quad = (s: string): number | null => {
  const m = s.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const p = m.slice(1).map(Number);
  if (p.some((x) => x > 255)) return null;
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
};
const vid = (s: string) => /^\d{1,4}$/.test(s.trim()) && +s >= 1 && +s <= 4094;
const credOk = (s: string) => s.length <= 64 && /^[\x21-\x7e]*$/.test(s);

/** Problems in plain words, empty when the device would accept it. */
export function checkWan(f: WanForm): string[] {
  const e: string[] = [];
  if (f.mode === 'static') {
    const m = f.ip.trim().match(/^(.+)\/(\d{1,2})$/);
    const a = m ? quad(m[1]) : null, prefix = m ? +m[2] : 0, g = quad(f.gw);
    if (a === null || !m) e.push('Address must look like 192.0.2.10/24.');
    else if (prefix < 8 || prefix > 30) e.push('Prefix must be between /8 and /30.');
    else {
      const mask = (0xffffffff << (32 - prefix)) >>> 0;
      if ((a & ~mask) === 0 || ((a & ~mask) >>> 0) === ((~mask) >>> 0)) e.push('The address is the network or broadcast address.');
      if (g === null) e.push('Gateway must be an IPv4 address.');
      else if (((a & mask) >>> 0) !== ((g & mask) >>> 0) || g === a) e.push('The gateway must be another address in the same network.');
    }
    if (f.dns.trim() && quad(f.dns) === null) e.push('DNS must be an IPv4 address (or leave it empty for the gateway).');
  }
  if (f.mode === 'pppoe') {
    if (!f.pppoeUser) e.push('PPPoE needs a username.');
    if (!credOk(f.pppoeUser) || !credOk(f.pppoePass)) e.push('PPPoE username and password: up to 64 characters, no spaces.');
  }
  if (f.vlanOn) {
    if (!vid(f.vlan)) e.push('VLAN ID must be 1–4094.');
    if (f.vlanOuter.trim() && !vid(f.vlanOuter)) e.push('Outer VLAN must be 1–4094.');
    if (f.pcp.trim() && !/^[0-7]$/.test(f.pcp.trim())) e.push('Priority must be 0–7.');
  }
  if (f.mgmtOn) {
    if (!vid(f.mgmtVlan)) e.push('Management VLAN must be 1–4094.');
    if (f.vlanOn && f.mgmtVlan.trim() === f.vlan.trim()) e.push('The management VLAN must differ from the ISP VLAN.');
    if (f.mgmtIp.trim() && !/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(f.mgmtIp.trim())) e.push('Management address must look like 10.0.99.2/24.');
    if (f.mgmtGw.trim() && quad(f.mgmtGw) === null) e.push('Management gateway must be an IPv4 address.');
  }
  if (f.mgmtFloor.trim()) {
    const m = f.mgmtFloor.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
    if (!m || quad(m[1]) === null || +m[2] < 8 || +m[2] > 32) e.push('Management access floor must be a network /8 to /32, like 10.0.99.0/24.');
  }
  return e;
}

/** Last line of defence before anything is signed: LF-only lines, no control characters, each key once
 *  (the device refuses a repeated key). Throws instead of producing a file the device would refuse. */
export function assertCanonical(text: string): string {
  const seen = new Set<string>();
  for (const line of text.split('\n').slice(0, -1)) {
    if (/[\x00-\x1f\x7f]/.test(line)) throw new Error('A value contains a control character (for example a line break).');
    const k = line.includes('=') ? line.slice(0, line.indexOf('=')) : line;
    if (seen.has(k)) throw new Error(`"${k}" would appear twice.`);
    seen.add(k);
  }
  return text;
}

export function buildWan(f: WanForm): string {
  const l = ['HQWAN1', `mode=${f.mode}`];
  if (f.mode === 'static') { l.push(`ip=${f.ip.trim()}`, `gw=${f.gw.trim()}`); if (f.dns.trim()) l.push(`dns=${f.dns.trim()}`); }
  if (f.mode === 'pppoe') l.push(`pppoe_user=${f.pppoeUser}`, `pppoe_pass=${f.pppoePass}`);
  if (f.vlanOn) { l.push(`vlan=${f.vlan.trim()}`); if (f.vlanOuter.trim()) l.push(`vlan_outer=${f.vlanOuter.trim()}`); if (f.pcp.trim()) l.push(`pcp=${f.pcp.trim()}`); }
  if (f.mgmtOn) {
    l.push(`mgmt_vlan=${f.mgmtVlan.trim()}`);
    if (f.mgmtIp.trim()) { l.push('mgmt=static', `mgmt_ip=${f.mgmtIp.trim()}`); if (f.mgmtGw.trim()) l.push(`mgmt_gw=${f.mgmtGw.trim()}`); } else l.push('mgmt=dhcp');
  }
  if (f.mgmtFloor.trim()) l.push(`mgmt_floor=${f.mgmtFloor.trim()}`);
  return assertCanonical(l.join('\n') + '\n');
}

type Keys = Record<string, string | boolean> | null | undefined;
const kv = (o: Keys, k: string) => (typeof o?.[k] === 'string' ? (o[k] as string) : '');
/** The internet form from the keys the device reports for the bundle in force (kernel #1055). Secrets are never served:
 *  `pppoePass` starts empty and must be typed again. */
export function wanFormFrom(w: Keys): WanForm {
  return { mode: (kv(w, 'mode') || 'dhcp') as WanForm['mode'], ip: kv(w, 'ip'), gw: kv(w, 'gw'), dns: kv(w, 'dns'), pppoeUser: kv(w, 'pppoe_user'), pppoePass: '',
    vlanOn: !!kv(w, 'vlan'), vlan: kv(w, 'vlan'), vlanOuter: kv(w, 'vlan_outer'), pcp: kv(w, 'pcp'), mgmtOn: !!kv(w, 'mgmt_vlan'), mgmtVlan: kv(w, 'mgmt_vlan'), mgmtIp: kv(w, 'mgmt_ip'), mgmtGw: kv(w, 'mgmt_gw'), mgmtFloor: kv(w, 'mgmt_floor') };
}
/** The Wi-Fi form from the keys in force; `psk` starts empty (never served). */
export function wifiFormFrom(f: Keys): WifiForm {
  return { ssid: kv(f, 'ssid'), psk: '', security: (kv(f, 'security') || 'wpa2') as WifiForm['security'], channel: kv(f, 'channel') || 'auto', maxClients: kv(f, 'max_clients') };
}

/** Keys the editors carry. A key the device reports outside these would be dropped by a bundle (it is the whole
 *  configuration), so bundles are refused until the editor learns it (mgmt_floor was dropped this way, 13 Nov). */
export const WAN_KEYS = new Set(['mode', 'ip', 'gw', 'dns', 'pppoe_user', 'pppoe_pass_set', 'vlan', 'vlan_outer', 'pcp', 'mgmt_vlan', 'mgmt', 'mgmt_ip', 'mgmt_gw', 'mgmt_floor']);
export const WIFI_KEYS = new Set(['ssid', 'security', 'channel', 'max_clients', 'psk_set']);
export function unknownKeys(keys: Keys, known: Set<string>): string[] { return Object.keys(keys ?? {}).filter((k) => !known.has(k)); }

export function checkWifi(f: WifiForm): string[] {
  const e: string[] = [];
  const ssid = new TextEncoder().encode(f.ssid);
  if (ssid.length < 1 || ssid.length > 32) e.push('Wi-Fi name: 1–32 bytes.');
  if (/[\x00-\x1f\x7f]/.test(f.ssid)) e.push('Wi-Fi name cannot contain control characters.');
  const hex64 = /^[0-9a-fA-F]{64}$/.test(f.psk);
  if (!hex64 && !(f.psk.length >= 8 && f.psk.length <= 63 && /^[\x20-\x7e]+$/.test(f.psk))) e.push('Password: 8–63 printable characters (or a 64-digit hex key).');
  if (hex64 && f.security !== 'wpa2') e.push('A 64-digit hex key works with WPA2 only (WPA3 needs the passphrase).');
  if (f.channel !== 'auto' && !(/^\d+$/.test(f.channel) && ((+f.channel >= 1 && +f.channel <= 13) || [36, 40, 44, 48].includes(+f.channel)))) e.push('Channel: auto, 1–13 or 36/40/44/48.');
  if (f.maxClients.trim() && !(/^\d+$/.test(f.maxClients.trim()) && +f.maxClients >= 1 && +f.maxClients <= 64)) e.push('Maximum devices: 1–64.');
  return e;
}

export function buildWifi(f: WifiForm): string {
  const l = [`ssid=${f.ssid}`, `psk=${f.psk}`];
  if (f.channel !== 'auto') l.push(`channel=${f.channel}`);
  if (f.security !== 'wpa2') l.push(`security=${f.security}`);
  if (f.maxClients.trim()) l.push(`max_clients=${f.maxClients.trim()}`);
  return assertCanonical(l.join('\n') + '\n');
}

const NAME = /^[A-Za-z0-9_-]{1,16}$/;
const ADDR = /^(any|pl:[A-Za-z0-9_-]{1,16}|[0-9a-fA-F:.]+(\/\d{1,3})?)$/;

export function checkPolicy(f: PolicyForm): string[] {
  const e: string[] = [];
  const lists = new Set(f.prefixes.map((p) => p.name));
  const acls = new Set([...f.acls.map((a) => a.name), ...f.defaults.map((d) => d.name)]);
  for (const p of f.prefixes) {
    if (!NAME.test(p.name)) e.push(`Prefix list "${p.name}": names are 1–16 letters, digits, - or _.`);
    if (!/^\d+$/.test(p.seq)) e.push(`Prefix list ${p.name}: seq must be a number.`);
    if (!/^[0-9a-fA-F:.]+\/\d{1,3}$/.test(p.prefix.trim())) e.push(`Prefix list ${p.name}: "${p.prefix}" is not a prefix.`);
  }
  for (const a of f.acls) {
    if (!NAME.test(a.name)) e.push(`Access list "${a.name}": names are 1–16 letters, digits, - or _.`);
    if (!/^\d+$/.test(a.seq)) e.push(`Access list ${a.name}: seq must be a number.`);
    if (!/^(any|tcp|udp|icmp|\d{1,3})$/.test(a.proto)) e.push(`Access list ${a.name}: protocol is any, tcp, udp, icmp or a number.`);
    for (const x of [a.src, a.dst]) {
      if (!ADDR.test(x.trim())) e.push(`Access list ${a.name}: "${x}" must be any, an address, a prefix or pl:LIST.`);
      if (x.startsWith('pl:') && !lists.has(x.slice(3))) e.push(`Access list ${a.name}: prefix list ${x.slice(3)} is not defined.`);
    }
    if (a.port.trim() && !/^\d{1,5}(-\d{1,5})?$/.test(a.port.trim())) e.push(`Access list ${a.name}: port is a number or a range like 1000-2000.`);
  }
  for (const b of f.binds) {
    if (b.kind === 'acl' && !acls.has(b.name)) e.push(`Interface ${b.iface}: access list ${b.name} is not defined.`);
    if (b.kind === 'prefix-list' && !lists.has(b.name)) e.push(`Interface ${b.iface}: prefix list ${b.name} is not defined.`);
  }
  for (const r of f.routes) {
    if (!/^[0-9a-fA-F:.]+\/\d{1,3}$/.test(r.dst.trim())) e.push(`Route: "${r.dst}" is not a prefix.`);
    if (r.gw.trim() && !/^[0-9a-fA-F:.]+$/.test(r.gw.trim())) e.push(`Route ${r.dst}: gateway is an address.`);
    if (r.metric.trim() && !/^\d+$/.test(r.metric.trim())) e.push(`Route ${r.dst}: metric is a number.`);
    if (r.via === 'lan' || r.via === 'eth1') e.push(`Route ${r.dst}: the device cannot send traffic out through ${r.via}; use wan or mgmt.`);
    else if (r.dst.includes(':') && (r.via !== 'wan' || r.gw.trim())) e.push(`Route ${r.dst}: IPv6 routes can only go via wan, without a gateway.`);
  }
  for (const p of f.prefixes) {
    for (const [k, v] of [['ge', p.ge], ['le', p.le]] as const) if (v.trim() && !/^\d{1,3}$/.test(v.trim())) e.push(`Prefix list ${p.name}: ${k} must be a prefix length.`);
  }
  for (const r of f.routes) if (r.from.trim() && !/^[0-9a-fA-F:.]+\/\d{1,3}$/.test(r.from.trim())) e.push(`Route ${r.dst}: "from" is a prefix.`);
  // The device refuses a repeated statement (heqk config parser, duplicate keys refused): one line per
  // (list, seq), one default per access list, one binding per (interface, kind, direction), one route per
  // (destination, from, via) — failover through different interfaces is allowed.
  const dup = (what: string, keys: string[]) => {
    const seen = new Set<string>();
    for (const k of keys) { if (seen.has(k)) e.push(`${what} ${k.replace(/\|/g, ' ')} appears twice.`); seen.add(k); }
  };
  dup('Prefix list', f.prefixes.map((p) => `${p.name}|seq|${p.seq}`));
  dup('Access list', f.acls.map((a) => `${a.name}|seq|${a.seq}`));
  dup('Default for access list', f.defaults.map((d) => d.name));
  dup('Interface binding', f.binds.map((b) => `${b.iface}|${b.kind}|${b.dir}`));
  dup('Route', f.routes.map((r) => `${r.dst.trim()}|from|${r.from.trim() || 'any'}|via|${r.via}`));
  if (new TextEncoder().encode(buildPolicyText(f)).length > 4096) e.push('The policy is larger than the 4096 bytes the device reads.');
  return e;
}

/** The policy text (definitions before use, as the device requires). */
/** The device's policy section (GET /api/config → policy_text) as the editor's form. Null when a line uses a
 *  statement this editor does not model (the text is then kept and re-sent verbatim, never rebuilt). */
export function parsePolicyText(text: string): PolicyForm | null {
  const f: PolicyForm = { prefixes: [], acls: [], defaults: [], binds: [], routes: [] };
  for (const ln of text.split('\n').map((x) => x.trim()).filter((x) => x && x !== 'HQPOL1')) {
    const w = ln.split(/\s+/);
    let m: RegExpMatchArray | null;
    if ((m = ln.match(/^prefix-list (\S+) seq (\d+) (permit|deny) (\S+)(?: ge (\d+))?(?: le (\d+))?$/))) f.prefixes.push({ name: m[1], seq: m[2], action: m[3] as PrefixRow['action'], prefix: m[4], ge: m[5] ?? '', le: m[6] ?? '' });
    else if ((m = ln.match(/^acl (\S+) seq (\d+) (allow|block|drop) (\S+) (\S+) (\S+)(?: (\S+))?$/))) f.acls.push({ name: m[1], seq: m[2], action: m[3] as AclRow['action'], proto: m[4], src: m[5], dst: m[6], port: m[7] ?? '' });
    else if ((m = ln.match(/^acl (\S+) default (allow|block|drop)$/))) f.defaults.push({ name: m[1], action: m[2] as AclRow['action'] });
    else if (w[0] === 'interface' && w.length === 5 && /^(lan|eth1|wan|mgmt)$/.test(w[1]) && /^(acl|prefix-list)$/.test(w[2]) && /^(in|out)$/.test(w[3])) f.binds.push({ iface: w[1] as BindRow['iface'], kind: w[2] as BindRow['kind'], dir: w[3] as BindRow['dir'], name: w[4] });
    else if ((m = ln.match(/^route (\S+)(?: from (\S+))? via (lan|eth1|wan|mgmt)(?: gw (\S+))?(?: metric (\d+))?$/))) f.routes.push({ dst: m[1], from: m[2] ?? '', via: m[3] as RouteRow['via'], gw: m[4] ?? '', metric: m[5] ?? '' });
    else return null;
  }
  return f;
}

export function buildPolicyText(f: PolicyForm): string {
  const l = ['HQPOL1'];
  for (const p of f.prefixes) l.push(`prefix-list ${p.name} seq ${p.seq} ${p.action} ${p.prefix.trim()}${p.ge.trim() ? ` ge ${p.ge.trim()}` : ''}${p.le.trim() ? ` le ${p.le.trim()}` : ''}`);
  for (const a of f.acls) l.push(`acl ${a.name} seq ${a.seq} ${a.action} ${a.proto} ${a.src.trim()} ${a.dst.trim()}${a.port.trim() ? ` ${a.port.trim()}` : ''}`);
  for (const d of f.defaults) l.push(`acl ${d.name} default ${d.action}`);
  for (const b of f.binds) l.push(`interface ${b.iface} ${b.kind} ${b.dir} ${b.name}`);
  for (const r of f.routes) l.push(`route ${r.dst.trim()}${r.from.trim() ? ` from ${r.from.trim()}` : ''} via ${r.via}${r.gw.trim() ? ` gw ${r.gw.trim()}` : ''}${r.metric.trim() ? ` metric ${r.metric.trim()}` : ''}`);
  return l.join('\n') + '\n';
}

/** The exact 4096-byte staged file (newline-padded, as os/build/make-cm5-heqk-disk.sh stages it). */
export function stagePolicy(text: string): Uint8Array {
  const b = new TextEncoder().encode(text);
  if (b.length > 4096) throw new Error('POLICY.TXT larger than 4096 bytes.');
  const out = new Uint8Array(4096).fill(0x0a);
  out.set(b);
  return out;
}

/** A line diff for review (current file as the device reports it vs the draft). */
export function lineDiff(before: string, after: string): { kind: 'added' | 'removed' | 'unchanged'; text: string }[] {
  const a = before.split('\n').filter((x) => x !== ''), b = after.split('\n').filter((x) => x !== '');
  const out: { kind: 'added' | 'removed' | 'unchanged'; text: string }[] = [];
  for (const x of a) out.push(b.includes(x) ? { kind: 'unchanged', text: x } : { kind: 'removed', text: x });
  for (const x of b) if (!a.includes(x)) out.push({ kind: 'added', text: x });
  return out;
}
