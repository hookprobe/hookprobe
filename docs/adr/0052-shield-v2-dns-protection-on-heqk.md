# ADR 0052 — Shield v2: DNS protection on heqk, built on the dnsXai model and its lessons

**Status:** 🟡 Proposed (2026-11-07) · **Supersedes:** the Shield v1 hook (`d2cee9b`, `os/kernel/kernel/src/dnsblock.rs`)
**Related:** ADR 0023 (enforcement separation — refuse a NAME, never a customer's PACKET), ADR 0033 (DNS sinkhole/RPZ on
the Linux tier), ADR 0049 D1 (operator-signed files), ADR 0050 (parser placement).

## Context

Shield v1 on the heqk AP matched a client's UDP/53 query and answered `0.0.0.0` / NODATA. On metal (2026-11-07) the
signed list loaded and 136 iPhone queries reached the hook, yet `example.org` loaded in Safari with `blocked=0`; the
heartbeat sampled one name per 5 s, so it could not show whether the query arrived. v1 was also written without
consulting the production engine it replaces. Two read-only studies of dnsXai (V1 `legacy/v1/shared/dnsXai/`, V2
`legacy/linux-tier/modules/dnsxai/`) were made before this ADR. Their findings drive every decision below.

**What dnsXai got right (kept):** the gateway is the resolver of record (DHCP DNS = gateway; Guardian DNATs every client
UDP/TCP 53 to it); NXDOMAIN for every query type; exact + parent-domain matching; an immutable SYSTEM never-block floor
(captive-portal checks, NTP, OCSP/CRL, OS updates); tracking subdomains do not inherit an allowlisted parent; atomic list
replacement; blocklists from hosts / adblock `||d^` / bare formats.

**What dnsXai got wrong (not repeated):** subdomain blocking silently broken by a Bloom-filter fast path; CNAME
"uncloaking" by a second upstream query per hop (doubles upstream load, up to ~10 s); no response cache in the engine;
UDP only (truncated answers fail); pause and privacy settings that are never applied; a top-10 that is always 1 per
domain; an ML ensemble with random weights and keyword substring rules that block `geometric`/`collection`; a default
allowlist that unblocks `google-analytics.com` and the Facebook pixel (`facebook.net`, all of `cloudfront.net`); an
empty download overwriting the good list; no per-client visibility; no handling of DDR, the Firefox canary, or iCloud
Private Relay.

## Decision

**D1 — The AP is the resolver of record, and every client DNS query goes through Shield.** DHCP (v4) already hands out
the AP address. Shield also sees queries a client sends to *any* resolver (hard-coded 8.8.8.8 etc.): UDP/53 from a LAN
client to any destination is policy-checked; allowed queries are forwarded to the upstream exactly as today, and the
reply is returned from the address the client asked. **TCP/53**: the first data segment carries the 2-byte length +
query; a blocked name is refused with a TCP RST (the client cannot get an answer by retrying over TCP); allowed TCP
passes. **DoT (TCP/853)** is rejected (RST) under `encrypted_dns=block` (default), so Android "Automatic" Private DNS
falls back to plain DNS; `encrypted_dns=allow` lets it pass and Shield reports it. **IPv6**: while Shield is active the
LAN RA carries **no** RDNSS pointing at the ISP's resolver (v1 advertised the WAN's DHCPv6 DNS, a silent bypass);
dual-stack clients use the DHCPv4 resolver.

**D2 — How a blocked name is answered.** NXDOMAIN (RCODE 3) for every QTYPE, question echoed, no SOA (so nothing is
negatively cached: unblocking takes effect at once — dnsXai's 1 h `neg-ttl` kept unblocked names dead). When the
query carried EDNS(0), the answer carries an OPT record with **Extended DNS Error 15 "Blocked"** (RFC 8914) so clients
and tools can tell *policy* from *nonexistent*. Shield answers from the device; the query never leaves it.

**D3 — Encrypted-DNS and bypass controls (none of these existed in V1 or V2):**
- `resolver.arpa` and below (DDR, RFC 9462 `_dns.resolver.arpa` SVCB): NODATA — "no designated resolver", so iOS 16+ /
  macOS 13+ / Windows do not upgrade to the upstream's DoH/DoT behind the AP's back. Always on.
- `use-application-dns.net` (Firefox canary): NXDOMAIN — Firefox disables automatic DoH. Always on.
- `mask.icloud.com`, `mask-h2.icloud.com` (iCloud Private Relay, Apple's documented network opt-out): NXDOMAIN when
  `private_relay=block`; default `report` (answered normally, counted per client and shown in Shield).
- Known DoH hostnames (dns.google, cloudflare-dns.com, dns.quad9.net, doh.opendns.com, dns.nextdns.io,
  dns.adguard-dns.com, …): NXDOMAIN only under `encrypted_dns=block` (stops name-bootstrapped DoH; IP-literal DoH is
  reported, not blocked — blocking 1.1.1.1:443 would break legitimate websites, ADR 0023).
- Every bypass signal is counted per client and surfaced ("this phone uses encrypted DNS — Shield can't see it").

**D4 — Matching and precedence.** Name normalised (lowercase, trailing dot dropped). A name is checked with every
parent suffix down to the registrable level (a bare TLD is never matched). Precedence, first hit wins:
1. **SYSTEM floor** (compiled in, cannot be removed): connectivity/captive checks (captive.apple.com,
   connectivitycheck.gstatic.com, clients3.google.com, msftconnecttest.com, msftncsi.com, detectportal.firefox.com,
   nmcheck.gnome.org, connectivity-check.ubuntu.com), NTP (time.apple.com, *.pool.ntp.org, time.windows.com), OCSP/CRL
   (ocsp.apple.com, ocsp.digicert.com, …), and this device's own update/MSSP endpoints → always allowed.
2. **Bypass controls** (D3).
3. **Longest match between ALLOW and BLOCK wins** (the more specific rule decides; ties → allow). This replaces V1's
   keyword heuristic for "tracking subdomains don't inherit an allowed parent": allowing `yahoo.com` while the list has
   `ads.yahoo.com` keeps `ads.yahoo.com` blocked, with no keyword false positives.
4. Otherwise allowed.
No ML or keyword rule ever blocks (V1's were the main source of false positives). Lexical DGA/lookalike scoring (the
cheap part of the V2 Wasm module) may later raise a **detection** in the Detect feed — never a block (ADR 0023).

**D5 — Lists.** `BLOCK.TXT` and optional `ALLOW.TXT` on the boot partition, each operator-signed (ADR 0049 D1 key; a
refused or missing signature → that list is not loaded, Shield says why; forwarding continues — DNS filtering fails
open, it is protection, not enforcement). Accepted line formats: bare domain, hosts (`0.0.0.0 d`, `127.0.0.1 d`,
`:: d`), adblock `||d^` (lines with `$` options other than none are skipped and counted), `@@||d^` → allow. Capacity
**262,144 blocked domains** (2 MiB of 64-bit hashes; fits oisd/hagezi-sized lists) and 16,384 allowed. Sorted hash
table, binary search; duplicates removed; lines refused for syntax are counted, never silently dropped.

**D6 — CNAME cloaking, without extra queries.** Allowed queries' *replies* are inspected on the way back: the answer
section is walked (compression-aware, ≤ 32 RRs, bounded), and if any CNAME target is blocked (and the original name is
not allowed by D4) the reply is rewritten to NXDOMAIN + EDE 15 before it reaches the client. No second upstream query
(V1 doubled upstream load and added up to 10 s latency).

**D7 — Visibility (what the operator sees; fixes V1's broken stats).** Counters per verdict (allowed, blocked-list,
blocked-cname, ddr, canary, relay-seen/blocked, dot-refused, doh-name, tcp53-refused, system-floor hits, unparsable).
A **query log ring** of the last 256 queries {time, client, qtype, name (≤ 64 chars), verdict}. **Top blocked
domains** by the space-saving algorithm (K = 32, correct counts, bounded memory). **Per-client** totals (queries,
blocked, bypass signals) for up to 64 clients. Served as `GET /api/dns` (owner session required) and summarised in
`/api/health` for the Shield tile; the heartbeat prints a one-line summary plus the last blocked name. Privacy: the log
never leaves the device, is RAM-only and bounded (oldest overwritten), and is not persisted across reboot.

**D8 — Placement.** The decision logic (`shield.rs`: list store, matching, verdict, answer builders, CNAME walk,
stats) is pure, `no_std`, allocation-free and fuzzed (`[P-fuzz]`), like the other parsers; it runs in the AP forward
path (EL1) now and is a candidate for the EL0 DNS server in ADR 0050 D4 step 2.

## Consequences

- iOS/macOS/Firefox automatic encrypted-DNS upgrades are suppressed on a Shield network; Private Relay and IP-literal
  DoH are visible, and blockable by explicit operator choice.
- Unblocking is immediate (no negative caching); blocking a name used by a cached client takes effect on its next
  query (client caches are outside our control).
- DoT strict-mode clients break under `encrypted_dns=block` — by design, and reported per client.
- Bigger lists cost 2 MiB RAM and a longer boot read (~1 s for 5 MB).
- Not in this ADR (later): per-client policy profiles (kids/guests), schedules, pause, list download/refresh over the
  network (lists arrive on the card or via the MSSP channel today), ECH stripping, IPv6 query rewriting for clients with
  hard-coded v6 resolvers.

## Verification

`[P-shield]` (QEMU): parsing of every format; precedence (floor > bypass > longest match); NXDOMAIN + EDE builder; DDR /
canary / relay / DoH-name answers; TCP/53 first-segment check; DoT refusal; CNAME rewrite; space-saving top-K; query
ring; signature refusal. `[P-fuzz]` covers the query parser, the CNAME walker and the TCP/53 path. Metal: an iPhone on
the AP — `example.org` NXDOMAIN with the query visible in the log; `_dns.resolver.arpa` answered NODATA on join; a
Firefox/Chrome client's canary handled; 853 refused.
