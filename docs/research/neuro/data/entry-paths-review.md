# Entry-path graph: build and review (doc 39 P1, 2026-11-23)

`tools/neuro-research/entry_paths.py` built `entry-paths.json` / `entry-paths.md` from intel-data's raw files
(hashes in the JSON's `inputs_sha256`): CISA KEV (1,786 entries, newest 2026-11-18), the 25 NVD CVE 2.0 yearly
feeds, CTID's KEV → ATT&CK 16.1 mappings, CAPEC, and ATT&CK Enterprise (STIX). Deterministic; no model; no CVE text
copied beyond ids, vendor and product names.

## What the review changed (and why)

| Change | Reason |
|---|---|
| Camera / NAS / router / edge rules widened (D-Link DCS and DNR, DNS-320, Unraid, GPON, Zyxel firewalls → edge) | first pass put them in the wrong class |
| Edge rule runs before router | Zyxel firewalls were landing in "router" |
| Workstation rule narrowed to Microsoft client components and named client software | "word" matched WordPress, "edge" matched VMware SD-WAN Edge |
| **CWE → CAPEC → ATT&CK fallback switched off** (`CAPEC_MAX = 0`) | even narrow chains named the same three techniques (HTML Smuggling, Embedded Payloads, Resource Forking) for server and router RCEs. The chain is too coarse to say how an attacker got in |
| Plex no longer treated as a client | Plex Media Server is a network service |

## What the graph says

1. **Getting in is two techniques.** For every appliance class (edge, router, NAS, camera, printer) and for
   self-hosted servers, the entry is **T1190 Exploit Public-Facing Application**: a network service the device
   exposes. For workstations and phones it is **T1203 Exploitation for Client Execution**: the user opens or visits
   something. CTID's curated mappings agree wherever they exist. T1133 External Remote Services (VPN, remote
   access) is a distant third.
2. **Both entries are gateway-visible.** In ATT&CK v18 each has analytics on network traffic flow or content. The
   gateway cannot see the exploit's payload in encrypted traffic, but it sees *who* reaches the exposed service, and
   what the device does next.
3. **What happens next is where a gateway earns its keep** (CTID impacts, mapped entries only):
   - **servers:** a command shell (T1059), a web shell (T1505.003), data theft (T1005), cryptomining (T1496), tool
     download (T1105), ransomware (T1486);
   - **edge:** shells, credential theft (T1555, T1003) and valid-account reuse (T1078);
   - **routers:** shells, cryptomining, flood traffic (T1499.002), sniffing (T1040);
   - **cameras:** denial-of-service floods (T1498, T1499), cryptomining.

   These are the signs DNA v1 and the explainer can see: new outbound peers, downloads, periodic C2, floods and
   scans from a device that never did them.
4. **Home device classes are thin.** Routers 78, NAS 23, cameras 19, printers 5 and media 5 KEV entries, against
   737 servers and 543 workstation entries. Weights for home classes rest on few examples (doc 39 §6.1).
5. **Reach.** 1,354 of the 1,786 KEV entries are network or adjacent reachable (NVD CVSS). The 432 local or physical
   ones are kept in the rows but not in the graph.

## Consequence for P2 (playbooks)

Playbooks should be organised around **exposure + follow-on**, not around CVEs:
- "a service on this device is reachable from outside" (T1190 / T1133 exposure);
- "this device now does something it never did": a shell or web shell's outbound C2, tool download, mining, flood,
  scan, data upload.

The CVE layer stays at inference: `lookup_exposure` (doc 39 §3.4) says which known-exploited entries hit this
product or class.

## Notices (attribution duties from the registry, P0)

- **CISA KEV:** public domain, U.S. Cybersecurity and Infrastructure Security Agency.
- **NVD:** this product uses data from the NVD API but is not endorsed or certified by the NVD.
- **CVE®, CWE™, CAPEC™, ATT&CK®:** © The MITRE Corporation. Reproduced and distributed with the permission of
  The MITRE Corporation. ATT&CK® is a registered trademark of The MITRE Corporation. No endorsement is implied.
- **CTID Mappings Explorer:** Apache-2.0, © MITRE Engenuity Center for Threat-Informed Defense (notice CT0104).
