#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 39 P2: investigation playbooks, written by hand from the entry-path graph (data/entry-paths.*) and ATT&CK /
D3FEND text. They are the CURRICULUM for investigation training (doc 39 §3.3), not a runtime rule set.

Organised as the graph showed (data/entry-paths-review.md): how attackers get in is almost always an exposed service
(T1190 / T1133) or a client exploit (T1203); what the gateway can see is the FOLLOW-ON behaviour. Each playbook says:
  seen   : what a gateway sees, in DNA v1 feature names and evidence-card terms;
  next   : ordered tool calls (the explainer's tools; `lookup_exposure` is doc 39 §3.4, not built yet);
  confirms / clears : what result moves the verdict either way (clears also teaches stopping);
  close  : D3FEND defensive techniques, always as PROPOSALS to the owner (policy enum of propose_policy_change, or
           an owner action); Neuro never enforces (doc 30);
  blind  : what the gateway cannot observe, said plainly.
No CVE id appears here (doc 39 §1). Validation: every ATT&CK id exists (and its name matches) in intel-data's
ATT&CK STIX, every D3FEND id exists with the stated label, tools, policies and DNA features are known names.
Usage: python3 -I playbooks.py <out prefix> [--raw ~/.cache/hookprobe-intel-data/raw]
"""
import argparse, glob, json, os, sys

TOOLS = {"lookup_reputation", "query_flows", "query_dns", "propose_policy_change", "lookup_exposure"}
POLICIES = {"isolated", "internet_only", "lan_only", "full_access", "owner_action"}
DNA = {"log_flows", "out_frac", "log_remotes", "log_dst_ports", "port_entropy", "top_port_share", "fail_ratio", "log_bytes_out",
       "log_bytes_in", "log_out_in_ratio", "log_mean_dur", "log_pkts_per_flow", "tcp_frac", "udp_frac", "icmp_frac", "wellknown_frac",
       "telnet_frac", "ssh_frac", "smb_frac", "web_frac", "dns_frac", "ntp_frac", "periodic_cv", "log_period_s", "log_max_per_min",
       "novel_pair_frac", "warninglist_frac", "unrouted_frac", "log_countries", "log_asns", "lan_peer_frac", "log_inbound_sources"}

P = [
 # ---- getting in -------------------------------------------------------------------------------------------------
 dict(id="T1190", name="Exploit Public-Facing Application", kind="entry", classes=["router", "edge", "nas", "camera", "printer", "server"],
      seen=["inbound connections from many new remote sources to a service port (log_inbound_sources up, novel_pair_frac up)",
            "a request burst to an admin or web port followed within minutes by the device's FIRST outbound connection to a new peer",
            "the device starts behaving differently right after: new destinations, a download, periodic traffic (see the follow-on playbooks)"],
      dna=["log_inbound_sources", "novel_pair_frac", "web_frac", "wellknown_frac"],
      next=[("query_flows", "the device", "is the service reachable from outside, since when, and who connected just before the change"),
            ("lookup_reputation", "the inbound sources", "known scanners or exploit infrastructure"),
            ("lookup_exposure", "the device", "known-exploited weaknesses for this product or class (doc 39 §3.4)"),
            ("query_flows", "the device", "any new outbound connection, download or periodic peer after the inbound burst")],
      confirms=["new outbound behaviour starts right after inbound traffic to the exposed service",
                "the inbound sources are known exploit or scanning infrastructure AND the device then reaches a new peer"],
      clears=["only inbound probing, no change in the device's own outbound behaviour (internet background noise)",
              "the service is not reachable from outside (the inbound traffic was blocked at the gateway)"],
      close=[("D3-ITF", "Inbound Traffic Filtering", "owner_action", "close the port forward or UPnP mapping to the service"),
             ("D3-SU", "Software Update", "owner_action", "update the device's firmware"),
             ("D3-NI", "Network Isolation", "internet_only", "keep it off the LAN until updated, if it already changed behaviour")],
      blind=["the exploit payload itself when the service is encrypted", "whether the exploit succeeded inside the device; only its consequences on the network"]),
 dict(id="T1133", name="External Remote Services", kind="entry", classes=["edge", "router", "nas", "server"],
      seen=["successful sessions to a VPN or remote-access port from unusual countries or networks (log_countries, log_asns up)",
            "a remote session at an unusual hour followed by LAN-wide connections from the device (lan_peer_frac up)"],
      dna=["log_countries", "log_asns", "lan_peer_frac", "log_inbound_sources"],
      next=[("query_flows", "the device", "who held remote sessions, from where, how long"),
            ("lookup_reputation", "the remote peers", "VPN exits, hosting providers, known bad ranges"),
            ("query_flows", "the device", "what it reached on the LAN during and after the session")],
      confirms=["a session from a known-bad or never-seen network, followed by LAN discovery or lateral connections"],
      clears=["sessions from the owner's usual networks and hours, no LAN-wide activity afterwards"],
      close=[("D3-MFA", "Multi-factor Authentication", "owner_action", "require a second factor on the remote-access service"),
             ("D3-DRA", "Disable Remote Access", "owner_action", "turn remote access off if it is not used"),
             ("D3-ITF", "Inbound Traffic Filtering", "owner_action", "allow the service only from known networks")],
      blind=["who typed the credentials; a valid login looks the same as the owner's"]),
 dict(id="T1110", name="Brute Force", kind="entry", classes=["router", "nas", "camera", "server", "edge"],
      seen=["many failed connections or logins to SSH, Telnet, RDP or a web login (fail_ratio, ssh_frac or telnet_frac up)",
            "from one source (inbound) or from a LAN device to many hosts (outbound: the device itself is infected)"],
      dna=["fail_ratio", "ssh_frac", "telnet_frac", "log_inbound_sources", "log_remotes"],
      next=[("query_flows", "the targeted device", "count of attempts, sources, and whether any attempt succeeded"),
            ("lookup_reputation", "the sources", "known brute-force infrastructure"),
            ("query_flows", "the source if it is a LAN device", "is it also scanning or connecting out to new peers (infected)")],
      confirms=["a successful login after a run of failures", "a LAN device brute-forcing others (lateral, often a botnet)"],
      clears=["a handful of failures from one known LAN host (a mistyped password), no success from elsewhere"],
      close=[("D3-CDP", "Change Default Password", "owner_action", "replace default credentials on the targeted device"),
             ("D3-AL", "Account Locking", "owner_action", "lock out after repeated failures where the device supports it"),
             ("D3-ITF", "Inbound Traffic Filtering", "owner_action", "do not expose SSH or Telnet to the internet")],
      blind=["the passwords tried", "whether a success on an encrypted service led to commands being run"]),
 dict(id="T1203", name="Exploitation for Client Execution", kind="entry", classes=["workstation", "phone"],
      seen=["a laptop or phone fetches a document or page from a new site, then starts NEW outbound behaviour: downloads, periodic connections, uploads"],
      dna=["novel_pair_frac", "log_remotes", "web_frac"],
      next=[("query_dns", "the device", "which new domains were resolved just before the change"),
            ("lookup_reputation", "those domains and addresses", "malware delivery or phishing infrastructure"),
            ("query_flows", "the device", "periodic or download behaviour after the visit")],
      confirms=["a known-bad delivery domain followed by periodic C2-like traffic or a tool download"],
      clears=["a new site with no change in the device's behaviour afterwards (ordinary browsing)"],
      close=[("D3-DNSDL", "DNS Denylisting", "owner_action", "block the delivery domain at the gateway's resolver"),
             ("D3-SU", "Software Update", "owner_action", "update the browser and document reader"),
             ("D3-NI", "Network Isolation", "internet_only", "keep the device off the LAN while it is checked")],
      blind=["what ran on the device; the gateway sees only its network consequences"]),
 # ---- what happens next (the gateway's strength) ------------------------------------------------------------------
 dict(id="T1105", name="Ingress Tool Transfer", kind="follow_on", classes=["server", "router", "camera", "nas", "workstation"],
      seen=["a device that never downloads suddenly fetches a file over HTTP or an odd port from a new peer (log_bytes_in, novel_pair_frac up)",
            "on IoT: a small download right after inbound traffic to an exposed port (a dropper)"],
      dna=["log_bytes_in", "novel_pair_frac", "web_frac", "log_out_in_ratio"],
      next=[("lookup_reputation", "the download peer", "malware hosting"),
            ("query_flows", "the device", "what it did right after the download: new peers, scanning, periodic traffic")],
      confirms=["a download from known malware hosting followed by scanning or C2-like traffic"],
      clears=["a vendor or CDN update host the device always uses (check the baseline)"],
      close=[("D3-OTF", "Outbound Traffic Filtering", "owner_action", "block the download peer"),
             ("D3-NI", "Network Isolation", "isolated", "isolate the device until it is reflashed or restored"),
             ("D3-RS", "Restore Software", "owner_action", "reflash or restore the device")],
      blind=["the file's content when the transfer is encrypted"]),
 dict(id="T1071", name="Application Layer Protocol (command and control)", kind="follow_on", classes=["all"],
      seen=["periodic connections to one new peer: low periodic_cv, steady log_period_s, small requests, for hours",
            "the same pattern from a device with no reason to call home that way"],
      dna=["periodic_cv", "log_period_s", "novel_pair_frac", "log_remotes"],
      next=[("lookup_reputation", "the peer", "known C2 or bot infrastructure"),
            ("query_dns", "the device", "how the peer is resolved: fixed name, changing names (DGA), direct IP"),
            ("query_flows", "the device", "when the pattern started and what preceded it (an entry event?)")],
      confirms=["a known C2 peer, or periodic traffic that started right after an entry event and has no vendor explanation"],
      clears=["the device maker's cloud or a known time, update or telemetry service at its usual period"],
      close=[("D3-OTF", "Outbound Traffic Filtering", "owner_action", "block the peer"),
             ("D3-DNSDL", "DNS Denylisting", "owner_action", "block the domain"),
             ("D3-NI", "Network Isolation", "isolated", "isolate the device while it is checked")],
      blind=["the commands inside an encrypted channel"]),
 dict(id="T1568.002", name="Domain Generation Algorithms", kind="follow_on", classes=["all"],
      seen=["many lookups of random-looking names, most failing (NXDOMAIN), from one device"],
      dna=["dns_frac", "fail_ratio", "novel_pair_frac"],
      next=[("query_dns", "the device", "the failing names, their entropy, and which one finally resolved"),
            ("lookup_reputation", "the name that resolved and its address", "known C2"),
            ("query_flows", "the device", "traffic to the resolved address")],
      confirms=["a burst of random-looking failed lookups followed by a connection to the one name that resolved"],
      clears=["a CDN or tracker using long random-looking labels that all resolve, with ordinary traffic"],
      close=[("D3-DNSDL", "DNS Denylisting", "owner_action", "block the resolved C2 domain"),
             ("D3-NI", "Network Isolation", "isolated", "isolate the device")],
      blind=["anything when the device uses encrypted DNS that bypasses the gateway (see T1572)"]),
 dict(id="T1505.003", name="Web Shell", kind="follow_on", classes=["server", "nas", "edge"],
      seen=["a self-hosted web service receives requests from a new external source at irregular intervals, and the server then reaches out to new peers"],
      dna=["log_inbound_sources", "web_frac", "novel_pair_frac"],
      next=[("query_flows", "the server", "which external sources talk to the web port, how regularly, since when"),
            ("lookup_reputation", "those sources", "known attacker infrastructure"),
            ("query_flows", "the server", "new outbound connections that the service never made before")],
      confirms=["a recurring external source after an entry event, plus new outbound behaviour from the server"],
      clears=["the owner's own remote use from known networks"],
      close=[("D3-ITF", "Inbound Traffic Filtering", "owner_action", "stop exposing the web service"),
             ("D3-RS", "Restore Software", "owner_action", "restore the service from a known-good copy"),
             ("D3-NI", "Network Isolation", "internet_only", "keep it off the LAN while restored")],
      blind=["the shell file and the commands sent through it"]),
 dict(id="T1496", name="Resource Hijacking (cryptomining)", kind="follow_on", classes=["server", "router", "camera", "nas"],
      seen=["long-lived connections to mining-pool ports or pools, steady small traffic, from a device that never did it (log_mean_dur up)"],
      dna=["log_mean_dur", "novel_pair_frac", "log_remotes"],
      next=[("lookup_reputation", "the peer", "known mining pools"),
            ("query_flows", "the device", "when it started and what preceded it")],
      confirms=["a known pool, or a stratum-like port, starting after an entry event"],
      clears=["the owner runs mining on this device on purpose"],
      close=[("D3-OTF", "Outbound Traffic Filtering", "owner_action", "block the pool"),
             ("D3-NI", "Network Isolation", "isolated", "isolate and restore the device")],
      blind=["CPU load on the device itself"]),
 dict(id="T1046", name="Network Service Discovery (scanning)", kind="follow_on", classes=["all"],
      seen=["one device touches many hosts or ports with mostly failed connections (log_dst_ports, port_entropy, fail_ratio up; fanout on the card)",
            "outbound to the internet on Telnet/SSH ports: a bot looking for its next victims"],
      dna=["log_dst_ports", "port_entropy", "fail_ratio", "telnet_frac", "lan_peer_frac", "log_remotes"],
      next=[("query_flows", "the device", "targets: LAN only (lateral) or internet-wide (bot)"),
            ("query_flows", "the device", "what preceded it: entry event, download"),
            ("lookup_exposure", "the device", "is this a class botnets recruit (cameras, routers, NAS)")],
      confirms=["internet-wide Telnet/SSH scanning from an IoT device (bot recruitment)", "LAN-wide scanning after a new download"],
      clears=["a few ports on one LAN host (device discovery: printers, casting, DLNA)", "an owner-run network scanner"],
      close=[("D3-NI", "Network Isolation", "isolated", "isolate the scanning device"),
             ("D3-CDP", "Change Default Password", "owner_action", "replace default credentials, then reflash"),
             ("D3-OTF", "Outbound Traffic Filtering", "owner_action", "block outbound Telnet from IoT devices")],
      blind=["which vulnerability the scan looks for"]),
 dict(id="T1498", name="Network Denial of Service (flooding)", kind="follow_on", classes=["camera", "router", "server", "nas"],
      seen=["a sudden very high packet rate to one or few external targets (log_max_per_min, log_bytes_out, log_pkts_per_flow up), often UDP or SYN"],
      dna=["log_max_per_min", "log_bytes_out", "log_pkts_per_flow", "udp_frac"],
      next=[("query_flows", "the device", "targets, rate and duration"),
            ("query_flows", "the device", "C2-like traffic before the flood (orders from the bot master)")],
      confirms=["a flood that starts on command after periodic C2 traffic"],
      clears=["a speed test or a large legitimate upload the owner started"],
      close=[("D3-NI", "Network Isolation", "isolated", "isolate the device"),
             ("D3-OTF", "Outbound Traffic Filtering", "owner_action", "rate-limit the device's outbound traffic")],
      blind=["who ordered the attack"]),
 dict(id="T1048", name="Exfiltration Over Alternative Protocol", kind="follow_on", classes=["all"],
      seen=["a large upload to a new destination, out of the device's habits (log_bytes_out, log_out_in_ratio up; out= on the card)",
            "at night, or over an unusual protocol or port"],
      dna=["log_bytes_out", "log_out_in_ratio", "novel_pair_frac"],
      next=[("lookup_reputation", "the destination", "file-sharing, paste or attacker hosting"),
            ("query_flows", "the device", "is this the first time; what preceded it"),
            ("query_dns", "the device", "the destination's name")],
      confirms=["a first-ever large upload to an unknown or known-bad destination after an entry event"],
      clears=["a known backup, photo-sync or camera-cloud service the owner uses (owner CONTEXT)"],
      close=[("D3-OTF", "Outbound Traffic Filtering", "owner_action", "block the destination"),
             ("D3-NI", "Network Isolation", "isolated", "isolate the device while it is checked")],
      blind=["what data left when the transfer is encrypted"]),
 dict(id="T1572", name="Protocol Tunneling (DNS or VPN bypass)", kind="follow_on", classes=["all"],
      seen=["the device talks DNS or a VPN protocol to an outside server instead of the gateway's resolver (dns_bypass on the card)",
            "unusually large or many DNS queries to one domain (tunnel)"],
      dna=["dns_frac", "log_bytes_out", "novel_pair_frac"],
      next=[("query_dns", "the device", "which resolver it uses, query sizes, the domain"),
            ("lookup_reputation", "the outside server", "known tunnel or C2 endpoints")],
      confirms=["high-volume DNS to one unknown domain, or a VPN to an unknown endpoint from an IoT device"],
      clears=["the owner's work VPN or a browser's encrypted DNS provider (owner CONTEXT)"],
      close=[("D3-OTF", "Outbound Traffic Filtering", "owner_action", "force DNS through the gateway; block the endpoint"),
             ("D3-NI", "Network Isolation", "internet_only", "limit the device while it is checked")],
      blind=["the tunnelled content"]),
 dict(id="T1021", name="Remote Services (lateral movement)", kind="follow_on", classes=["workstation", "server", "nas"],
      seen=["a device connects to SMB, RDP or SSH on several LAN hosts it never used (smb_frac, lan_peer_frac up)", "often after a brute-force run"],
      dna=["smb_frac", "ssh_frac", "lan_peer_frac", "fail_ratio"],
      next=[("query_flows", "the source device", "which LAN hosts, which services, success or failure"),
            ("query_flows", "each reached host", "did they change behaviour afterwards")],
      confirms=["new LAN-wide service connections followed by changes on the reached hosts"],
      clears=["a NAS or backup server doing its scheduled job (owner CONTEXT, baseline)"],
      close=[("D3-NI", "Network Isolation", "isolated", "isolate the source device"),
             ("D3-BDI", "Broadcast Domain Isolation", "owner_action", "put IoT and PCs on separate network segments")],
      blind=["the commands run on the reached hosts"]),
 dict(id="T1090", name="Proxy (proxyware, residential proxy)", kind="follow_on", classes=["router", "camera", "media", "workstation"],
      seen=["a device relays traffic for many outside parties: many remote peers and countries, balanced in and out (log_remotes, log_countries up; log_out_in_ratio near 0)"],
      dna=["log_remotes", "log_countries", "log_asns", "log_out_in_ratio"],
      next=[("query_flows", "the device", "how many peers, which countries, since when"),
            ("lookup_reputation", "the coordinating peer", "known proxyware services")],
      confirms=["a sudden jump in peers and countries with relayed traffic, from a device that never did it"],
      clears=["the owner installed a bandwidth-sharing app knowingly"],
      close=[("D3-OTF", "Outbound Traffic Filtering", "owner_action", "block the proxy service"),
             ("D3-NI", "Network Isolation", "isolated", "isolate and reset the device")],
      blind=["whose traffic is relayed"]),
 # ---- what the gateway cannot see: said plainly so the explainer does not guess ---------------------------------
 dict(id="T1003", name="OS Credential Dumping", kind="follow_on", classes=["workstation", "server", "edge"], observable=False,
      seen=["nothing directly. A gateway may see what follows: logins elsewhere with valid accounts, lateral connections"],
      dna=[],
      next=[("query_flows", "the device", "new LAN logins or remote sessions after a suspected compromise")],
      confirms=["a compromised device followed by successful logins on other hosts"],
      clears=["no follow-on activity"],
      close=[("D3-CRO", "Credential Rotation", "owner_action", "rotate the passwords used on the affected device"),
             ("D3-MFA", "Multi-factor Authentication", "owner_action", "add a second factor where possible")],
      blind=["the dumping itself happens inside the device"]),
]


def find(raw, src, pat):
    m = sorted(glob.glob(os.path.join(raw, src, "*", pat)))
    if not m:
        sys.exit("missing %s/%s" % (src, pat))
    return m[-1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out"); ap.add_argument("--raw", default=os.path.expanduser("~/.cache/hookprobe-intel-data/raw"))
    a = ap.parse_args()
    att = {}
    for o in json.load(open(find(a.raw, "mitre-attack-stix", "enterprise-attack.json")))["objects"]:
        if o["type"] == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
            tid = [e["external_id"] for e in o["external_references"] if e.get("source_name") == "mitre-attack"][0]
            att[tid] = o["name"]
    d3 = {n["d3f:d3fend-id"]: n.get("rdfs:label") for n in json.load(open(find(a.raw, "mitre-d3fend", "d3fend__d3fend.json")))["@graph"]
          if isinstance(n, dict) and "d3f:d3fend-id" in n}
    errs = []
    for p in P:
        if p["id"] not in att:
            errs.append("%s: not an ATT&CK technique" % p["id"])
        elif att[p["id"]].split(":")[-1].strip().lower() not in p["name"].lower() and p["name"].split(" (")[0].lower() != att[p["id"]].lower():
            errs.append("%s: name %r vs ATT&CK %r" % (p["id"], p["name"], att[p["id"]]))
        for t, _, _ in p["next"]:
            if t not in TOOLS: errs.append("%s: tool %s" % (p["id"], t))
        for did, lab, pol, _ in p["close"]:
            if d3.get(did) != lab: errs.append("%s: D3FEND %s %r vs %r" % (p["id"], did, lab, d3.get(did)))
            if pol not in POLICIES: errs.append("%s: policy %s" % (p["id"], pol))
        for f in p["dna"]:
            if f not in DNA: errs.append("%s: DNA feature %s" % (p["id"], f))
        if "CVE-" in json.dumps(p): errs.append("%s: contains a CVE id" % p["id"])
    if errs:
        sys.exit("INVALID:\n  " + "\n  ".join(errs))
    out = [dict(p, observable=p.get("observable", True),
                next=[dict(tool=t, on=on, why=w) for t, on, w in p["next"]],
                close=[dict(d3fend=i, label=l, proposal=pol, what=w) for i, l, pol, w in p["close"]]) for p in P]
    json.dump({"schema": "hookprobe.neuro.playbooks/1", "doc": "39 §3.2", "playbooks": out}, open(a.out + ".json", "w"), indent=1)
    with open(a.out + ".md", "w") as f:
        f.write("# Investigation playbooks (doc 39 §3.2), generated by `tools/neuro-research/playbooks.py`\n\n"
                "Curriculum, not a rule set. Close-in actions are **proposals** for the owner; Neuro never enforces.\n")
        for p in out:
            f.write("\n## %s %s (%s; %s)\n\n" % (p["id"], p["name"], "getting in" if p["kind"] == "entry" else "what happens next",
                                               ", ".join(p["classes"])))
            if not p["observable"]:
                f.write("**Not observable from the gateway.**\n\n")
            f.write("**Seen on the wire:**\n" + "".join("- %s\n" % s for s in p["seen"]))
            if p["dna"]:
                f.write("\nDNA v1 features: %s\n" % ", ".join("`%s`" % x for x in p["dna"]))
            f.write("\n**Next steps:**\n" + "".join("%d. `%s` on %s: %s\n" % (i + 1, s["tool"], s["on"], s["why"]) for i, s in enumerate(p["next"])))
            f.write("\n**Confirms:** %s\n\n**Clears:** %s\n\n" % ("; ".join(p["confirms"]), "; ".join(p["clears"])))
            f.write("**Close in (proposals):**\n" + "".join("- %s %s (`%s`): %s\n" % (c["d3fend"], c["label"], c["proposal"], c["what"]) for c in p["close"]))
            f.write("\n**Cannot see:** %s\n" % "; ".join(p["blind"]))
        f.write("\n---\nATT&CK® and D3FEND™ © The MITRE Corporation; see `entry-paths-review.md` for notices.\n")
    print("playbooks %d (%d entry, %d follow-on, %d not observable); all ids validated against ATT&CK and D3FEND" % (
        len(out), sum(p["kind"] == "entry" for p in out), sum(p["kind"] == "follow_on" for p in out), sum(not p["observable"] for p in out)))


if __name__ == "__main__":
    main()
