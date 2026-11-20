# HEQK intelligence — dataset, feed and partnership research (2026-11-18)

> **Method.** Three research passes on 2026-11-18 read original sources: dataset pages, licence files,
> terms of use, API docs and repository LICENSE files. The three passes covered:
> 1. academic and research datasets;
> 2. feeds, knowledge bases and attack-simulation tooling;
> 3. national and regional CERTs and programmes (Switzerland, EU, UK, Romania, international).
>
> Every entry is in [`tools/intel-data/registry/sources.json`](../../../tools/intel-data/registry/sources.json),
> with the URLs actually read in `evidence`, `verified_on` and `verification_status`. The full table is
> generated as [CATALOGUE.md](CATALOGUE.md). No data file was downloaded during research. Facts that
> could not be checked are `null` with a note, never estimated.
>
> **Hosts unreachable from the research machine.** During research several sites failed DNS:
> cve.org, circl.lu (incl. vulnerability.circl.lu), feodotracker.abuse.ch, enisa.europa.eu,
> cybersecurity-centre.europa.eu, switch.ch, misp-project.org, data.europa.eu, docs.greynoise.io,
> community.emergingthreats.net, levelblue.com, archive.ics.uci.edu, stratosphereips.org and
> data.mendeley.com.
>
> **Cause, found afterwards:** the lab network's resolver (a HookProbe router running dnsXai)
> answers NXDOMAIN for at least feodotracker.abuse.ch, archive.ics.uci.edu, stratosphereips.org and
> data.mendeley.com, while 1.1.1.1 resolves them. HookProbe's own DNS protection blocks
> security-research sites. That is a false-positive report for dnsXai in its own right.
>
> Entries that depend on these sites are `partially_verified` or `unverified` and must be re-read
> before they are relied on.
>
> **Not legal advice.** Licence classifications are research findings for counsel to confirm.

## 1. Headline findings

1. **Public does not mean usable, and 2025–2026 made this sharper.** abuse.ch's Platforms Terms
   (effective 2025-11-04, updated 2026-10-21) make the free tier non-profit only:
   - URLhaus, ThreatFox and MalwareBazaar need an abuse.ch-Spamhaus Alliance subscription for
     commercial use;
   - §7.3 forbids training any AI model on abuse.ch data without Spamhaus' written consent;
   - the ban holds even for Feodo Tracker, SSLBL and YARAify, which are still stated as CC0.

   The registry records this: Feodo is **live intel yes, training no**.
2. **There is no licence-clean DNS benign baseline today:**
   - Tranco states no licence of its own, and since 2023-08-01 it has blended Cloudflare Radar
     (CC BY-NC) and CrUX (CC BY-SA);
   - Cloudflare Radar is NC;
   - Cisco Umbrella's list has its own terms.

   The DNS collection therefore cannot produce a commercial training build yet. Evaluation and research
   builds work.
3. **Every phishing feed checked is closed to a commercial edge product:**
   - OpenPhish bans commercial use and derivatives;
   - PhishStats bans redistribution;
   - PhishTank's data licence is unclear.
4. **Licences that are clear for commercial training and shipping:**
   - MITRE ATT&CK, CWE and CAPEC (keep the copyright notice);
   - CISA KEV and Vulnrichment (CC0);
   - the CVE List (CVE ToU);
   - the GitHub Advisory Database (CC BY 4.0);
   - Sigma and signature-base (DRL 1.1, which carries a runtime author-attribution duty);
   - Atomic Red Team (MIT), CALDERA (Apache-2.0), Stratus Red Team (Apache-2.0);
   - OTRF Security-Datasets (MIT), Splunk attack_data (Apache-2.0);
   - DARPA OpTC and Transparent Computing (public domain);
   - IoT-23 (CC BY 4.0), already used by the neuro programme.
5. **The legacy feed scripts fetched sources with no stated licence or restrictive terms.** In
   `hydra-feed-fetch.sh` (removed in #1396) and V1 `feed_sync.py` (removed in #1395): FireHOL (aggregator; per-source terms), ET
   compromised-ips, blocklist.de and CINS (no licence stated), and Spamhaus DROP (free in products
   with attribution, but revocable and silent on AI). A heqk `IOC.TXT` must not be compiled from them
   until the registry says so.
6. **Brief corrections:**
   - **CIRCL is Luxembourg's CERT, not Switzerland's.**
   - Microsoft SimuLand was archived on 2026-10-26; its last commit was 2023-03-09.
   - `mitre/caldera` now redirects to `apache/caldera`.
   - The Romanian NCC is run by ADR (Autoritatea pentru Digitalizarea României), not DNSC.
   - The ECCC is based in Bucharest, but its calls go through the EU Funding & Tenders Portal.

## 2. Academic and research datasets

| Verdict | Datasets |
|---|---|
| **Train now** (explicit open grant incl. commercial) | **UMUDGA** (MIT, Mendeley; >30M DGA names, 50 families) · **360netlab DGA code** (MIT: generate DGA names locally) · **IoT-23** (CC BY 4.0) · **CTU-13** (CC BY) · **Kitsune** (CC BY 4.0) · **LANL 2015 multi-source** (CC0; includes DNS lookups + red-team labels) · **LANL 2017 unified host/network** (CC0) · **PhiUSIIL phishing URLs** (CC BY 4.0) |
| **After one e-mail to UNB CIC** | CIRA-CIC-DoHBrw-2020, CIC-Bell-DNS-2021, CIC-Bell-DNS-EXF-2021, CICIoT2023 |
| **Commercial use needs the authors' agreement** | UNSW-NB15, Bot-IoT, TON_IoT ("should be agreed by the authors" / "allowable after asking"). The restriction carries into derivatives (UQ NF-* NetFlow sets) |
| **Research or evaluation only** | MAWI/WIDE ("only research purposes"), MAWILab (discontinued Dec 2024), CAIDA (AUA: non-profit research or internal commercial evaluation, no redistribution), DGArchive (CC BY-NC-SA 3.0), CTIBench (CC BY-NC-SA 4.0), Tu et al. 2023 DNS-tunnelling PCAPs (no LICENSE: all rights reserved) |
| **Unknown** | BCCC (York) relabels (request form, no licence shown), UGR'16 (site 403), CSIC 2010 (unreachable), AWID3 ("All Rights Reserved", request form), Cisco Umbrella top-1M (no licence), Tranco (see §1) |

**UNB CIC terms.**
- Each dataset page says the data may be redistributed, republished and mirrored "in any form", with a
  mandatory citation. The CIC FAQ gives the same answer to a question about commercial use by
  companies.
- That is permissive, but it is not a named licence and not an explicit training grant.
- CIC-IDS2017's own page says only "publicly available for researchers".
- All CIC sets are classed RESEARCH / `unclear`. A written confirmation from CIC would very likely make
  the four DNS/DoH/IoT sets usable.

**Label quality.**
- Never use the original CIC-IDS2017/2018 CSVs. Use the DistriNet corrected releases (WTMC 2021 /
  CNS 2022), with "Attempted" flows merged rather than used as a class, or BCCC-CSE-CIC-IDS2018.
- BCCC-DoHBrw is SMOTE-balanced, so it must not be used for test splits.
- No download location was found for the Lanvin et al. 2022 corrections.

**Licence laundering.**
- Kaggle re-uploads show their own licence field:

  | Kaggle copy | Field shown |
  |---|---|
  | CIC-IDS2017 | CC0, or CC BY-NC-SA 4.0, depending on the uploader |
  | CSE-CIC-IDS2018 | CC BY 4.0 |
  | UNSW-NB15 | Unknown |

  None of these overrides the owner's terms.
- Hugging Face instruction sets labelled Apache-2.0 (Trendyol, Fenrir, CyberMetric) are LLM-generated
  from undisclosed sources, so their provenance cannot be audited.
- `ealvaradob/phishing-dataset` relabels third-party data, including the Enron e-mails, as Apache-2.0;
  treated as UNKNOWN.
- **WitFoo Precinct6** (Apache-2.0) is rare: real, sanitised SOC data. Its card admits earlier
  versions leaked values, so run a PII scan before use.
- **The DNS Threats dataset** (Palau et al., CC BY 3.0 US) repackages Alexa and Bambenek lists. A CC
  grant cannot cover third-party content, so only its lab-generated tunnelling subset is clean.


## 3. DNS sources: what each is good for

| Need | Best candidate | Status for HookProbe |
|---|---|---|
| DGA positives | **UMUDGA** (MIT) via `domain_list` adapter; 360netlab DGA code (MIT) to generate | **acquired** (51 × 1000-name samples, sha256-checked) |
| Tunnelling / exfiltration | CIC-Bell-DNS-EXF-2021 (UNB CIC) | RESEARCH terms: evaluation for research only |
| Malicious hosts | URLhaus, ThreatFox | RESTRICTED (subscription + AI consent) |
| Botnet C2 IPs (live intel) | Feodo Tracker | ship as IOC pack: yes; train: needs consent |
| Benign baseline | Tranco | UNKNOWN: ask the Tranco authors for terms, or build our own from consented HookProbe deployments (aggregate, k-anonymous) |
| Phishing names + benign baseline | **PhiUSIIL** (CC BY 4.0, UCI; label 1 = legitimate, 0 = phishing) | **acquired**: 219,850 distinct domains; the benign half is the licence-clean baseline Tranco could not provide |
| Lookalike / brand | (none open) | generate from `dga.rs` BRANDS × substitution rules, marked synthetic |
| **Best route** | **HookProbe's own isolated-lab captures** of DNS tunnelling tools and DGA families re-implemented from published algorithms | owned data, no licence question, matches device telemetry |

## 4. Regional and collaboration findings

### Switzerland (priority in the brief)
- **BACS (Federal Office for Cybersecurity, formerly NCSC.ch / MELANI):** semi-annual reports (2026/1
  published 2026-08-24). No RSS or open machine-readable data was found.
- **GovCERT.ch** has a CTI GitHub repository with no stated licence; permission is needed for commercial
  reuse.
- **Switch-CERT** (.ch/.li registry) publishes abuse statistics but no public feed.
- **ETH, EPFL and the Cyber-Defence Campus:** no DNS dataset with a published licence was found. CYD
  Campus fellowships need a Swiss host.
- **Verdict:** Switzerland is a weak data route for a Romanian startup.

### Luxembourg (CIRCL, misattributed to Switzerland in the brief)
- **Open data:** hashlookup (CC BY, with an offline Bloom filter), CIRCL Open Data (CC BY 4.0: BGP
  Ranking, phishing screenshots, Hugging Face datasets), and Vulnerability-Lookup dumps (CC BY 4.0).
- **The MISP OSINT feed is TLP:CLEAR, but TLP is not a licence.** Ask info@circl.lu.
- **Passive DNS / passive SSL** are for trusted partners only.
- **Best route:** apply to CIRCL's MISP communities as a security vendor. They are free, and vendors
  are an explicit audience.

### EU
- **ENISA** Threat Landscape 2026 (CC BY 4.0) is reports only.
- **EUVD** (ENISA's vulnerability database) has public GET endpoints with no authentication; its data
  licence is not confirmed.
- **CERT-EU** advisories RSS is CC BY 4.0.
- **Funding:** ECCC call **DIGITAL-ECCC-2027-DEPLOY-CYBER-11** closes 14 Jan 2027.
  - The AI4SME topic is EUR 20M (75% funding for SMEs) and the CYBERAI topic is EUR 15M.
  - It needs a European consortium; NCC-RO (ncc-ro@gov.ro) helps with partner search.
- **NCC-RO SME calls:** EUR 60–100k per project. None was confirmed open on 2026-11-18.

### UK
- **CiSP and the NCSC's protective services** need a UK-registered entity.
- **NCSC reports and GitHub** are public.
- **Cambridge Cybercrime Centre** shares data only under institutional research agreements, with
  commercial use heavily restricted.
- **Verdict:** the UK is effectively out of reach without a UK subsidiary.

### Romania (priority)
- **DNSC** (the national CSIRT; it replaced CERT-RO under OUG 104/2021) publishes RSS alerts: Romanian
  campaign context, but not an IOC feed.
- **DNSC sharing:** no MISP community or self-service platform was found. The real route is a
  bilateral cooperation agreement; precedents are ENEVO Group (2025) and Nextgen Software.
- **ROTLD (.ro):** no public abuse feed. ICI București is a possible research partner.
- **Bitdefender:**
  - the `malware-ioc` GitHub repo has no licence, so ask Bitdefender Labs;
  - its Matter IoT benign-traffic dataset is CC BY 4.0, a rare open **benign IoT** baseline;
  - Voyager Ventures is a possible investor.
- **UPB** (Politehnica București), co-author of RoEduNet-SIMARGL2021 (licence unconfirmed), is the
  natural academic partner for joint ECCC proposals.
- **No public Romanian-language phishing dataset was found.** A multilingual Mendeley set is embargoed
  until December 2026, and it is unconfirmed whether it includes Romanian. A Romanian corpus would
  have to be built, e.g. from DNSC alerts plus consented HookProbe deployments.
- **Timing:** DefCamp 2026 runs 19–20 Nov in Bucharest, starting the day after this research. It is
  the place to meet DNSC, Bitdefender and UPB contacts.

### Cloud credits (for fine-tuning; modest needs per `HEQK-TRAINING-STRATEGY.md`)

| Programme | Offer |
|---|---|
| Microsoft for Startups | up to USD 150k Azure; USD 5k after business verification |
| AWS Activate Founders | USD 1k–5k |
| Google for Startups | USD 2k Start tier; USD 200k–350k for funded startups |
| Oracle | current EU offer unverified |

## 5. Recommended actions, in order

| # | Action | Unblocks |
|---|---|---|
| 1 | Write to Spamhaus / abuse.ch for written AI-training consent + a commercial redistribution subscription quote | collections 01, 04; live-intel breadth |
| 2 | Ask the Tranco authors (KU Leuven / imec-DistriNet) for terms of the research list, or for the Majestic/Umbrella-only variant | DNS benign baseline |
| 3 | Apply to CIRCL MISP communities as a security vendor; ask CIRCL about OSINT-feed reuse terms | MISP-format live intel; Luxembourg/EU network |
| 4 | Propose a DNSC cooperation agreement (DefCamp contact) | Romanian campaign intelligence |
| 5 | Approach UPB for a research partnership + joint ECCC CYBER-11 proposal (deadline 2027-01-14) | funding; RoEduNet-SIMARGL licence; lab capacity |
| 6 | Build the isolated attack/DNS lab (training strategy §4) | collections 01, 03 with owned, perfectly labelled data |
| 7 | ~~Register IoT-23~~ done: all 23 scenarios (the 12 multi-GB captures sampled per label at registration) | collection 02 |
