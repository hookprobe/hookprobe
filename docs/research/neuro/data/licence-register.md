# HEQK intel-data source and licence register

Generated read-only from `tools/intel-data/registry/` at origin/main dd83ea9c, on 2026-11-22. 205 sources. No downloads, no builds.

How to read it:
- **training / evaluation / live_intel** are the output of `licensing.decide()` for the purposes `commercial_training`, `evaluation` and `live_intel`, from the registry alone. *yes* means the gate allows it, *no* means it denies it.
- **redistribution** is the registry's licence field (`yes / no / unclear / requires_agreement`).
- **registry status** is the licence class: OPEN, RESEARCH, COMMERCIAL, RESTRICTED or UNKNOWN. UNKNOWN means the licence was not verified, and it is denied for everything. Two flags can follow the class:
  - *requires_agreement*: some right needs a signed agreement first.
  - *eval-only caveat*: evaluation is allowed only under the 2026-11-22 operator exception (commercial use unclear). Any build that uses such a source is marked `licence_caveats` and must never train or ship a model.
- **verified date** and **URL** come from the licence entry.
- The gate is per licence, not legal advice. 'unclear' counts as no, except for that evaluation exception.

## 1. Sources asked about by name

| source id | dataset / feed name | licence (SPDX or name) | training | evaluation | live_intel (ship on device) | redistribution | registry status | verified date | URL of the licence page |
|---|---|---|---|---|---|---|---|---|---|
| `abusech-feodotracker` | abuse.ch Feodo Tracker | CC0-1.0 | no | yes | yes | yes | OPEN / requires_agreement | 2026-11-18 | https://abuse.ch/terms-of-use/ |
| `abusech-malwarebazaar` | abuse.ch MalwareBazaar | abuse.ch Platforms Terms of Use (2025-11-04, updated 2026-10-21) | no | no | no | no | RESTRICTED / requires_agreement | 2026-11-18 | https://abuse.ch/terms-of-use/ |
| `abusech-sslbl` | abuse.ch SSL Blacklist (SSLBL) | CC0-1.0 | no | yes | yes | yes | OPEN / requires_agreement | 2026-11-18 | https://abuse.ch/terms-of-use/ |
| `abusech-threatfox` | abuse.ch ThreatFox | abuse.ch Platforms Terms of Use (2025-11-04, updated 2026-10-21) | no | no | no | no | RESTRICTED / requires_agreement | 2026-11-18 | https://abuse.ch/terms-of-use/ |
| `abusech-urlhaus` | abuse.ch URLhaus | abuse.ch Platforms Terms of Use (2025-11-04, updated 2026-10-21) | no | no | no | no | RESTRICTED / requires_agreement | 2026-11-18 | https://abuse.ch/terms-of-use/ |
| `abusech-yaraify` | abuse.ch YARAify | CC0-1.0 | no | yes | yes | yes | OPEN / requires_agreement | 2026-11-18 | https://abuse.ch/terms-of-use/ |
| `mitre-emb3d` | MITRE EMB3D (embedded device threat model) | MITRE EMB3D Terms of Use | no | no | no | requires_agreement | RESTRICTED / requires_agreement | 2026-11-21 | https://emb3d.mitre.org/subtabs/terms-of-use.html |
| `alienvault-otx` | LevelBlue (AlienVault) Open Threat Exchange (OTX) | OTX End User License Agreement | no | no | no | no | RESTRICTED | 2026-11-18 | https://levelblue.com/terms/otx-eula |
| `aptnotes` | APTnotes | None stated (links to third-party vendor reports) | no | no | no | no | UNKNOWN | 2026-11-21 | — |
| `dfir-report` | The DFIR Report (intrusion reports) | All rights reserved | no | no | no | no | RESTRICTED | 2026-11-21 | https://thedfirreport.com/ |
| `dfir-report-rules` | The DFIR Report Sigma / YARA / Suricata rules | GPL-3.0-or-later | no | yes | yes | yes | OPEN | 2026-11-21 | https://github.com/The-DFIR-Report/Sigma-Rules |
| `unit42-timely-threat-intel` | Palo Alto Networks Unit 42 timely threat intel (IOC repo) | GPL-3.0-only | no | yes | yes | yes | OPEN | 2026-11-18 | https://www.gnu.org/licenses/gpl-3.0.html |
| `vx-underground-papers` | vx-underground papers and APT report archive | None found (site returned 403; archived papers are third-party works) | no | no | no | unclear | UNKNOWN | 2026-11-21 | https://vx-underground.org/ |
| `secqa` | SecQA | CC-BY-NC-SA-4.0 | no | no | no | yes | RESEARCH | 2026-11-21 | https://creativecommons.org/licenses/by-nc-sa/4.0/ |
| `trendmicro-primus` | Trend Micro Primus datasets (FineWeb, Seed, Instruct, Reasoning) | ODC-By-1.0 | no | no | no | unclear | UNKNOWN | 2026-11-21 | https://huggingface.co/datasets/trendmicro-ailab/Primus-FineWeb |
| `hf-cybermetric` | CyberMetric | Apache-2.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://www.apache.org/licenses/LICENSE-2.0 |
| `cesnet-datazoo` | CESNET DataZoo traffic datasets (CESNET-TLS-Year22, CESNET-QUIC22, CESNET-TLS22) | CC-BY-4.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/licenses/by/4.0/ |
| `kitsune-network-attack` | Kitsune Network Attack Dataset | CC-BY-4.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/licenses/by/4.0/ |
| `ember-2017-2018` | EMBER 2017/2018 PE feature dataset | MIT | yes | yes | yes | yes | OPEN | 2026-11-18 | https://opensource.org/license/mit |
| `ember2024` | EMBER2024 multi-format malware feature dataset | Apache-2.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://www.apache.org/licenses/LICENSE-2.0 |
| `iot-23 (sealed: split:test@neuro-sha256-mod3)` | IoT-23 (Aposemat) | CC-BY-4.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/licenses/by/4.0/ |
| `ctu-13 (sealed: split:test@neuro-sha256-mod3)` | CTU-13 botnet dataset | Creative Commons CC-BY (page links CC BY 2.0) | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/licenses/by/2.0/ |

Some sources the licence gate allows were still left out by choice, not because of their licence:
- CESNET DataZoo: dropped by Neuro on 2026-11-21. It is QUIC-only benign traffic, and its addresses may not be anonymised, so it would need a privacy review.
- Kitsune and EMBER: judged not a fit for Neuro's tasks.
- abuse.ch CC0 feeds (Feodo Tracker, SSLBL, YARAify): CC0, but abuse.ch Platforms Terms §7.3 forbids AI training without Spamhaus' written consent. So training is *no*, while evaluation and on-device shipping are *yes*. Neuro's rule is that abuse.ch values may appear only at inference.
- IoT-23 and CTU-13: their *test* splits are sealed (Neuro holdouts). The licence allows them, but they must never be trained on.

### Not in the registry

| dataset | status |
|---|---|
| UNSW-IoTraffic | **Verified 2026-11-22 (intel-data #1462): CC0-1.0**, row `unsw-iotraffic`: training yes, evaluation yes, live_intel yes, redistribution yes, OPEN; licence page https://creativecommons.org/publicdomain/zero/1.0/ (Dryad doi:10.5061/dryad.w0vt4b94b). Caveats: PCAPs carry payloads from lab devices (Neuro uses anonymised windows only); lab testbed. Citation requested by the README: IEEE Data Descriptions paper (Aug 2025). |
| Deakin IoT Traffic v2 (Figshare 28013234 v2) | **Sealed holdout** (`registry/sealed.json`, scope `*`), deliberately unopened, no registry entry. Neuro doc 18 states CC BY 4.0. intel-data has NOT verified that licence. |

## 2. CIC tier (eval-only caveat unless stated)

| source id | dataset / feed name | licence (SPDX or name) | training | evaluation | live_intel (ship on device) | redistribution | registry status | verified date | URL of the licence page |
|---|---|---|---|---|---|---|---|---|---|
| `bccc-cic-bell-dns-2024` | BCCC-CIC-Bell-DNS-2024 | None stated on the BCCC page | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `bccc-cic-ids2017` | BCCC-CIC-IDS2017 | None stated on the BCCC page | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `bccc-cira-cic-dohbrw-2020` | BCCC-CIRA-CIC-DoHBrw-2020 (balanced) | None stated on the BCCC page | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `bccc-cse-cic-ids2018` | BCCC-CSE-CIC-IDS2018 (Large-Scale Intrusion Detection Dataset) | None stated on the BCCC page | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `cic-bell-dns-2021` | CIC-Bell-DNS-2021 | UNB CIC dataset terms (custom, no named licence): 'You may redistribute, republish, and mirror the CIC-Bell-DNS2021 dataset in any form...' with citation | no | yes | no | yes | RESEARCH / eval-only caveat | 2026-11-18 | https://www.unb.ca/cic/datasets/dns-2021.html |
| `cic-bell-dns-exf-2021` | CIC-Bell-DNS-EXF-2021 | UNB CIC dataset terms (custom, no named licence): 'You may redistribute, republish, and mirror the CIC-Bell-DNS-EXF-2021 dataset in any form...' with citation | no | yes | no | yes | RESEARCH / eval-only caveat | 2026-11-18 | https://www.unb.ca/cic/datasets/dns-exf-2021.html |
| `cic-ddos2019` | CIC-DDoS2019 | UNB CIC dataset terms (custom, no named licence): 'You may redistribute, republish and mirror the CICDDoS2019 dataset in any form. However, any use or redistribution of the data must include a citati… | no | yes | no | yes | RESEARCH / eval-only caveat | 2026-11-18 | https://www.unb.ca/cic/datasets/ddos-2019.html |
| `cic-ids2017` | CIC-IDS2017 (Intrusion Detection Evaluation Dataset) | UNB CIC dataset terms (custom, no named licence) | no | yes | no | yes | RESEARCH / eval-only caveat | 2026-11-18 | https://www.unb.ca/cic/datasets/index.html |
| `ciciot2023` | CICIoT2023 | UNB CIC dataset terms (custom, no named licence) (no licence note on the dataset page; FAQ applies) | no | yes | no | yes | RESEARCH / eval-only caveat | 2026-11-18 | https://www.unb.ca/cic/datasets/index.html |
| `cira-cic-dohbrw-2020` | CIRA-CIC-DoHBrw-2020 | UNB CIC dataset terms (custom, no named licence): 'You may redistribute, republish, and mirror the CIRA-CIC-DoHBrw-2020 dataset in any form...' with citation of DoHMeter and the paper | no | yes | no | yes | RESEARCH / eval-only caveat | 2026-11-18 | https://www.unb.ca/cic/datasets/dohbrw-2020.html |
| `cse-cic-ids2018` | CSE-CIC-IDS2018 (IPS/IDS dataset on AWS) | UNB CIC dataset terms (custom, no named licence): 'You may redistribute, republish, and mirror the CSE-CIC-IDS2018 dataset in any form. However, any use or redistribution of the data must include a c… | no | yes | no | yes | RESEARCH / eval-only caveat | 2026-11-18 | https://www.unb.ca/cic/datasets/ids-2018.html |
| `distrinet-cic-ids-2017-2018-improved` | Improved CIC-IDS2017 and CSE-CIC-IDS2018 (WTMC2021 / CNS2022 relabels) | None stated (derived from UNB CIC data; CIC terms apply) | no | yes | no | unclear | RESEARCH / eval-only caveat | 2026-11-18 | https://www.unb.ca/cic/datasets/index.html |
| `iscx-url2016` | ISCX-URL2016 | UNB CIC dataset terms (custom, no named licence) (no licence note on the page; FAQ applies) | no | yes | no | unclear | RESEARCH / eval-only caveat | 2026-11-18 | https://www.unb.ca/cic/datasets/index.html |

## 3. Every source in the registry (205)

| source id | dataset / feed name | licence (SPDX or name) | training | evaluation | live_intel (ship on device) | redistribution | registry status | verified date | URL of the licence page |
|---|---|---|---|---|---|---|---|---|---|
| `abusech-feodotracker` | abuse.ch Feodo Tracker | CC0-1.0 | no | yes | yes | yes | OPEN / requires_agreement | 2026-11-18 | https://abuse.ch/terms-of-use/ |
| `abusech-malwarebazaar` | abuse.ch MalwareBazaar | abuse.ch Platforms Terms of Use (2025-11-04, updated 2026-10-21) | no | no | no | no | RESTRICTED / requires_agreement | 2026-11-18 | https://abuse.ch/terms-of-use/ |
| `abusech-sslbl` | abuse.ch SSL Blacklist (SSLBL) | CC0-1.0 | no | yes | yes | yes | OPEN / requires_agreement | 2026-11-18 | https://abuse.ch/terms-of-use/ |
| `abusech-threatfox` | abuse.ch ThreatFox | abuse.ch Platforms Terms of Use (2025-11-04, updated 2026-10-21) | no | no | no | no | RESTRICTED / requires_agreement | 2026-11-18 | https://abuse.ch/terms-of-use/ |
| `abusech-urlhaus` | abuse.ch URLhaus | abuse.ch Platforms Terms of Use (2025-11-04, updated 2026-10-21) | no | no | no | no | RESTRICTED / requires_agreement | 2026-11-18 | https://abuse.ch/terms-of-use/ |
| `abusech-yaraify` | abuse.ch YARAify | CC0-1.0 | no | yes | yes | yes | OPEN / requires_agreement | 2026-11-18 | https://abuse.ch/terms-of-use/ |
| `alienvault-otx` | LevelBlue (AlienVault) Open Threat Exchange (OTX) | OTX End User License Agreement | no | no | no | no | RESTRICTED | 2026-11-18 | https://levelblue.com/terms/otx-eula |
| `aptnotes` | APTnotes | None stated (links to third-party vendor reports) | no | no | no | no | UNKNOWN | 2026-11-21 | — |
| `atomic-red-team` | Atomic Red Team | MIT | yes | yes | yes | yes | OPEN | 2026-11-18 | https://opensource.org/license/mit |
| `awid3` | AWID3 (Aegean Wi-Fi Intrusion Dataset v3) | None stated (copyright 'All Rights Reserved', Info-Sec-Lab) | no | no | no | unclear | RESTRICTED | 2026-11-18 | — |
| `bccc-cic-bell-dns-2024` | BCCC-CIC-Bell-DNS-2024 | None stated on the BCCC page | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `bccc-cic-ids2017` | BCCC-CIC-IDS2017 | None stated on the BCCC page | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `bccc-cira-cic-dohbrw-2020` | BCCC-CIRA-CIC-DoHBrw-2020 (balanced) | None stated on the BCCC page | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `bccc-cse-cic-ids2018` | BCCC-CSE-CIC-IDS2018 (Large-Scale Intrusion Detection Dataset) | None stated on the BCCC page | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `blocklist-de` | blocklist.de attacker lists | No licence stated ('as they are, and to be used at your own risk') | no | no | no | unclear | UNKNOWN | 2026-11-18 | https://www.blocklist.de/en/export.html |
| `bot-iot` | Bot-IoT | UNSW custom terms: 'Free use of the Bot-IoT dataset for academic research purposes is hereby granted in perpetuity. Use for commercial purposes should be agreed by the authors.' | no | no | no | unclear | RESEARCH / requires_agreement | 2026-11-18 | https://research.unsw.edu.au/projects/bot-iot-dataset |
| `caida-anonymized-passive-traces` | CAIDA Anonymized Internet Traces (passive_dataset) | CAIDA Acceptable Use Agreement (Master AUA for restricted datasets; Public AUA for public ones) | no | no | no | no | RESTRICTED / requires_agreement | 2026-11-18 | https://www.caida.org/about/legal/aua/ |
| `certfr-avis-alertes-ioc` | CERT-FR advisories, alerts, CTI reports and IoC feeds | etalab-2.0 | yes | yes | yes | yes | OPEN | 2026-11-21 | https://cert.cyber.gouv.fr/mentions-legales/ |
| `cesnet-datazoo` | CESNET DataZoo traffic datasets (CESNET-TLS-Year22, CESNET-QUIC22, CESNET-TLS22) | CC-BY-4.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/licenses/by/4.0/ |
| `ch-academic-datasets` | Swiss academic security datasets (ETH Zurich, EPFL) | terms not identified | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `ch-bacs-semiannual-reports` | BACS / NCSC Semi-Annual Reports (Halbjahresbericht) | Swiss federal administration terms (not checked) | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `ch-cyd-campus-fellowships` | CYD Campus Fellowships and Proof-of-Concept Fellowships | terms not identified | no | no | no | unclear | RESTRICTED | 2026-11-18 | — |
| `ch-govcert-cti-github` | GovCERT.ch CTI repository (IOC lists and reports) | None stated (TLP:CLEAR, 'as is', no warranty); credits Team Cymru for AS/geo data | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `ch-switch-abuse-handling` | Switch .ch/.li malware and phishing domain handling | terms not identified | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `ch-switch-cert-report` | Switch-CERT Report / registry takedown statistics | terms not identified | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `cic-bell-dns-2021` | CIC-Bell-DNS-2021 | UNB CIC dataset terms (custom, no named licence): 'You may redistribute, republish, and mirror the CIC-Bell-DNS2021 dataset in any form...' with citation | no | yes | no | yes | RESEARCH / eval-only caveat | 2026-11-18 | https://www.unb.ca/cic/datasets/dns-2021.html |
| `cic-bell-dns-exf-2021` | CIC-Bell-DNS-EXF-2021 | UNB CIC dataset terms (custom, no named licence): 'You may redistribute, republish, and mirror the CIC-Bell-DNS-EXF-2021 dataset in any form...' with citation | no | yes | no | yes | RESEARCH / eval-only caveat | 2026-11-18 | https://www.unb.ca/cic/datasets/dns-exf-2021.html |
| `cic-ddos2019` | CIC-DDoS2019 | UNB CIC dataset terms (custom, no named licence): 'You may redistribute, republish and mirror the CICDDoS2019 dataset in any form. However, any use or redistribution of the data must include a citati… | no | yes | no | yes | RESEARCH / eval-only caveat | 2026-11-18 | https://www.unb.ca/cic/datasets/ddos-2019.html |
| `cic-ids2017` | CIC-IDS2017 (Intrusion Detection Evaluation Dataset) | UNB CIC dataset terms (custom, no named licence) | no | yes | no | yes | RESEARCH / eval-only caveat | 2026-11-18 | https://www.unb.ca/cic/datasets/index.html |
| `ciciot2023` | CICIoT2023 | UNB CIC dataset terms (custom, no named licence) (no licence note on the dataset page; FAQ applies) | no | yes | no | yes | RESEARCH / eval-only caveat | 2026-11-18 | https://www.unb.ca/cic/datasets/index.html |
| `cins-army` | CINS Army list (ci-badguys) | No formal licence ('parse and use in any way you see fit') | no | no | no | unclear | UNKNOWN | 2026-11-18 | https://cinsscore.com/ |
| `cira-cic-dohbrw-2020` | CIRA-CIC-DoHBrw-2020 | UNB CIC dataset terms (custom, no named licence): 'You may redistribute, republish, and mirror the CIRA-CIC-DoHBrw-2020 dataset in any form...' with citation of DoHMeter and the paper | no | yes | no | yes | RESEARCH / eval-only caveat | 2026-11-18 | https://www.unb.ca/cic/datasets/dohbrw-2020.html |
| `cisa-csaf-advisories` | CISA CSAF advisories (ICS / IT) | none stated | no | no | no | unclear | UNKNOWN | 2026-11-21 | — |
| `cisa-kev` | CISA Known Exploited Vulnerabilities Catalog | CC0-1.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/publicdomain/zero/1.0/ |
| `cisa-vulnrichment` | CISA Vulnrichment | CC0-1.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/publicdomain/zero/1.0/ |
| `cisco-umbrella-top1m` | Cisco Umbrella Popularity List (top 1M) | None stated (page footer '© Cisco Umbrella, 2016'). Tranco describes it as 'available free of charge'. | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `cloudflare-radar` | Cloudflare Radar API | CC-BY-NC-4.0 | no | no | no | no | RESEARCH | 2026-11-18 | https://creativecommons.org/licenses/by-nc/4.0/ |
| `crowdstrike-falcon-intel` | CrowdStrike Falcon Intelligence | CrowdStrike commercial terms | no | no | no | no | COMMERCIAL / requires_agreement | 2026-11-18 | https://www.crowdstrike.com/ |
| `cse-cic-ids2018` | CSE-CIC-IDS2018 (IPS/IDS dataset on AWS) | UNB CIC dataset terms (custom, no named licence): 'You may redistribute, republish, and mirror the CSE-CIC-IDS2018 dataset in any form. However, any use or redistribution of the data must include a c… | no | yes | no | yes | RESEARCH / eval-only caveat | 2026-11-18 | https://www.unb.ca/cic/datasets/ids-2018.html |
| `csic-2010-http` | HTTP DATASET CSIC 2010 | terms not identified | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `ctu-13 (sealed: split:test@neuro-sha256-mod3)` | CTU-13 botnet dataset | Creative Commons CC-BY (page links CC BY 2.0) | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/licenses/by/2.0/ |
| `cve-list-v5` | CVE List (CVE JSON 5.x records) | CVE Program Terms of Use (cve-tou) | yes | yes | yes | yes | OPEN | 2026-11-18 | https://www.cve.org/Legal/TermsOfUse |
| `darpa-optc` | DARPA OpTC (Operationally Transparent Cyber) | Public domain (DARPA release, Distribution A) | yes | yes | yes | yes | OPEN | 2026-11-18 | https://github.com/FiveDirections/OpTC-data |
| `darpa-transparent-computing` | DARPA Transparent Computing (E3/E5) | Public domain (DARPA release) | yes | yes | yes | yes | OPEN | 2026-11-18 | https://github.com/darpa-i2o/Transparent-Computing |
| `de-bsi-certbund-csaf` | BSI CERT-Bund WID CSAF advisories | none stated | no | no | no | unclear | UNKNOWN | 2026-11-21 | — |
| `dfir-report` | The DFIR Report (intrusion reports) | All rights reserved | no | no | no | no | RESTRICTED | 2026-11-21 | https://thedfirreport.com/ |
| `dfir-report-rules` | The DFIR Report Sigma / YARA / Suricata rules | GPL-3.0-or-later | no | yes | yes | yes | OPEN | 2026-11-21 | https://github.com/The-DFIR-Report/Sigma-Rules |
| `dgarchive` | DGArchive | CC BY-NC-SA 3.0 (DGArchive Terms of Service) | no | no | no | no | RESEARCH / requires_agreement | 2026-11-18 | http://creativecommons.org/licenses/by-nc-sa/3.0/ |
| `digitalside-threat-intel` | DigitalSide Threat-Intel | MIT | yes | yes | yes | yes | OPEN | 2026-11-18 | https://opensource.org/license/mit |
| `distrinet-cic-ids-2017-2018-improved` | Improved CIC-IDS2017 and CSE-CIC-IDS2018 (WTMC2021 / CNS2022 relabels) | None stated (derived from UNB CIC data; CIC terms apply) | no | yes | no | unclear | RESEARCH / eval-only caveat | 2026-11-18 | https://www.unb.ca/cic/datasets/index.html |
| `dns-threats-palau-2019` | DNS Threats Dataset (normal / DGA / tunnelling domains) | Creative Commons Attribution 3.0 United States (Zenodo) | no | no | no | yes | UNKNOWN | 2026-11-18 | https://creativecommons.org/licenses/by/3.0/us/ |
| `dshield-isc` | SANS ISC / DShield data and API | CC BY-NC-SA 4.0 (with site statement allowing commercial use to protect own network, no resale) | no | no | no | no | RESEARCH | 2026-11-18 | https://creativecommons.org/licenses/by-nc-sa/4.0/ |
| `dvwa` | Damn Vulnerable Web Application (DVWA) | GPL-3.0-only | no | yes | yes | yes | OPEN | 2026-11-18 | https://www.gnu.org/licenses/gpl-3.0.html |
| `elastic-protections-artifacts` | Elastic protections-artifacts (YARA and behaviour rules) | Elastic-2.0 | no | no | no | yes | RESTRICTED | 2026-11-21 | https://www.elastic.co/licensing/elastic-license |
| `ember-2017-2018` | EMBER 2017/2018 PE feature dataset | MIT | yes | yes | yes | yes | OPEN | 2026-11-18 | https://opensource.org/license/mit |
| `ember2024` | EMBER2024 multi-format malware feature dataset | Apache-2.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://www.apache.org/licenses/LICENSE-2.0 |
| `eset-malware-ioc` | ESET malware-ioc | BSD-2-Clause | yes | yes | yes | yes | OPEN | 2026-11-21 | https://opensource.org/licenses/BSD-2-Clause |
| `et-compromised-ips` | Emerging Threats compromised-ips / block rules | Unclear (question raised on ET community forum; answer not read) | no | no | no | unclear | UNKNOWN | 2026-11-18 | https://community.emergingthreats.net/t/licensing-is-the-compromised-ips-list-also-open/676 |
| `et-open` | Proofpoint Emerging Threats Open ruleset | Mixed: BSD (most ET-authored SIDs) and GPLv2 (some SID ranges) | no | yes | yes | yes | OPEN | 2026-11-18 | https://rules.emergingthreats.net/ |
| `et-pro` | Proofpoint ET Pro ruleset | Proofpoint commercial licence | no | no | no | no | COMMERCIAL / requires_agreement | 2026-11-18 | https://www.proofpoint.com/us/products/et-pro-ruleset |
| `eu-cert-eu-advisories` | CERT-EU Security Advisories | CC-BY-4.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/licenses/by/4.0/ |
| `eu-cert-eu-threat-intel` | CERT-EU Cyber Briefs and Threat Landscape Report | CC-BY-4.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/licenses/by/4.0/ |
| `eu-cybersecurity-atlas` | EU Cybersecurity Atlas | terms not identified | no | no | no | unclear | RESTRICTED | 2026-11-18 | — |
| `eu-cyssde-cascade` | CYSSDE cascade open calls (pentest/vulnerability assessment) | terms not identified | no | no | no | unclear | RESTRICTED | 2026-11-18 | — |
| `eu-eccc-dep-call-11` | ECCC Digital Europe call DIGITAL-ECCC-2027-DEPLOY-CYBER-11 (AI4SME, CYBERAI) | terms not identified | no | no | no | unclear | RESTRICTED | 2026-11-18 | — |
| `eu-ecso-membership` | ECSO membership | terms not identified | no | no | no | unclear | RESTRICTED | 2026-11-18 | — |
| `eu-enisa-euvd` | European Union Vulnerability Database (EUVD) | Not confirmed (ENISA content generally CC BY 4.0) | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `eu-enisa-threat-landscape` | ENISA Threat Landscape 2026 | CC-BY-4.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/licenses/by/4.0/ |
| `evtx-attack-samples` | EVTX-ATTACK-SAMPLES | GPL-3.0-only | no | yes | yes | yes | OPEN | 2026-11-18 | https://www.gnu.org/licenses/gpl-3.0.html |
| `exploit-db` | Exploit Database (Exploit-DB) | GPL-2.0-or-later | no | yes | yes | yes | OPEN | 2026-11-18 | https://www.gnu.org/licenses/old-licenses/gpl-2.0.html |
| `firehol-blocklist-ipsets` | FireHOL IP lists (blocklist-ipsets) | No repo licence; per-source licences apply | no | no | no | unclear | UNKNOWN | 2026-11-18 | https://github.com/firehol/blocklist-ipsets |
| `first-cvss-spec` | CVSS v4.0 / v3.1 Specification | FIRST CVSS terms (free public use with conditions) | yes | yes | yes | yes | OPEN | 2026-11-18 | https://www.first.org/cvss/v4.0/specification-document |
| `first-epss` | EPSS - Exploit Prediction Scoring System | No explicit data licence; FIRST states scores are free, attribution requested | no | no | no | unclear | UNKNOWN | 2026-11-18 | https://www.first.org/epss/faq |
| `github-advisory-db` | GitHub Advisory Database | CC-BY-4.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/licenses/by/4.0/ |
| `gitlab-advisories-community` | GitLab Advisory Database (Open Source Edition) | MIT | yes | yes | yes | yes | OPEN | 2026-11-18 | https://opensource.org/license/mit |
| `golang-vulndb` | Go Vulnerability Database | CC-BY-4.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/licenses/by/4.0/ |
| `google-threat-intel-virustotal` | Google Threat Intelligence / VirusTotal (Mandiant) | VirusTotal Terms of Service / Google Threat Intelligence commercial terms | no | no | no | no | COMMERCIAL / requires_agreement | 2026-11-18 | https://docs.virustotal.com/docs/terms-of-service |
| `greynoise-community` | GreyNoise Community API | GreyNoise Terms (proprietary) | no | no | no | no | COMMERCIAL | 2026-11-18 | https://www.greynoise.io/terms |
| `gtfobins` | GTFOBins | GPL-3.0-only | no | yes | yes | yes | OPEN | 2026-11-18 | https://www.gnu.org/licenses/gpl-3.0.html |
| `hf-all-cve-records` | All-CVE-Records-Training-Dataset (CVE chat-style 1999-2025) | Apache-2.0 (card). Upstream: CVE content under the CVE Terms of Use | yes | yes | yes | yes | OPEN | 2026-11-18 | https://www.apache.org/licenses/LICENSE-2.0 |
| `hf-cti-bench` | CTIBench | CC BY-NC-SA 4.0 | no | no | no | yes | RESEARCH | 2026-11-18 | https://creativecommons.org/licenses/by-nc-sa/4.0/ |
| `hf-cybermetric` | CyberMetric | Apache-2.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://www.apache.org/licenses/LICENSE-2.0 |
| `hf-ealvaradob-phishing` | ealvaradob/phishing-dataset (combined URLs, emails, SMS, HTML) | Apache-2.0 (card). Upstream Kaggle and Mendeley sources have their own licences | no | no | no | unclear | UNKNOWN | 2026-11-18 | https://www.apache.org/licenses/LICENSE-2.0 |
| `hf-fenrir-v2-1` | Cybersecurity-Dataset-Fenrir v2.1 | Apache-2.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://www.apache.org/licenses/LICENSE-2.0 |
| `hf-nist-cybersecurity-training` | NIST Cybersecurity Training Dataset v1.1 | CC0-1.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/publicdomain/zero/1.0/ |
| `hf-trendyol-cybersecurity-instruct` | Trendyol Cybersecurity Defense Instruction-Tuning Dataset v2.0 | Apache-2.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://www.apache.org/licenses/LICENSE-2.0 |
| `hf-witfoo-precinct6` | WitFoo Precinct6 Cybersecurity Dataset v2.1.0 | Apache-2.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://www.apache.org/licenses/LICENSE-2.0 |
| `hookprobe-synthetic-soc` | HookProbe synthetic SOC triage templates | AGPL-3.0-only | yes | yes | yes | yes | OPEN | 2026-11-18 | https://www.gnu.org/licenses/agpl-3.0.html |
| `infection-monkey` | Infection Monkey | GPL-3.0-only | no | yes | yes | yes | OPEN | 2026-11-18 | https://www.gnu.org/licenses/gpl-3.0.html |
| `inquest-yara-rules` | InQuest YARA rules | MIT | no | yes | yes | yes | OPEN | 2026-11-21 | https://github.com/InQuest/yara-rules |
| `int-apwg-ecx` | APWG eCrime eXchange (eCX) | APWG Data Sharing Agreement | no | no | no | no | RESTRICTED / requires_agreement | 2026-11-18 | — |
| `int-aws-activate` | AWS Activate | terms not identified | no | yes | no | unclear | COMMERCIAL / eval-only caveat | 2026-11-18 | — |
| `int-first-membership` | FIRST membership | terms not identified | no | no | no | unclear | RESTRICTED | 2026-11-18 | — |
| `int-google-for-startups` | Google for Startups Cloud Program | terms not identified | no | yes | no | unclear | COMMERCIAL / eval-only caveat | 2026-11-18 | — |
| `int-microsoft-for-startups` | Microsoft for Startups (Azure credits) | terms not identified | no | yes | no | unclear | COMMERCIAL / eval-only caveat | 2026-11-18 | — |
| `int-oracle-for-startups` | Oracle for Startups | terms not identified | no | yes | no | unclear | COMMERCIAL / eval-only caveat | 2026-11-18 | — |
| `int-shadowserver-reports` | Shadowserver network reports and public dashboard | Shadowserver terms (reports restricted to own network space) | no | no | no | no | RESTRICTED / requires_agreement | 2026-11-18 | — |
| `iot-23 (sealed: split:test@neuro-sha256-mod3)` | IoT-23 (Aposemat) | CC-BY-4.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/licenses/by/4.0/ |
| `ipinfo-lite` | IPinfo Lite | CC-BY-SA-4.0 | no | yes | yes | yes | OPEN | 2026-11-21 | https://ipinfo.io/lite |
| `ipsum-stamparm` | IPsum threat-IP aggregate | Unlicense | no | no | no | yes | UNKNOWN | 2026-11-21 | https://unlicense.org/ |
| `iptoasn` | IPtoASN database | PDDL-1.0 | yes | yes | yes | yes | OPEN | 2026-11-21 | https://opendatacommons.org/licenses/pddl/1-0/ |
| `iscx-url2016` | ISCX-URL2016 | UNB CIC dataset terms (custom, no named licence) (no licence note on the page; FAQ applies) | no | yes | no | unclear | RESEARCH / eval-only caveat | 2026-11-18 | https://www.unb.ca/cic/datasets/index.html |
| `jp-jvn-ipedia-myjvn` | JVN iPedia / MyJVN API | MyJVN service-related tools terms of use (Japanese, 2023-03-29) | no | no | no | unclear | UNKNOWN | 2026-11-21 | https://jvndb.jvn.jp/apis/myjvn//document/termsofuse.pdf |
| `kitsune-network-attack` | Kitsune Network Attack Dataset | CC-BY-4.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/licenses/by/4.0/ |
| `lanl-comprehensive-multisource-2015` | LANL Comprehensive, Multi-Source Cyber-Security Events (2015) | CC0-1.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/publicdomain/zero/1.0/ |
| `lanl-unified-host-network-2017` | LANL Unified Host and Network Dataset (2017) | CC0-1.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/publicdomain/zero/1.0/ |
| `lolbas` | LOLBAS | GPL-3.0-only | no | yes | yes | yes | OPEN | 2026-11-18 | https://www.gnu.org/licenses/gpl-3.0.html |
| `lu-circl-ail-framework` | AIL framework (Analysis of Information Leaks) | AGPL-3.0 | no | yes | yes | yes | OPEN | 2026-11-18 | https://www.gnu.org/licenses/agpl-3.0.html |
| `lu-circl-hashlookup` | CIRCL hashlookup | CC BY (commercial and non-commercial use allowed) | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/licenses/by/4.0/ |
| `lu-circl-misp-communities` | CIRCL MISP communities (private sector / partners) | terms not identified | no | no | no | no | RESTRICTED / requires_agreement | 2026-11-18 | — |
| `lu-circl-misp-osint-feed` | CIRCL OSINT Feed (MISP default feed) | None stated; classified TLP:WHITE/TLP:CLEAR | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `lu-circl-opendata` | CIRCL Open Data (phishing screenshots, BGP Ranking, AIL screenshots, Hugging Face datasets) | CC-BY-4.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/licenses/by/4.0/ |
| `lu-circl-passive-dns` | CIRCL Passive DNS | terms not identified | no | no | no | no | RESTRICTED / requires_agreement | 2026-11-18 | — |
| `lu-circl-passive-ssl` | CIRCL Passive SSL | terms not identified | no | no | no | no | RESTRICTED / requires_agreement | 2026-11-18 | — |
| `lu-circl-vulnerability-lookup` | Vulnerability-Lookup (vulnerability.circl.lu) | Data: CC BY 4.0 per CIRCL Open Data page (unless resource states otherwise); software AGPL-3.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/licenses/by/4.0/ |
| `malpedia` | Malpedia | CC BY-NC-SA 3.0 (public content) | no | no | no | yes | RESEARCH / requires_agreement | 2026-11-21 | https://malpedia.caad.fkie.fraunhofer.de/usage/tos |
| `maltrail-trails` | Maltrail static trails | MIT | no | no | no | yes | UNKNOWN | 2026-11-21 | https://opensource.org/licenses/MIT |
| `mawi-wide` | MAWI Working Group Traffic Archive (WIDE backbone) | WIDE usage terms: 'You may use WIDE traffic data for only research purposes. Actions that trespass upon users' privacy are prohibited.' | no | no | no | unclear | RESEARCH | 2026-11-18 | https://mawi.wide.ad.jp/mawi/ |
| `mawilab` | MAWILab | Citation policy only (data follows MAWI/WIDE research-only terms) | no | no | no | unclear | RESEARCH | 2026-11-18 | https://mawi.wide.ad.jp/mawi/ |
| `metasploit-framework` | Metasploit Framework | BSD-3-Clause (framework) + third-party component licences (LGPL/GPL/MIT/Apache) | no | yes | yes | yes | OPEN | 2026-11-18 | https://github.com/rapid7/metasploit-framework/blob/master/LICENSE |
| `microsoft-defender-ti` | Microsoft Defender Threat Intelligence (in Defender XDR) | Microsoft commercial licensing | no | no | no | no | COMMERCIAL / requires_agreement | 2026-11-18 | https://learn.microsoft.com/en-us/defender-xdr/defender-threat-intelligence |
| `microsoft-simuland` | Microsoft SimuLand | MIT | yes | yes | yes | yes | OPEN | 2026-11-18 | https://opensource.org/license/mit |
| `misp-default-feeds` | MISP default feed list (feed-metadata/defaults.json) | Metadata: AGPL-3.0 (MISP); each feed has its own terms - no licence field in metadata | no | no | no | unclear | UNKNOWN | 2026-11-18 | https://github.com/MISP/MISP |
| `misp-feed-botvrij` | botvrij.eu OSINT feed | botvrij.eu terms (site FAQ) | no | no | no | no | UNKNOWN | 2026-11-21 | https://www.botvrij.eu/ |
| `misp-galaxy` | MISP Galaxy clusters | CC0-1.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/publicdomain/zero/1.0/ |
| `misp-taxonomies` | MISP Taxonomies | CC0-1.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/publicdomain/zero/1.0/ |
| `misp-warninglists` | MISP Warninglists | CC0-1.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/publicdomain/zero/1.0/ |
| `mitre-atlas` | MITRE ATLAS data | Apache-2.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://www.apache.org/licenses/LICENSE-2.0 |
| `mitre-attack-ics` | MITRE ATT&CK for ICS (STIX 2.1 data) | MITRE ATT&CK Terms of Use (royalty-free licence) | yes | yes | yes | yes | OPEN | 2026-11-18 | https://attack.mitre.org/resources/legal-and-branding/terms-of-use/ |
| `mitre-attack-mobile` | MITRE ATT&CK for Mobile (STIX 2.1 data) | MITRE ATT&CK Terms of Use (royalty-free licence) | yes | yes | yes | yes | OPEN | 2026-11-18 | https://attack.mitre.org/resources/legal-and-branding/terms-of-use/ |
| `mitre-attack-stix` | MITRE ATT&CK (STIX 2.1 data) | MITRE ATT&CK Terms of Use (royalty-free licence) | yes | yes | yes | yes | OPEN | 2026-11-18 | https://attack.mitre.org/resources/legal-and-branding/terms-of-use/ |
| `mitre-caldera` | MITRE CALDERA | Apache-2.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://www.apache.org/licenses/LICENSE-2.0 |
| `mitre-capec` | CAPEC - Common Attack Pattern Enumeration and Classification | CAPEC Terms of Use | yes | yes | yes | yes | OPEN | 2026-11-18 | https://capec.mitre.org/about/termsofuse.html |
| `mitre-cwe` | CWE - Common Weakness Enumeration | CWE Terms of Use | yes | yes | yes | yes | OPEN | 2026-11-18 | https://cwe.mitre.org/about/termsofuse.html |
| `mitre-d3fend` | MITRE D3FEND ontology | MIT | yes | yes | yes | yes | OPEN | 2026-11-18 | https://opensource.org/license/mit |
| `mitre-emb3d` | MITRE EMB3D (embedded device threat model) | MITRE EMB3D Terms of Use | no | no | no | requires_agreement | RESTRICTED / requires_agreement | 2026-11-21 | https://emb3d.mitre.org/subtabs/terms-of-use.html |
| `neo23x0-signature-base` | Neo23x0 signature-base (YARA + IOC) | DRL-1.1 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://github.com/SigmaHQ/Detection-Rule-License |
| `netlab360-dga` | 360 Netlab DGA (feed and reversed DGA code) | MIT License (GitHub repo) | yes | yes | yes | yes | OPEN | 2026-11-18 | https://github.com/360netlab/DGA/blob/master/LICENSE |
| `nist-nsrl-rds` | NIST NSRL Reference Data Set (RDSv3) | US Government work - public domain (17 USC 105) | yes | yes | yes | yes | OPEN | 2026-11-21 | https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/subscribe/redistribution |
| `nist-nvd-api2` | NVD CVE/CPE API 2.0 | NVD Terms of Use (US Government work; notice requested) | yes | yes | yes | yes | OPEN | 2026-11-18 | https://nvd.nist.gov/developers/terms-of-use |
| `nl-ncsc-csaf` | NCSC-NL security advisories (CSAF) | none stated | no | no | no | unclear | UNKNOWN | 2026-11-21 | — |
| `nuclei-templates` | ProjectDiscovery nuclei-templates | MIT | yes | yes | yes | yes | OPEN | 2026-11-18 | https://opensource.org/license/mit |
| `nvd-cpe-dictionary` | CPE Dictionary / CPE Match (NVD) | NVD Terms of Use | yes | yes | yes | yes | OPEN | 2026-11-18 | https://nvd.nist.gov/developers/terms-of-use |
| `oasis-stix-taxii` | OASIS STIX 2.1 / TAXII 2.1 specifications (+ JSON schemas) | OASIS copyright notice / IPR Policy | yes | yes | yes | yes | OPEN | 2026-11-18 | https://www.oasis-open.org/policies-guidelines/ipr/ |
| `openintel` | OpenINTEL active DNS measurements | CC BY-NC-SA 4.0 | no | no | no | no | RESEARCH / requires_agreement | 2026-11-21 | https://openintel.nl/download/terms/ |
| `openphish-community` | OpenPhish Community Feed | OpenPhish Terms of Use | no | no | no | no | RESTRICTED | 2026-11-18 | https://openphish.com/terms.html |
| `ossf-malicious-packages` | OpenSSF Malicious Packages | Apache-2.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://www.apache.org/licenses/LICENSE-2.0 |
| `osv-dev` | OSV.dev (Open Source Vulnerabilities) | Per-source licences (CC0, CC-BY 4.0, CC-BY-SA 4.0, Apache-2.0, MIT, CC-BY-NC-ND 4.0 for Chainguard/Wolfi ...); code Apache-2.0 | no | no | no | unclear | UNKNOWN | 2026-11-18 | https://google.github.io/osv.dev/data/ |
| `otrf-security-datasets` | OTRF Security-Datasets (formerly Mordor) | MIT | yes | yes | yes | yes | OPEN | 2026-11-18 | https://opensource.org/license/mit |
| `owasp-juice-shop` | OWASP Juice Shop | MIT | yes | yes | yes | yes | OPEN | 2026-11-18 | https://opensource.org/license/mit |
| `owasp-webgoat` | OWASP WebGoat | GPL-2.0-or-later | no | yes | yes | yes | OPEN | 2026-11-18 | https://www.gnu.org/licenses/old-licenses/gpl-2.0.html |
| `phishing-army` | Phishing Army blocklist | Phishing Army usage and licensing | no | no | no | unclear | UNKNOWN | 2026-11-21 | https://phishing.army/license/ |
| `phishing-database-mitchellkrogza` | Phishing.Database | MIT | no | no | no | yes | UNKNOWN | 2026-11-21 | https://opensource.org/licenses/MIT |
| `phishstats` | PhishStats | PhishStats Terms of Service | no | no | no | no | RESTRICTED / requires_agreement | 2026-11-18 | https://phishstats.info/terms |
| `phishtank` | PhishTank | Cisco end-user licence agreement linked as Terms of Use | no | no | no | unclear | UNKNOWN | 2026-11-18 | https://www.phishtank.com/developer_info.php |
| `phiusiil-phishing-url` | PhiUSIIL Phishing URL Dataset | CC-BY-4.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/licenses/by/4.0/ |
| `pl-certpl-warning-list` | CERT Polska Warning List (Lista Ostrzezen) | CERT Polska Warning List data usage policy | no | no | no | unclear | RESTRICTED | 2026-11-21 | https://cert.pl/en/warning-list/ |
| `poc-in-github` | PoC-in-GitHub (nomi-sec) | CC0-1.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/publicdomain/zero/1.0/ |
| `pypa-advisory-db` | PyPA Python Packaging Advisory Database | CC-BY-4.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/licenses/by/4.0/ |
| `ransomware-live` | Ransomware.live | Ransomware.live Terms & Conditions | no | no | no | no | RESTRICTED / requires_agreement | 2026-11-21 | https://www.ransomware.live/t&c |
| `ransomwhere` | Ransomwhere ransomware payment tracker | none stated | no | no | no | unclear | UNKNOWN | 2026-11-21 | — |
| `recorded-future` | Recorded Future Intelligence Cloud | Recorded Future commercial terms | no | no | no | no | COMMERCIAL / requires_agreement | 2026-11-18 | https://www.recordedfuture.com/ |
| `redhat-csaf-vex` | Red Hat Product Security CSAF advisories and VEX | CC-BY-4.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/licenses/by/4.0/ |
| `ro-bitdefender-malware-ioc` | Bitdefender Labs malware-ioc repository | None stated | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `ro-bitdefender-matter-iot` | Bitdefender Matter IoT dataset (benign traffic) | CC-BY-4.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/licenses/by/4.0/ |
| `ro-bitdefender-voyager` | Bitdefender Voyager Ventures and academic programmes | terms not identified | no | no | no | unclear | RESTRICTED | 2026-11-18 | — |
| `ro-conferences` | DefCamp 2026 and Bucharest Cybersecurity Conference (BCC) | terms not identified | no | no | no | unclear | RESTRICTED | 2026-11-18 | — |
| `ro-dnsc-rss` | DNSC alerts and news RSS feed | None stated | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `ro-dnsc-sharing` | DNSC information sharing / public-private partnerships | terms not identified | no | no | no | no | RESTRICTED / requires_agreement | 2026-11-18 | — |
| `ro-edih-cyber` | Romanian EDIHs with cybersecurity focus (DIH4Society, CiTyInnoHub) | terms not identified | no | no | no | unclear | RESTRICTED | 2026-11-18 | — |
| `ro-ncc-ro` | NCC-RO - Romanian National Coordination Centre for cybersecurity | terms not identified | no | no | no | unclear | RESTRICTED | 2026-11-18 | — |
| `ro-roedunet-simargl2021` | RoEduNet-SIMARGL2021 network intrusion dataset | Not verified (paper is open access) | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `ro-romanian-phishing-datasets` | Romanian-language phishing datasets (public) | terms not identified | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `ro-rotld` | ROTLD .ro registry (ICI Bucuresti) | terms not identified | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `routeviews` | University of Oregon RouteViews | none stated | no | no | no | unclear | UNKNOWN | 2026-11-21 | — |
| `rustsec-advisory-db` | RustSec Advisory Database | CC0-1.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/publicdomain/zero/1.0/ |
| `secqa` | SecQA | CC-BY-NC-SA-4.0 | no | no | no | yes | RESEARCH | 2026-11-21 | https://creativecommons.org/licenses/by-nc-sa/4.0/ |
| `shadowserver-reports` | Shadowserver network reports | Shadowserver subscription terms (redistribution not addressed on page) | no | no | no | no | RESTRICTED | 2026-11-18 | https://www.shadowserver.org/what-we-do/network-reporting/get-reports/ |
| `sigmahq-rules` | SigmaHQ detection rules | DRL-1.1 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://github.com/SigmaHQ/Detection-Rule-License |
| `sorel-20m` | SOREL-20M | Apache-2.0 (repo code); data licence not stated | no | no | no | unclear | UNKNOWN | 2026-11-21 | https://github.com/sophos/SOREL-20M |
| `spamhaus-dnsbl-dqs` | Spamhaus DNSBLs (ZEN/SBL/XBL/PBL/DBL, ZRD) public mirrors and Data Query Service | Spamhaus DNSBL Usage Terms / commercial Datafeed subscription | no | no | no | no | COMMERCIAL / requires_agreement | 2026-11-18 | https://www.spamhaus.org/organization/dnsblusage/ |
| `spamhaus-drop` | Spamhaus DROP / DROPv6 / ASN-DROP | Spamhaus DROP Terms | no | no | no | unclear | RESTRICTED | 2026-11-18 | https://www.spamhaus.org/drop/terms/ |
| `splunk-attack-data` | Splunk attack_data | Apache-2.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://www.apache.org/licenses/LICENSE-2.0 |
| `stratosphere-mcfp-captures` | Stratosphere / Malware Capture Facility Project captures (CTU-Malware-Capture-Botnet-*, Normal, Mixed) | No explicit licence (FAQ: no permission needed if cited) | no | no | no | unclear | UNKNOWN | 2026-11-18 | https://www.stratosphereips.org/datasets-faq |
| `stratus-red-team` | Stratus Red Team | Apache-2.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://www.apache.org/licenses/LICENSE-2.0 |
| `team-cymru-ip-asn` | Team Cymru IP-to-ASN mapping and Bogon Reference | none stated | no | no | no | unclear | UNKNOWN | 2026-11-21 | — |
| `ton-iot` | TON_IoT datasets | UNSW custom terms: 'Free use of the TON_IoT datasets for academic research purposes is hereby granted in perpetuity. Use for commercial purposes is allowable after asking the author, Dr Nour Moustafa… | no | no | no | unclear | RESEARCH / requires_agreement | 2026-11-18 | https://research.unsw.edu.au/projects/toniot-datasets |
| `tor-collector-exit-lists` | Tor Metrics CollecTor (exit lists, relay descriptors) | CC0-1.0 | yes | yes | yes | yes | OPEN | 2026-11-18 | https://creativecommons.org/publicdomain/zero/1.0/ |
| `tranco` | Tranco top-sites list | No licence stated for the Tranco list itself. Inputs per Tranco: Cisco Umbrella (free of charge), Majestic (CC BY 3.0), CrUX (CC BY-SA 4.0), Cloudflare Radar (CC BY-NC 4.0), Farsight (default list on… | no | no | no | unclear | UNKNOWN | 2026-11-18 | https://tranco-list.eu/ |
| `trendmicro-primus` | Trend Micro Primus datasets (FineWeb, Seed, Instruct, Reasoning) | ODC-By-1.0 | no | no | no | unclear | UNKNOWN | 2026-11-21 | https://huggingface.co/datasets/trendmicro-ailab/Primus-FineWeb |
| `trickest-cve` | trickest/cve PoC index | MIT | yes | yes | yes | yes | OPEN | 2026-11-18 | https://opensource.org/license/mit |
| `tu-dns-tunnelling-2023` | DNS tunnelling dataset (Tu, Liu, Sun, Computers & Security 2023) | None (GitHub repo has no LICENSE file) | no | no | no | no | UNKNOWN | 2026-11-18 | — |
| `ubuntu-security-notices` | Ubuntu Security Notices (USN) in OSV format | CC-BY-SA-4.0 | no | yes | yes | yes | OPEN | 2026-11-21 | https://creativecommons.org/licenses/by-sa/4.0/ |
| `ugr16` | UGR'16 | terms not identified | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `uk-cambridge-cybercrime-centre` | Cambridge Cybercrime Centre datasets | Per-project legal agreement | no | no | no | no | RESEARCH / requires_agreement | 2026-11-18 | — |
| `uk-cisp` | CiSP - Cyber Security Information Sharing Partnership | terms not identified | no | no | no | no | RESTRICTED / requires_agreement | 2026-11-18 | — |
| `uk-ncsc-annual-review-acd` | NCSC UK Annual Review 2026 - Active Cyber Defence | Open Government Licence v3 (typical for NCSC; not checked) | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `uk-ncsc-github` | NCSC UK GitHub (ukncsc) | Mixed (Apache-2.0 where shown) | no | yes | yes | yes | OPEN | 2026-11-18 | — |
| `umudga` | UMUDGA (University of Murcia DGA Dataset) | MIT | yes | yes | yes | yes | OPEN | 2026-11-18 | https://opensource.org/license/mit |
| `unit42-timely-threat-intel` | Palo Alto Networks Unit 42 timely threat intel (IOC repo) | GPL-3.0-only | no | yes | yes | yes | OPEN | 2026-11-18 | https://www.gnu.org/licenses/gpl-3.0.html |
| `unsw-nb15` | UNSW-NB15 | UNSW custom terms: 'Free use of the UNSW-NB15 dataset for academic research purposes is hereby granted in perpetuity. Use for commercial purposes should be agreed by the authors.' | no | no | no | unclear | RESEARCH / requires_agreement | 2026-11-18 | https://research.unsw.edu.au/projects/unsw-nb15-dataset |
| `uq-netflow-nids` | UQ NetFlow NIDS datasets (NF-UNSW-NB15, NF-ToN-IoT, NF-BoT-IoT, NF-CSE-CIC-IDS2018, NF-UQ-NIDS; v1/v2/v3) | None found on the UQ page (UQ RDM pages need JavaScript and were not readable) | no | no | no | unclear | UNKNOWN | 2026-11-18 | — |
| `volexity-threat-intel` | Volexity threat-intel IoCs | BSD-2-Clause | yes | yes | yes | yes | OPEN | 2026-11-21 | https://raw.githubusercontent.com/volexity/threat-intel/main/LICENSE.txt |
| `vx-underground-papers` | vx-underground papers and APT report archive | None found (site returned 403; archived papers are third-party works) | no | no | no | unclear | UNKNOWN | 2026-11-21 | https://vx-underground.org/ |
| `yara-forge` | YARA-Forge rule packages | Tool: GPL-3.0; rules: per-source licences (mixed) | no | no | no | yes | UNKNOWN | 2026-11-18 | https://github.com/YARAHQ/yara-forge/blob/main/LICENSE |
