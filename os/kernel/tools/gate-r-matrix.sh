#!/bin/bash
# M2 Gate-R metal matrix: drive each frame-drivable row, 6s gap so the [SEPDIAG] heartbeat
# drain attributes the verdict. Rule-id -> row: 101 arp-malformed(F5/F9), 102 arp-spoof(L3/F10),
# 110 struct-anomaly(F6/F7/F8), 112 bcast-storm(A3), 113 port-scan(A4/A5),
# 116 beacon(L8), 117 lateral(A10), 201/202/203 null/fin/xmas(A6/F11),
# 302 ip-blocklist(L11), 114 conn-rate(L10), 120 truncated(F4). Expected verdict in comments.
# NOTE (A7/A8/L9 resource-shed) are NOT frame-drivable — proven by the sepdiag on-metal
# self-test ([SEPDIAG-SHED] ... => PASS) at sensor bring-up, not by this runner.
# NOTE: send A3_bcast_storm ALONE / last — its bounded burst crosses the 10s bcast window and
# any other broadcast-dst row sent within that window is also counted toward the storm.
GEN="$(dirname "$0")/gate-r-frames.py"
row(){ echo "===ROW=$1 (expect $2)==="; python3 "$GEN" enp4s0 "$3" "${4:-40}" >/dev/null 2>&1; sleep 6; }
echo "###MATRIX-START###"
# --- LEGIT: must PASS (Observe or no-fire) ---
row L3_arp_flipflop "rule102 PASS"       L3_arp_flipflop 40
row L7_cdn_443       "no-scan PASS"       L7_cdn_443 40
row L10_newconn      "under-cap PASS"     L10_newconn_burst 40
row L11_ioc_hit      "rule302 PASS"       L11_ioc_hit 40
row L8_ntp_beacon    "allowlist PASS"     L8_ntp_beacon 40
# --- FRAME: structural ---
row F1_iphone_arp42  "no-fire PASS"       F1_iphone_arp42 40
row F2_bare_ack54    "no-fire PASS"       F2_bare_ack54 40
row F3_local_admin   "no-fire PASS"       F3_local_admin_mac 40
row F6_mcast_src     "rule110 DROP"       F6_mcast_src 40
row F8_double_vlan   "rule110 DROP"       F8_double_vlan 40
row F9_arp_malformed "rule101 DROP"       F9_arp_malformed 40
# --- ATTACKER: correct tri-state ---
row A4_synscan_rl    "rule113 DROP(RL)"   A4_synscan_ports 60
row A5_synscan_confirm "rule113 DROP(Qtn)" A4_synscan_ports 130
row A6_fin_scan      "rule202 fire"       A6_fin_scan 40
row A6_null_scan     "rule201 fire"       A6_null_scan 40
row A6_xmas_scan     "rule203 fire"       A6_xmas_scan 40
row threat_4444      "rule1 DROP"         threat_4444 40
# --- BEHAVIORAL (M2.4, Observe-only — fire but NEVER wire-drop) ---
row A10_lateral      "rule117 PASS"       A10_lateral 10
# --- A3: bcast-storm shed on ANY port (post-fix: FloodRate -> RateLimit DROP). LAST + alone. ---
row A3_bcast_storm   "rule112 DROP"       A3_bcast_storm 120
echo "###MATRIX-END###"
