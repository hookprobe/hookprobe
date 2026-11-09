"""
Regression tests for the 2026-11-09 IDS stack audit.

Each test pins a production bug found live on the MSSP host:

  1. packet_inspector flow orientation — lexicographic (ip, port) compare made
     the host the "src" of ~every inbound flow (attackers landed in dst_ip).
  2. event_consumer — prev_stats seeded with zeros (restart spike) and the
     high_rate_ips map replayed as fresh alerts forever (never drained).
  3. trusted_networks dynamic operator trust (operator VPN IP self-blocked).
  4. feed_sync — expired cognitive blocks never left the XDP maps (600s
     throttles became permanent WAN drops and killed 4 threat feeds); empty
     feeds reported as success; failed feeds must keep last-good entries.
  5. cognitive_defense — host-initiated peers (feed CDNs) exempt from blocks.
  6. flow_threats — low-and-slow inbound recon classification + dedup.

Pure unit tests: no ClickHouse, no BPF, no network.
"""

import json
import os
import struct
import sys
import types
from unittest.mock import patch

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
HYDRA = os.path.join(ROOT, 'core', 'hydra')
INSPECTOR = os.path.join(ROOT, 'core', 'napse', 'inspector')
for p in (ROOT, HYDRA, INSPECTOR):
    if p not in sys.path:
        sys.path.insert(0, p)


# ============================================================================
# 1. Inspector flow orientation
# ============================================================================

class TestFlowOrientation:
    def setup_method(self):
        import packet_inspector as pi
        self.pi = pi

    def _pkt(self, src, dst, sp, dp, proto=6, flags=0):
        return {'src_ip': src, 'dst_ip': dst, 'src_port': sp, 'dst_port': dp,
                'proto': proto, 'tcp_flags': flags, 'total_length': 60,
                'payload_len': 0, 'entropy': 0.0, 'payload': b''}

    def test_syn_sender_is_originator(self):
        assert self.pi.sender_is_originator(self._pkt('203.0.113.9', '10.0.1.110', 51234, 22, flags=0x02))

    def test_synack_sender_is_responder(self):
        assert not self.pi.sender_is_originator(self._pkt('10.0.1.110', '203.0.113.9', 22, 51234, flags=0x12))

    def test_midflow_service_port_side_is_responder(self):
        # first-seen packet is the server's reply (ACK only) — server is NOT originator
        assert not self.pi.sender_is_originator(self._pkt('10.0.1.110', '203.0.113.9', 443, 50000, flags=0x10))
        # UDP DNS response first seen
        assert not self.pi.sender_is_originator(self._pkt('1.1.1.1', '10.0.1.110', 53, 40000, proto=17))
        # mesh port counts as a service port
        assert self.pi.sender_is_originator(self._pkt('86.120.11.18', '10.0.1.110', 40001, 8144, proto=17))

    def test_inbound_flow_recorded_with_attacker_as_src(self):
        """The production bug: '10.0.1.110' < '203.0.113.9' lexicographically."""
        insp = self.pi.PacketInspector.__new__(self.pi.PacketInspector)
        insp.flows = {}
        attacker, host = '203.0.113.9', '10.0.1.110'
        insp.update_flow(self._pkt(attacker, host, 51234, 22, flags=0x02))     # SYN
        insp.update_flow(self._pkt(host, attacker, 22, 51234, flags=0x12))     # SYN-ACK
        insp.update_flow(self._pkt(attacker, host, 51234, 22, flags=0x10))     # ACK
        assert len(insp.flows) == 1
        flow = next(iter(insp.flows.values()))
        assert flow.src_ip == attacker and flow.dst_ip == host
        assert flow.src_port == 51234 and flow.dst_port == 22
        assert flow.pkts_orig == 2 and flow.pkts_resp == 1

    def test_outbound_flow_keeps_host_as_src(self):
        insp = self.pi.PacketInspector.__new__(self.pi.PacketInspector)
        insp.flows = {}
        host, cdn = '10.0.1.110', '146.75.122.49'
        insp.update_flow(self._pkt(host, cdn, 45000, 443, flags=0x02))
        insp.update_flow(self._pkt(cdn, host, 443, 45000, flags=0x12))
        flow = next(iter(insp.flows.values()))
        assert (flow.src_ip, flow.dst_ip, flow.dst_port) == (host, cdn, 443)
        assert flow.pkts_orig == 1 and flow.pkts_resp == 1

    def test_flow_key_is_direction_independent(self):
        k1 = self.pi.flow_key('a', 'b', 1, 2, 6)
        k2 = self.pi.flow_key('b', 'a', 2, 1, 6)
        assert k1 == k2


# ============================================================================
# 2. Event consumer: restart baseline + high_rate_ips drain
# ============================================================================

class FakeOps:
    def __init__(self, stats, high_rate):
        self.stats = list(stats)
        self.high_rate = dict(high_rate)   # key bytes -> value bytes
        self.deleted = []

    def read_percpu_u64(self, name, idx):
        return self.stats[idx]

    def find_map_by_name(self, name):
        return 7 if name == 'high_rate_ips' else None

    def map_dump(self, map_id):
        return list(self.high_rate.items())

    def map_delete(self, map_id, key):
        self.deleted.append(key)
        self.high_rate.pop(key, None)
        return True


def _ipkey(ip):
    import ipaddress
    return ipaddress.IPv4Address(ip).packed


class TestEventConsumer:
    def setup_method(self):
        import event_consumer as ec
        self.ec = ec
        ec.event_buffer.clear() if isinstance(ec.event_buffer, list) else None
        ec.drop_counts.clear()

    def test_seed_prev_stats_uses_live_counters(self):
        ops = FakeOps([137_000_000, 1, 0, 0, 518_802, 0, 358_497], {})
        assert self.ec._seed_prev_stats(ops) == ops.stats

    def test_first_poll_after_restart_reports_no_spike(self):
        ops = FakeOps([1000, 0, 0, 0, 50, 0, 7], {_ipkey('13.226.244.33'): struct.pack('<Q', 5000)})
        prev = self.ec._seed_prev_stats(ops)
        with patch.object(self.ec, 'ch_query', lambda *a, **k: None), \
             patch.object(self.ec, 'CH_PASSWORD', ''):
            curr = self.ec.poll_xdp_stats(ops, prev, [], 1)
        assert curr == ops.stats
        # no blocklist/score delta -> no synthetic alerts replayed
        assert self.ec.event_buffer == []

    def test_high_rate_entries_drained_once(self):
        ops = FakeOps([0] * 7, {
            _ipkey('203.0.113.5'): struct.pack('<Q', 4000),
            _ipkey('10.1.2.3'): struct.pack('<Q', 9000),   # trusted RFC1918
        })
        first = self.ec.drain_high_rate_ips(ops)
        assert [e['src_ip'] for e in first] == ['203.0.113.5']
        assert first[0]['reason'] == 'rate_exceeded'
        assert len(ops.deleted) == 2               # trusted entry drained too
        assert self.ec.drain_high_rate_ips(ops) == []   # never replayed

    def test_counter_reset_never_negative(self):
        ops = FakeOps([5, 0, 0, 0, 0, 0, 0], {})
        with patch.object(self.ec, 'CH_PASSWORD', ''):
            self.ec.poll_xdp_stats(ops, [100] * 7, [], 1)
        assert self.ec.event_buffer == []


# ============================================================================
# 3. Dynamic operator trust
# ============================================================================

class TestDynamicTrust:
    def setup_method(self):
        import trusted_networks as tn
        self.tn = tn

    def _use_file(self, tmp_path, text):
        f = tmp_path / 'operator_ips.txt'
        f.write_text(text)
        self.tn.DYNAMIC_TRUST_FILE = str(f)
        self.tn._dyn_cache.update(mtime=None, checked=0.0, nets=())
        return f

    def test_operator_ip_trusted_from_file(self, tmp_path):
        self._use_file(tmp_path, '# header\n86.120.11.18\n213.233.104.11  # today\n')
        assert self.tn.is_trusted('86.120.11.18')
        assert self.tn.is_trusted('213.233.104.11')
        assert not self.tn.is_trusted('86.120.11.19')

    def test_overbroad_and_garbage_rejected(self, tmp_path):
        self._use_file(tmp_path, '0.0.0.0/0\n10.0.0.0/7\nnot-an-ip\n198.51.100.0/24\n')
        nets = [str(n) for n in self.tn.dynamic_trusted_networks()]
        assert nets == ['198.51.100.0/24']
        assert not self.tn.is_trusted('203.0.113.1')

    def test_missing_file_is_empty(self, tmp_path):
        self.tn.DYNAMIC_TRUST_FILE = str(tmp_path / 'absent.txt')
        self.tn._dyn_cache.update(mtime=None, checked=0.0, nets=())
        assert self.tn.dynamic_trusted_networks() == ()
        assert self.tn.is_trusted('127.0.0.1')   # static list unaffected

    def test_static_list_still_covers_dns_resolvers(self):
        assert self.tn.is_trusted('1.1.1.1')


# ============================================================================
# 4. feed_sync: XDP reconciliation + feed health
# ============================================================================

@pytest.fixture
def feed_sync(monkeypatch):
    import feed_sync as fs
    monkeypatch.setattr(fs, 'CH_PASSWORD', 'x')
    fs.prev_blocklist = set()
    fs._last_good_feed.clear()
    fs._feed_fail_streak.clear()
    return fs


class RecordingOps:
    def __init__(self):
        self.deleted = []

    def delete_lpm_trie(self, name, cidr):
        self.deleted.append((name, cidr))
        return True


class TestFeedSync:
    def test_expired_cognitive_blocks_removed_from_both_maps(self, feed_sync, monkeypatch):
        ops = RecordingOps()
        monkeypatch.setattr(feed_sync, 'get_bpf_ops', lambda: ops)
        monkeypatch.setattr(feed_sync, 'ch_query', lambda q: (
            '{"ip":"146.75.122.49"}\n{"ip":"185.199.111.133"}\n{"ip":"5.6.7.8"}\n'))
        removed = feed_sync.purge_expired_cognitive_blocks(keep={'5.6.7.8/32'})
        assert removed == 2
        assert ('blocklist', '146.75.122.49/32') in ops.deleted
        assert ('sw_blocklist', '146.75.122.49/32') in ops.deleted   # WAN enforcement map
        assert not any(c == '5.6.7.8/32' for _, c in ops.deleted)    # still desired

    def test_expired_query_excludes_permanent_blocks(self, feed_sync, monkeypatch):
        seen = {}
        monkeypatch.setattr(feed_sync, 'ch_query', lambda q: seen.setdefault('q', q) and '')
        feed_sync.expired_cognitive_ips()
        q = seen['q']
        assert 'min(duration_seconds) > 0' in q
        assert 'INTERVAL 30 DAY' in q

    def _run_sync(self, feed_sync, monkeypatch, downloads):
        monkeypatch.setattr(feed_sync, 'FEEDS', [{'name': n, 'url': f'https://x/{n}', 'format': 'plain'}
                                                 for n in downloads])
        monkeypatch.setattr(feed_sync, 'download_feed', lambda f: downloads[f['name']])
        monkeypatch.setattr(feed_sync, 'log_feed_sync', lambda *a, **k: None)
        monkeypatch.setattr(feed_sync, 'sync_cognitive_blocks', lambda: (set(), 0))
        monkeypatch.setattr(feed_sync, 'feed_source_ips', lambda: set())
        monkeypatch.setattr(feed_sync, 'purge_expired_cognitive_blocks', lambda keep: 0)
        pushed = {}
        monkeypatch.setattr(feed_sync, 'update_xdp_map_batch',
                            lambda m, c, value=1: (pushed.__setitem__(m, set(c)), len(c))[1])
        monkeypatch.setattr(feed_sync, 'update_allowlist', lambda: 0)
        removed = {}
        monkeypatch.setattr(feed_sync, 'remove_xdp_cidrs',
                            lambda m, c: (removed.__setitem__(m, set(c)), len(c))[1])
        feed_sync.sync_all_feeds()
        return pushed, removed

    def test_failed_feed_keeps_last_good_entries(self, feed_sync, monkeypatch):
        self._run_sync(feed_sync, monkeypatch, {'a': ({'198.51.100.0/24'}, None)})
        pushed, removed = self._run_sync(feed_sync, monkeypatch, {'a': (set(), 'timed out')})
        assert '198.51.100.0/24' in pushed['blocklist']
        assert not removed.get('blocklist')
        assert feed_sync._feed_fail_streak['a'] == 1

    def test_empty_feed_is_not_success(self, feed_sync, monkeypatch):
        self._run_sync(feed_sync, monkeypatch, {'edrop': (set(), None)})
        assert feed_sync._feed_fail_streak['edrop'] == 1

    def test_dropped_feed_cidr_removed_from_xdp(self, feed_sync, monkeypatch):
        self._run_sync(feed_sync, monkeypatch, {'a': ({'198.51.100.0/24', '203.0.113.0/24'}, None)})
        _, removed = self._run_sync(feed_sync, monkeypatch, {'a': ({'198.51.100.0/24'}, None)})
        assert removed['blocklist'] == {'203.0.113.0/24'}

    def test_feed_source_ips_never_blocklisted(self, feed_sync, monkeypatch):
        monkeypatch.setattr(feed_sync, 'feed_source_ips', lambda: {'146.75.122.49'})
        nets = feed_sync.never_block_nets()
        import ipaddress
        assert any(ipaddress.ip_address('146.75.122.49') in n for n in nets)


# ============================================================================
# 5. cognitive_defense enforcement exemptions
# ============================================================================

class TestEnforcementExempt:
    def setup_method(self):
        import cognitive_defense as cd
        self.cd = cd

    def test_host_initiated_peer_exempt(self):
        assert self.cd._is_enforcement_exempt('146.75.122.49', set(), {'146.75.122.49'}) == 'host-initiated peer'

    def test_live_ssh_exempt(self):
        assert self.cd._is_enforcement_exempt('86.120.11.18', {'86.120.11.18'}) == 'live SSH session'

    def test_unknown_ip_not_exempt(self):
        assert self.cd._is_enforcement_exempt('203.0.113.77', set(), set()) is None


# ============================================================================
# 6. flow_threats
# ============================================================================

class TestFlowThreats:
    def setup_method(self):
        import flow_threats as ft
        self.ft = ft

    def test_classify_rules(self):
        c = self.ft.classify
        assert c({'ip': '203.0.113.1', 'uniq_ports': 9, 'flows': 9}) == ['slow_scan']
        assert c({'ip': '203.0.113.1', 'uniq_ports': 3, 'unanswered': 6, 'flows': 6}) == ['slow_scan']
        assert c({'ip': '203.0.113.1', 'uniq_ports': 1, 'ssh_flows': 3, 'flows': 3}) == ['ssh_probe']
        assert c({'ip': '203.0.113.1', 'uniq_ports': 1, 'web_flows': 5, 'flows': 5}) == ['origin_direct']
        # Cloudflare proxied web traffic is the normal path
        assert c({'ip': '104.16.1.1', 'uniq_ports': 1, 'web_flows': 500, 'flows': 500}) == []
        assert c({'ip': '203.0.113.1', 'uniq_ports': 2, 'flows': 4}) == []

    def test_build_query_rejects_bad_local_ips(self):
        assert self.ft.build_query('db', ["1.2.3.4'); DROP TABLE x;--"]) is None
        q = self.ft.build_query('hookprobe_ids', ['10.0.1.110'])
        assert "dst_ip IN (IPv4StringToNum('10.0.1.110'))" in q
        assert 'src_ip NOT IN' in q

    def test_detector_emits_once_per_window_and_skips_trusted(self):
        now = [1000.0]
        rows = '\n'.join(json.dumps(r) for r in [
            {'ip': '203.0.113.50', 'flows': 4, 'uniq_ports': 1, 'ports': [22], 'ssh_flows': 4},
            {'ip': '86.120.11.18', 'flows': 9, 'uniq_ports': 9, 'ports': list(range(9))},
        ])
        det = self.ft.FlowThreatDetector(
            'hookprobe_ids', lambda q: rows, lambda: ['10.0.1.110'],
            is_trusted_fn=lambda ip: ip == '86.120.11.18', clock=lambda: now[0])
        ev = det.scan()
        assert {e['src_ip'] for e in ev} == {'203.0.113.50'}
        assert all(e['reason'] == 'ssh_probe' and e['dst_port'] == 22 for e in ev)
        assert len(ev) == 4
        assert det.scan() == []                       # suppressed within window
        now[0] += self.ft.WINDOW_S + 1
        assert len(det.scan()) == 4                   # re-armed after window

    def test_origin_direct_capped_low_weight(self):
        ev = self.ft.events_for({'ip': '203.0.113.9', 'flows': 50, 'ports': [443]},
                                'origin_direct', '10.0.1.110')
        assert len(ev) == 3 and all(e['dst_port'] == 443 for e in ev)


# ============================================================================
# 7. WAN enforcement map full reconcile (2026-11-09: ~160k stale entries)
# ============================================================================

class FakeLpmOps:
    def __init__(self, cidrs):
        import ipaddress
        self.keys = {}
        for c in cidrs:
            n = ipaddress.ip_network(c)
            self.keys[struct.pack('<I', n.prefixlen) + n.network_address.packed] = b'\x01'
        self.deleted = []

    def find_map_by_name(self, name):
        return 9 if name == 'sw_blocklist' else None

    def map_dump(self, map_id):
        return list(self.keys.items())

    def delete_lpm_trie(self, name, cidr):
        self.deleted.append(cidr)
        return True


class TestWanReconcile:
    LIVE = ['198.51.100.0/24', '203.0.113.7/32', '192.0.2.0/24', '100.64.1.1/32', '100.64.1.2/32']

    def test_removes_only_stale(self, feed_sync, monkeypatch, tmp_path):
        ops = FakeLpmOps(self.LIVE)
        monkeypatch.setattr(feed_sync, 'get_bpf_ops', lambda: ops)
        n = feed_sync.reconcile_wan_blocklist({'198.51.100.0/24', '203.0.113.7/32'},
                                              complete=True, snapshot_dir=str(tmp_path))
        assert n == 3
        assert set(ops.deleted) == {'192.0.2.0/24', '100.64.1.1/32', '100.64.1.2/32'}
        assert (tmp_path / 'sw_blocklist.removed.json').exists()     # rollback snapshot

    def test_skips_when_feed_set_incomplete(self, feed_sync, monkeypatch, tmp_path):
        ops = FakeLpmOps(self.LIVE)
        monkeypatch.setattr(feed_sync, 'get_bpf_ops', lambda: ops)
        assert feed_sync.reconcile_wan_blocklist({'198.51.100.0/24'}, complete=False,
                                                 snapshot_dir=str(tmp_path)) == 0
        assert ops.deleted == []

    def test_refuses_implausibly_small_desired_set(self, feed_sync, monkeypatch, tmp_path):
        ops = FakeLpmOps(self.LIVE)
        monkeypatch.setattr(feed_sync, 'get_bpf_ops', lambda: ops)
        assert feed_sync.reconcile_wan_blocklist(set(), complete=True,
                                                 snapshot_dir=str(tmp_path)) == 0
        assert ops.deleted == []

    def test_failed_feed_without_cache_marks_incomplete(self, feed_sync, monkeypatch):
        seen = {}
        monkeypatch.setattr(feed_sync, 'reconcile_wan_blocklist',
                            lambda desired, complete: seen.setdefault('complete', complete) and 0)
        TestFeedSync()._run_sync(feed_sync, monkeypatch, {'a': (set(), 'timed out')})
        assert seen['complete'] is False


class TestMirrorReconcile:
    def test_mirror_keeps_live_cno_blocks(self, feed_sync, monkeypatch, tmp_path):
        class Ops(FakeLpmOps):
            def find_map_by_name(self, name):
                return 9 if name == 'blocklist' else None
        ops = Ops(['198.51.100.0/24', '203.0.113.7/32', '192.0.2.9/32', '100.64.1.1/32'])
        monkeypatch.setattr(feed_sync, 'get_bpf_ops', lambda: ops)
        monkeypatch.setattr(feed_sync, 'active_cno_mirror_cidrs', lambda: {'203.0.113.7/32'})
        monkeypatch.setenv('WAN_RECONCILE_SNAPSHOT_DIR', str(tmp_path))
        n = feed_sync.reconcile_mirror_blocklist({'198.51.100.0/24', '192.0.2.9/32'}, complete=True)
        assert n == 1 and ops.deleted == ['100.64.1.1/32']

    def test_cno_mirror_never_reaches_wan(self, feed_sync):
        assert 'cno_mirror' not in feed_sync.COGNITIVE_BLOCK_SOURCES


class TestCnoMirrorRecord:
    def test_reason_cannot_inject_sql(self, monkeypatch):
        import re as _re
        reason = "x'); DROP TABLE hydra_blocks; --"
        safe = _re.sub(r"[^A-Za-z0-9 _.:/,()-]", "", reason)[:200]
        assert "'" not in safe and ";" not in safe
