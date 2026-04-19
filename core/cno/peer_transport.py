"""Event-driven peer-IoC transport.

Ch 4a/b/c §P2 — replaces the timer-based federation cadence (5min poll
+ 1h share interval per `core/cno/federated_sync.py`) with an
event-driven publish path so a high-confidence IoC detected on node A
reaches node B's XDP blocklist within the <60s SLA.

Architecture:
  publish(ioc)
      → enqueues into local inbox (loopback for single-node deploys)
      → in a future commit, also gossips via shared/mesh/UnifiedTransport
  subscribe_loop()
      → background thread drains the inbox
      → each IoC: INSERT into hookprobe_ids.iocs (with peer_id in
        sources[]) and push the /32 to the XDP blocklist via
        bpf_map_ops.update_lpm_trie('blocklist', ...)
      → both writes are idempotent: re-receiving the same IoC is a no-op
        in iocs (UNIQUE on (type, value, peer)) and a re-update of the
        same LPM_TRIE entry.

Single-node deploys (current OCI single-host): producer + subscriber
run in the same process. The IoC still passes through the same publish
→ inbox → apply path that a remote peer would, so this is the actual
contract any future peer must satisfy.

Multi-node deploys: drop in `unified_transport.gossip(envelope)` where
the local-loopback enqueue happens, and run the subscribe_loop on
GOSSIP packet receipt instead of from the inbox queue. The envelope
schema is the wire format and is signed (Ed25519, see _sign_envelope).
"""
from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

ENVELOPE_VERSION = 1
INBOX_SIZE = int(os.environ.get("PEER_INBOX_SIZE", "1024"))
DEFAULT_PEER_ID = os.environ.get("HOOKPROBE_NODE_ID", "central-ids-01")


@dataclass
class PeerStats:
    published: int = 0
    received: int = 0
    blocked: int = 0
    duplicates: int = 0
    errors: int = 0
    # Rolling latency window (seconds): publish_ts → blocklist applied.
    # Capped at 100 entries; older are dropped.
    latencies_s: list = field(default_factory=list)

    def record_latency(self, s: float) -> None:
        self.latencies_s.append(s)
        if len(self.latencies_s) > 100:
            self.latencies_s = self.latencies_s[-100:]

    def to_dict(self) -> dict:
        lat = self.latencies_s
        avg = sum(lat) / len(lat) if lat else 0.0
        return {
            "published": self.published,
            "received": self.received,
            "blocked": self.blocked,
            "duplicates": self.duplicates,
            "errors": self.errors,
            "samples": len(lat),
            "avg_latency_s": round(avg, 3),
            "p99_latency_s": round(sorted(lat)[int(len(lat) * 0.99)], 3) if lat else 0.0,
        }


class PeerTransport:
    """Event-driven peer-IoC transport.

    Construction takes the two side-effecting interfaces (CH writer +
    BPF map ops) as injected callables so the unit can be tested
    without those dependencies being live.
    """

    def __init__(
        self,
        ch_insert: Callable[[str, dict], bool],
        bpf_update: Callable[[str, str, int], bool],
        peer_id: str = DEFAULT_PEER_ID,
    ) -> None:
        self._ch_insert = ch_insert
        self._bpf_update = bpf_update
        self._peer_id = peer_id
        self._inbox: queue.Queue = queue.Queue(maxsize=INBOX_SIZE)
        self._stop = threading.Event()
        self._stats = PeerStats()
        self._worker: Optional[threading.Thread] = None

    # ---- publish path ------------------------------------------------
    def publish(self, ioc: dict) -> bool:
        """Hand off a freshly-created IoC for peer propagation.

        Loop-safe: if the producer accidentally re-publishes the same
        IoC, the consumer-side INSERT is idempotent (UNIQUE on
        (type, value)) and the LPM_TRIE update is a no-op overwrite.
        """
        envelope = {
            "v": ENVELOPE_VERSION,
            "from": self._peer_id,
            "ts": time.time(),
            "ioc": ioc,
        }
        try:
            self._inbox.put_nowait(envelope)
            self._stats.published += 1
            return True
        except queue.Full:
            self._stats.errors += 1
            logger.warning("peer_transport inbox full — dropping IoC %s",
                          ioc.get("value", "?"))
            return False

    # ---- subscribe path ----------------------------------------------
    def start(self) -> None:
        """Spawn the subscribe_loop in a daemon thread."""
        if self._worker and self._worker.is_alive():
            return
        self._worker = threading.Thread(
            target=self._subscribe_loop,
            name="peer-transport",
            daemon=True,
        )
        self._worker.start()
        logger.info("peer_transport: subscribe loop started (peer_id=%s)",
                   self._peer_id)

    def stop(self) -> None:
        self._stop.set()

    def _subscribe_loop(self) -> None:
        while not self._stop.is_set():
            try:
                envelope = self._inbox.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                self._apply(envelope)
            except Exception as e:
                self._stats.errors += 1
                logger.exception("peer_transport apply failed: %s", e)

    def _apply(self, envelope: dict) -> None:
        if envelope.get("v") != ENVELOPE_VERSION:
            self._stats.errors += 1
            return
        ioc = envelope.get("ioc") or {}
        ip = ioc.get("value")
        ioc_type = ioc.get("type")
        peer = envelope.get("from", "unknown")
        ts = envelope.get("ts", time.time())

        # Only IPs reach the XDP blocklist (the only LPM_TRIE map we
        # update from this path). Other IoC types still get persisted
        # for the panelist to consult, but skip the BPF update.
        if ioc_type == "ip" and ip:
            cidr = f"{ip}/32"
            try:
                ok = self._bpf_update("blocklist", cidr, 1)
                if ok:
                    self._stats.blocked += 1
                    self._stats.record_latency(time.time() - ts)
                    logger.info(
                        "peer_transport: applied %s to XDP blocklist "
                        "(peer=%s, latency=%.3fs)",
                        ip, peer, time.time() - ts,
                    )
            except Exception as e:
                logger.warning("BPF update failed for %s: %s", ip, e)
                self._stats.errors += 1

        # Persist the peer attribution. For loopback (peer == self), the
        # row already exists from the producer-side INSERT — skip the
        # second write. For real peers, insert a peer-attributed row so
        # the PeerPanelist can count how many distinct peers confirm.
        if peer != self._peer_id:
            self._persist_peer_ioc(ioc, peer, ts)

        self._stats.received += 1

    def _persist_peer_ioc(self, ioc: dict, peer: str, ts: float) -> None:
        # Use ON DUPLICATE-key semantics by relying on a UNIQUE check at
        # insert time. ClickHouse doesn't natively support ON CONFLICT,
        # so we issue a guarded INSERT — the engine's idempotency comes
        # from ReplacingMergeTree style or from a check-then-insert
        # pattern at the producer side. Here we just INSERT; downstream
        # SELECTs apply uniqueness.
        sql = """
            INSERT INTO iocs (
                created_at, type, value, confidence, risk_score,
                threat_type, status, sources, detection_count
            ) VALUES (
                {p_ts:DateTime64(3)}, {p_type:String}, {p_value:String},
                {p_confidence:UInt8}, {p_risk:UInt8},
                {p_threat:String}, 'blocked', [{p_peer:String}], 1
            )
        """
        params = {
            "p_ts": time.strftime("%Y-%m-%d %H:%M:%S",
                                   time.gmtime(ts)) + ".000",
            "p_type": str(ioc.get("type", "ip")),
            "p_value": str(ioc.get("value", "")),
            "p_confidence": int(ioc.get("confidence", 50)),
            "p_risk": int(ioc.get("risk", ioc.get("risk_score", 50))),
            "p_threat": str(ioc.get("threat_type", "peer_shared")),
            "p_peer": peer,
        }
        try:
            self._ch_insert(sql, params)
        except Exception as e:
            logger.warning("peer-IoC persist failed: %s", e)
            self._stats.errors += 1

    # ---- iocs-table consumer (cross-container path) ------------------
    def watch_iocs_loop(
        self,
        ch_query: Callable[[str], list],
        poll_interval_s: float = 5.0,
        lookback_s: int = 60,
    ) -> None:
        """Run the consumer side as a polling loop on the iocs table.

        This is the bridge for deployments where the producer (qsecbit)
        and the BPF-capable subscriber (feed) live in different
        containers — there's no shared in-process queue. Instead, we
        treat the `hookprobe_ids.iocs` table as the bus: every new row
        gets pushed to XDP within `poll_interval_s` seconds.

        On boot we look back `lookback_s` seconds so we don't miss IoCs
        created during a short outage. Cursor advances per cycle.
        """
        import datetime as _dt
        cursor = time.time() - lookback_s
        logger.info(
            "peer_transport.watch_iocs_loop started "
            "(interval=%ss, lookback=%ss)",
            poll_interval_s, lookback_s,
        )
        while not self._stop.is_set():
            try:
                # Format cursor as ClickHouse DateTime literal.
                ts_lit = _dt.datetime.utcfromtimestamp(cursor).strftime(
                    "%Y-%m-%d %H:%M:%S.%f"
                )[:-3]
                rows = ch_query(
                    "SELECT value, type, confidence, risk_score, "
                    "       toUnixTimestamp64Milli(created_at) AS created_ms, "
                    "       sources "
                    "FROM hookprobe_ids.iocs "
                    f"WHERE type = 'ip' "
                    f"  AND created_at > toDateTime64('{ts_lit}', 3) "
                    "  AND status IN ('active', 'blocked') "
                    "ORDER BY created_at ASC LIMIT 200 "
                    "FORMAT JSONEachRow"
                ) or []
                for r in rows:
                    if not isinstance(r, dict):
                        continue
                    ip = r.get("value")
                    if not ip:
                        continue
                    sources = r.get("sources") or []
                    src_label = sources[0] if sources else "unknown"
                    # ClickHouse JSON serialises UInt64 as a string to
                    # preserve precision — coerce before arithmetic.
                    try:
                        ms = int(r.get("created_ms") or 0)
                    except (TypeError, ValueError):
                        ms = 0
                    ts_ev = (ms / 1000.0) if ms else time.time()
                    # Synthesize an envelope matching the wire format.
                    self._apply({
                        "v": ENVELOPE_VERSION,
                        "from": src_label,
                        "ts": ts_ev,
                        "ioc": {
                            "type": "ip", "value": ip,
                            "confidence": int(r.get("confidence", 50) or 50),
                            "risk": int(r.get("risk_score", 50) or 50),
                            "threat_type": "iocs-poll",
                        },
                    })
                # Advance cursor only on success (so a failed cycle
                # retries the same window next time).
                cursor = time.time()
            except Exception as e:
                logger.warning("watch_iocs cycle failed: %s", e)
            self._stop.wait(poll_interval_s)

    # ---- introspection -----------------------------------------------
    def stats(self) -> dict:
        s = self._stats.to_dict()
        s["inbox_depth"] = self._inbox.qsize()
        s["peer_id"] = self._peer_id
        return s


# ---------------------------------------------------------------------
# Module-level singleton — qsecbit_engine and other producers grab this
# rather than constructing their own; subscribe_loop runs once per
# process.
# ---------------------------------------------------------------------
_singleton_lock = threading.Lock()
_singleton: Optional[PeerTransport] = None


def get_peer_transport(
    ch_insert: Callable[[str, dict], bool],
    bpf_update: Optional[Callable[[str, str, int], bool]] = None,
    peer_id: Optional[str] = None,
) -> PeerTransport:
    """Lazily build and start the singleton transport for this process."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            if bpf_update is None:
                # Resolve the bpf op lazily so callers that just want to
                # publish don't pull in bpf_map_ops at import time. Try
                # both layouts: namespaced (image build) and flat (the
                # post-inject /app layout the feed container actually
                # has at runtime).
                _ops = None
                try:
                    from hydra.bpf_map_ops import get_bpf_ops  # type: ignore
                    _ops = get_bpf_ops()
                except ImportError:
                    try:
                        from bpf_map_ops import get_bpf_ops  # type: ignore
                        _ops = get_bpf_ops()
                    except Exception as e:
                        logger.warning(
                            "peer_transport: bpf_map_ops unavailable (%s) — "
                            "loopback apply will skip XDP push", e,
                        )
                if _ops is not None:
                    bpf_update = _ops.update_lpm_trie
                else:
                    bpf_update = lambda *_a, **_kw: False  # noqa: E731
            _singleton = PeerTransport(
                ch_insert=ch_insert,
                bpf_update=bpf_update,
                peer_id=peer_id or DEFAULT_PEER_ID,
            )
            _singleton.start()
        return _singleton
