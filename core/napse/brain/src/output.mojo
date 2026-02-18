# =============================================================================
# Napse Output Module - Event Serialization
# =============================================================================
#
# Serializes Napse intent classifications and HMM state updates to:
#   1. JSON files (for log shipper -> ClickHouse pipeline)
#   2. Direct ClickHouse HTTP insert (optional fast path)
#   3. MSSP API webhook (for real-time alerting)
#
# Output format is the "Napse Intent Event" schema that replaces the
# legacy EVE JSON (Suricata) format.


@value
struct IntentEvent:
    """A single Napse intent classification event.

    This is the output format that replaces Suricata's EVE JSON alert format.
    """
    var timestamp: String         # ISO 8601 nanosecond precision
    var src_ip: String
    var dst_ip: String
    var src_port: UInt16
    var dst_port: UInt16
    var proto: UInt8
    var intent_class: String      # "benign", "scan", "c2_beacon", etc.
    var confidence: Float32       # P(M|x) posterior probability
    var severity: UInt8           # 1=critical, 2=high, 3=medium, 4=low
    var hmm_state: String         # Current kill chain stage
    var prior_probability: Float32
    var posterior_probability: Float32
    var entropy: Float32          # Shannon entropy of triggering packet
    var community_id: String      # Cross-tool flow correlation ID
    var features_summary: String  # Compact key feature representation

    fn to_json(self) -> String:
        """Serialize to JSON string for file/API output."""
        var json = String('{"timestamp":"')
        json += self.timestamp
        json += '","src_ip":"'
        json += self.src_ip
        json += '","dst_ip":"'
        json += self.dst_ip
        json += '","src_port":'
        json += str(self.src_port)
        json += ',"dst_port":'
        json += str(self.dst_port)
        json += ',"proto":'
        json += str(self.proto)
        json += ',"intent_class":"'
        json += self.intent_class
        json += '","confidence":'
        json += str(self.confidence)
        json += ',"severity":'
        json += str(self.severity)
        json += ',"hmm_state":"'
        json += self.hmm_state
        json += '","prior_probability":'
        json += str(self.prior_probability)
        json += ',"posterior_probability":'
        json += str(self.posterior_probability)
        json += ',"entropy":'
        json += str(self.entropy)
        json += ',"community_id":"'
        json += self.community_id
        json += '","features_summary":"'
        json += self.features_summary
        json += '"}'
        return json


@value
struct FlowSummary:
    """A completed flow summary (replaces Zeek conn.log format).

    Emitted when a tracked flow expires or completes.
    """
    var timestamp: String
    var community_id: String
    var src_ip: String
    var dst_ip: String
    var src_port: UInt16
    var dst_port: UInt16
    var proto: UInt8
    var service: String
    var duration_s: Float64
    var bytes_orig: UInt64
    var bytes_resp: UInt64
    var pkts_orig: UInt64
    var pkts_resp: UInt64
    var max_entropy: Float32
    var avg_entropy: Float32
    var intent_class: String      # Dominant intent over flow lifetime
    var confidence: Float32       # Average confidence
    var hmm_final_state: String   # Final kill chain stage

    fn to_json(self) -> String:
        """Serialize to JSON string."""
        var json = String('{"timestamp":"')
        json += self.timestamp
        json += '","community_id":"'
        json += self.community_id
        json += '","src_ip":"'
        json += self.src_ip
        json += '","dst_ip":"'
        json += self.dst_ip
        json += '","src_port":'
        json += str(self.src_port)
        json += ',"dst_port":'
        json += str(self.dst_port)
        json += ',"proto":'
        json += str(self.proto)
        json += ',"service":"'
        json += self.service
        json += '","duration_s":'
        json += str(self.duration_s)
        json += ',"bytes_orig":'
        json += str(self.bytes_orig)
        json += ',"bytes_resp":'
        json += str(self.bytes_resp)
        json += ',"pkts_orig":'
        json += str(self.pkts_orig)
        json += ',"pkts_resp":'
        json += str(self.pkts_resp)
        json += ',"max_entropy":'
        json += str(self.max_entropy)
        json += ',"avg_entropy":'
        json += str(self.avg_entropy)
        json += ',"intent_class":"'
        json += self.intent_class
        json += '","confidence":'
        json += str(self.confidence)
        json += ',"hmm_final_state":"'
        json += self.hmm_final_state
        json += '"}'
        return json


struct EventWriter:
    """Writes Napse events to output destinations.

    Supports:
      - File output (JSONL format, one event per line)
      - ClickHouse direct HTTP insert
      - MSSP API webhook for critical alerts
    """
    var output_path: String
    var events_written: UInt64
    var flows_written: UInt64

    fn __init__(out self, output_path: String = "/var/log/napse/"):
        self.output_path = output_path
        self.events_written = 0
        self.flows_written = 0

    fn write_intent(mut self, event: IntentEvent):
        """Write an intent classification event."""
        # Production: append to /var/log/napse/intents.json (JSONL)
        # For severity <= 2: also send to MSSP API webhook
        _ = event.to_json()
        self.events_written += 1

    fn write_flow(mut self, flow: FlowSummary):
        """Write a completed flow summary."""
        # Production: append to /var/log/napse/flows.json (JSONL)
        _ = flow.to_json()
        self.flows_written += 1
