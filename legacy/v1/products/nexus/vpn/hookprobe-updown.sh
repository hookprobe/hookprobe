#!/bin/bash
# HookProbe VPN Updown Script
# /etc/strongswan.d/hookprobe-updown.sh
#
# Called by strongSwan on VPN connection/disconnection events.
# Integrates with Django API and initiates HTP tunnels to Guardian/Fortress.

set -euo pipefail

# Configuration
HOOKPROBE_API_URL="${HOOKPROBE_API_URL:-http://127.0.0.1:8000/api/v1}"
HOOKPROBE_API_KEY="${HOOKPROBE_API_KEY:-}"
LOG_FILE="/var/log/hookprobe/vpn-updown.log"
HTP_TUNNEL_MANAGER="/opt/hookprobe/bin/htp-tunnel"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

# Send notification to Django API
notify_api() {
    local action="$1"
    local data="$2"

    if [[ -z "$HOOKPROBE_API_KEY" ]]; then
        log "WARNING: HOOKPROBE_API_KEY not set, skipping API notification"
        return 0
    fi

    curl -s -X POST \
        -H "Authorization: Bearer $HOOKPROBE_API_KEY" \
        -H "Content-Type: application/json" \
        -d "$data" \
        "${HOOKPROBE_API_URL}/vpn/sessions/${action}/" \
        >> "$LOG_FILE" 2>&1 || true
}

# Apply bandwidth limits using tc
apply_bandwidth_limit() {
    local interface="$1"
    local limit_mbps="$2"
    local client_ip="$3"

    # Convert Mbps to kbit
    local rate_kbit=$((limit_mbps * 1000))
    local burst_kbit=$((rate_kbit / 10))

    # Check if qdisc exists
    if ! tc qdisc show dev "$interface" | grep -q htb; then
        tc qdisc add dev "$interface" root handle 1: htb default 10
    fi

    # Create class for this client
    local class_id=$(echo "$client_ip" | awk -F. '{print $4}')

    tc class add dev "$interface" parent 1: classid 1:$class_id htb \
        rate ${rate_kbit}kbit ceil ${rate_kbit}kbit burst ${burst_kbit}k

    # Filter traffic to this class
    tc filter add dev "$interface" protocol ip parent 1:0 prio 1 \
        u32 match ip dst "$client_ip" flowid 1:$class_id

    log "Applied bandwidth limit: ${limit_mbps}Mbps for $client_ip"
}

# Remove bandwidth limits
remove_bandwidth_limit() {
    local interface="$1"
    local client_ip="$2"

    local class_id=$(echo "$client_ip" | awk -F. '{print $4}')

    # Remove filter and class
    tc filter del dev "$interface" protocol ip parent 1:0 prio 1 \
        u32 match ip dst "$client_ip" 2>/dev/null || true
    tc class del dev "$interface" parent 1: classid 1:$class_id 2>/dev/null || true

    log "Removed bandwidth limit for $client_ip"
}

# Start HTP tunnel to target device
start_htp_tunnel() {
    local device_id="$1"
    local assigned_ip="$2"

    if [[ -x "$HTP_TUNNEL_MANAGER" ]]; then
        "$HTP_TUNNEL_MANAGER" start \
            --device-id "$device_id" \
            --client-ip "$assigned_ip" \
            >> "$LOG_FILE" 2>&1 &
        log "Started HTP tunnel for device $device_id"
    else
        log "HTP tunnel manager not found: $HTP_TUNNEL_MANAGER"
    fi
}

# Stop HTP tunnel
stop_htp_tunnel() {
    local device_id="$1"

    if [[ -x "$HTP_TUNNEL_MANAGER" ]]; then
        "$HTP_TUNNEL_MANAGER" stop --device-id "$device_id" \
            >> "$LOG_FILE" 2>&1 || true
        log "Stopped HTP tunnel for device $device_id"
    fi
}

# Main handler
main() {
    log "=== VPN Event: $PLUTO_VERB ==="
    log "  Connection: $PLUTO_CONNECTION"
    log "  Peer: $PLUTO_PEER"
    log "  Peer ID: ${PLUTO_PEER_ID:-unknown}"
    log "  Virtual IP: ${PLUTO_PEER_SOURCEIP:-none}"
    log "  Mark: ${PLUTO_MARK_IN:-none}/${PLUTO_MARK_OUT:-none}"

    case "$PLUTO_VERB" in
        up-client|up-client-v6)
            # VPN connection established
            log "Client connected: ${PLUTO_PEER_ID:-$PLUTO_PEER}"

            # Notify Django API
            notify_api "start" "{
                \"client_ip\": \"$PLUTO_PEER\",
                \"assigned_ip\": \"${PLUTO_PEER_SOURCEIP:-}\",
                \"peer_id\": \"${PLUTO_PEER_ID:-}\",
                \"connection\": \"$PLUTO_CONNECTION\",
                \"ike_sa_id\": \"${PLUTO_UNIQUEID:-}\"
            }"

            # Get bandwidth limit from API (simplified - in production query API)
            local bandwidth_limit="${HOOKPROBE_DEFAULT_BANDWIDTH:-50}"

            # Apply bandwidth limits
            if [[ -n "${PLUTO_PEER_SOURCEIP:-}" ]]; then
                apply_bandwidth_limit "eth0" "$bandwidth_limit" "$PLUTO_PEER_SOURCEIP"
            fi

            # Extract device ID from peer ID (format: user@device.vpn.hookprobe.local)
            local device_id=""
            if [[ "${PLUTO_PEER_ID:-}" =~ @([^.]+)\.vpn\.hookprobe ]]; then
                device_id="${BASH_REMATCH[1]}"
                start_htp_tunnel "$device_id" "${PLUTO_PEER_SOURCEIP:-$PLUTO_PEER}"
            fi
            ;;

        down-client|down-client-v6)
            # VPN connection terminated
            log "Client disconnected: ${PLUTO_PEER_ID:-$PLUTO_PEER}"

            # Notify Django API
            notify_api "end" "{
                \"client_ip\": \"$PLUTO_PEER\",
                \"assigned_ip\": \"${PLUTO_PEER_SOURCEIP:-}\",
                \"peer_id\": \"${PLUTO_PEER_ID:-}\",
                \"connection\": \"$PLUTO_CONNECTION\"
            }"

            # Remove bandwidth limits
            if [[ -n "${PLUTO_PEER_SOURCEIP:-}" ]]; then
                remove_bandwidth_limit "eth0" "$PLUTO_PEER_SOURCEIP"
            fi

            # Stop HTP tunnel
            if [[ "${PLUTO_PEER_ID:-}" =~ @([^.]+)\.vpn\.hookprobe ]]; then
                stop_htp_tunnel "${BASH_REMATCH[1]}"
            fi
            ;;

        up-host|up-host-v6)
            log "Host route up: $PLUTO_PEER"
            ;;

        down-host|down-host-v6)
            log "Host route down: $PLUTO_PEER"
            ;;

        *)
            log "Unhandled verb: $PLUTO_VERB"
            ;;
    esac

    log "=== Event complete ==="
}

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Run main handler
main "$@"

exit 0
