# AIOCHI Zeek Local Configuration
# Enhanced network monitoring for cognitive awareness

# Load standard frameworks
@load base/frameworks/notice
@load base/frameworks/intel
@load base/frameworks/files
@load base/frameworks/metrics
@load base/frameworks/sumstats

# Load protocol analyzers
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/ssh
@load base/protocols/ftp
@load base/protocols/smtp
@load base/protocols/dhcp
@load base/protocols/socks
@load base/protocols/rdp
@load base/protocols/modbus
@load base/protocols/dnp3
@load base/protocols/mqtt
@load base/protocols/ntp

# Load file extraction
@load base/files/extract
@load base/files/hash
@load frameworks/files/hash-all-files

# Network awareness
@load policy/frameworks/notice/extend-email/hostnames

# Software detection
@load policy/frameworks/software/vulnerable
@load policy/frameworks/software/version-changes

# Intel framework
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice

# SSL/TLS analysis
@load policy/protocols/ssl/validate-certs
@load policy/protocols/ssl/log-hostcerts-only
@load policy/protocols/ssl/extract-certs-pem
@load policy/protocols/ssl/validate-scts

# SSH analysis
@load policy/protocols/ssh/detect-bruteforcing
@load policy/protocols/ssh/geo-data

# DNS analysis
@load policy/protocols/dns/auth-addl
@load policy/protocols/dns/detect-external-names

# HTTP analysis
@load policy/protocols/http/detect-sqli
@load policy/protocols/http/detect-webapps

# Connection tracking
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services

# DHCP fingerprinting
@load policy/protocols/dhcp/software

# Packet filtering
@load policy/misc/capture-loss

# ============================================================
# AIOCHI Custom Scripts
# ============================================================

# JSON logging (required for log shipper)
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;

# Increase connection memory for busy networks
redef Pcap::bufsize = 256;

# Log rotation interval (1 hour)
redef Log::default_rotation_interval = 1 hr;

# Notice actions
redef Notice::mail_dest = "";

# DHCP fingerprinting for device identification
module AIOCHI;

export {
    redef enum Notice::Type += {
        New_Device,
        Device_Hostname_Change,
        Suspicious_DNS,
        Port_Scan_Detected,
        SSH_Bruteforce,
        TLS_Cert_Invalid,
    };
}

# Track new devices by DHCP
event dhcp_ack(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list,
               lease: interval, serv_addr: addr, host_name: string)
{
    if (|host_name| > 0)
    {
        local client_mac = msg$h_addr;
        NOTICE([$note=New_Device,
                $msg=fmt("New device on network: %s (hostname: %s)", client_mac, host_name),
                $conn=c,
                $identifier=cat(client_mac)]);
    }
}

# Detect suspicious DNS queries
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    # Long DNS queries (potential tunneling)
    if (|query| > 60)
    {
        NOTICE([$note=Suspicious_DNS,
                $msg=fmt("Suspicious DNS query (length=%d): %s", |query|, query),
                $conn=c]);
    }

    # Queries for suspicious TLDs
    local suspicious_tlds = set(".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top");
    for (tld in suspicious_tlds)
    {
        if (tld in query)
        {
            NOTICE([$note=Suspicious_DNS,
                    $msg=fmt("Query to suspicious TLD: %s", query),
                    $conn=c]);
            break;
        }
    }
}

# SSL certificate validation
event ssl_established(c: connection)
{
    if (c$ssl?$validation_status && c$ssl$validation_status != "ok")
    {
        NOTICE([$note=TLS_Cert_Invalid,
                $msg=fmt("TLS certificate validation failed: %s (%s)",
                        c$ssl?$server_name ? c$ssl$server_name : "unknown",
                        c$ssl$validation_status),
                $conn=c]);
    }
}
