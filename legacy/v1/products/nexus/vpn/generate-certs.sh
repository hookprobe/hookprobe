#!/bin/bash
# HookProbe VPN Certificate Generator
# Generates CA and server certificates for strongSwan

set -euo pipefail

# Configuration
CERT_DIR="${CERT_DIR:-/etc/hookprobe/vpn}"
CA_DAYS=3650    # 10 years
SERVER_DAYS=365  # 1 year
KEY_SIZE=384     # ECC P-384

# Server identity
SERVER_CN="${SERVER_CN:-vpn.hookprobe.com}"
ORGANIZATION="${ORGANIZATION:-HookProbe}"
COUNTRY="${COUNTRY:-US}"

echo "=== HookProbe VPN Certificate Generator ==="
echo "Certificate directory: $CERT_DIR"
echo "Server CN: $SERVER_CN"
echo ""

# Create directory
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

# Check if CA already exists
if [[ -f ca.crt && -f ca.key ]]; then
    echo "CA certificate already exists. Skipping CA generation."
    echo "To regenerate, remove $CERT_DIR/ca.crt and ca.key"
else
    echo "Generating CA certificate..."

    # Generate CA private key (ECDSA P-384)
    openssl ecparam -name secp384r1 -genkey -noout -out ca.key

    # Generate self-signed CA certificate
    openssl req -x509 -new -nodes \
        -key ca.key \
        -sha384 \
        -days $CA_DAYS \
        -out ca.crt \
        -subj "/C=$COUNTRY/O=$ORGANIZATION/OU=Nexus VPN CA/CN=HookProbe Nexus VPN CA"

    echo "  CA certificate: $CERT_DIR/ca.crt"
    echo "  CA private key: $CERT_DIR/ca.key"
fi

# Check if server certificate exists
if [[ -f server.crt && -f server.key ]]; then
    echo "Server certificate already exists. Skipping server cert generation."
    echo "To regenerate, remove $CERT_DIR/server.crt and server.key"
else
    echo "Generating server certificate..."

    # Generate server private key
    openssl ecparam -name secp384r1 -genkey -noout -out server.key

    # Generate CSR
    openssl req -new \
        -key server.key \
        -out server.csr \
        -subj "/C=$COUNTRY/O=$ORGANIZATION/OU=Nexus VPN Server/CN=$SERVER_CN"

    # Create extensions file for SAN
    cat > server_ext.cnf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $SERVER_CN
DNS.2 = *.vpn.hookprobe.com
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF

    # Sign server certificate with CA
    openssl x509 -req \
        -in server.csr \
        -CA ca.crt \
        -CAkey ca.key \
        -CAcreateserial \
        -out server.crt \
        -days $SERVER_DAYS \
        -sha384 \
        -extfile server_ext.cnf

    # Cleanup
    rm -f server.csr server_ext.cnf

    echo "  Server certificate: $CERT_DIR/server.crt"
    echo "  Server private key: $CERT_DIR/server.key"
fi

# Set permissions
chmod 600 ca.key server.key
chmod 644 ca.crt server.crt

# Create symlinks for strongSwan
SWAN_DIR="/etc/swanctl"
if [[ -d "$SWAN_DIR" ]]; then
    echo "Creating strongSwan symlinks..."
    ln -sf "$CERT_DIR/ca.crt" "$SWAN_DIR/x509ca/hookprobe-ca.crt" 2>/dev/null || true
    ln -sf "$CERT_DIR/server.crt" "$SWAN_DIR/x509/server.crt" 2>/dev/null || true
    ln -sf "$CERT_DIR/server.key" "$SWAN_DIR/private/server.key" 2>/dev/null || true
fi

echo ""
echo "=== Certificate Generation Complete ==="
echo ""
echo "Verify certificates:"
echo "  openssl x509 -in $CERT_DIR/ca.crt -text -noout"
echo "  openssl x509 -in $CERT_DIR/server.crt -text -noout"
echo ""
echo "Reload strongSwan:"
echo "  swanctl --load-all"
