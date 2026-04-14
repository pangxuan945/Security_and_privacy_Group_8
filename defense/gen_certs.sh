#!/usr/bin/env bash
# ==============================================================================
# SmartNest CW2 Defense D1 — TLS certificate generation
# ==============================================================================
# Generates:
#   1. A self-signed CA (the root of trust for SmartNest)
#   2. A server certificate for the Mosquitto broker, signed by the CA
#   3. Three client certificates (one per device + one for the web panel),
#      each signed by the CA
#
# Usage:  cd defense && ./gen_certs.sh
# Output: defense/certs/  (contains all generated keys and certificates)
# ==============================================================================

set -e

CERT_DIR="$(dirname "$0")/certs"
DAYS=3650                     # 10 years — fine for a lab, NEVER for production
KEY_BITS=2048
SUBJECT_BASE="/C=GB/ST=London/L=London/O=SmartNest/OU=ELEC0138"

mkdir -p "${CERT_DIR}"
cd "${CERT_DIR}"

echo "============================================"
echo "  SmartNest TLS Certificate Generator"
echo "============================================"

# ------------------------------------------------------------------------------
# STEP 1: Create the Certificate Authority (CA)
# ------------------------------------------------------------------------------
# The CA key must be kept secret. Its certificate (ca.crt) is the root of
# trust — it will be installed on every broker and every client so that they
# can verify the authenticity of each other's certificates.
# ------------------------------------------------------------------------------

if [ ! -f ca.key ]; then
    echo ""
    echo "[1/3] Generating root CA..."
    openssl genrsa -out ca.key ${KEY_BITS}
    openssl req -new -x509 -days ${DAYS} -key ca.key -out ca.crt \
        -subj "${SUBJECT_BASE}/CN=SmartNest-CA"
    echo "      ca.key, ca.crt created."
else
    echo "[1/3] CA already exists, skipping."
fi

# ------------------------------------------------------------------------------
# STEP 2: Create the broker server certificate
# ------------------------------------------------------------------------------
# CN=broker matches the Docker service name used by clients to connect.
# subjectAltName is required by modern TLS libraries to validate the hostname.
# ------------------------------------------------------------------------------

echo ""
echo "[2/3] Generating broker server certificate..."
openssl genrsa -out broker.key ${KEY_BITS}

cat > broker.ext <<EOF
subjectAltName = DNS:broker,DNS:localhost,IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF

openssl req -new -key broker.key -out broker.csr \
    -subj "${SUBJECT_BASE}/CN=broker"
openssl x509 -req -in broker.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out broker.crt -days ${DAYS} -extfile broker.ext

rm -f broker.csr broker.ext
echo "      broker.key, broker.crt created."

# ------------------------------------------------------------------------------
# STEP 3: Create one client certificate per identity
# ------------------------------------------------------------------------------
# Each device gets its own key pair and certificate. The CN is used by
# Mosquitto as the username when use_identity_as_username=true is enabled,
# which lets us write fine-grained ACLs later.
# ------------------------------------------------------------------------------

generate_client_cert() {
    local NAME=$1
    echo "      - ${NAME}"

    openssl genrsa -out "${NAME}.key" ${KEY_BITS} 2>/dev/null

    cat > "${NAME}.ext" <<EOF
extendedKeyUsage = clientAuth
EOF

    openssl req -new -key "${NAME}.key" -out "${NAME}.csr" \
        -subj "${SUBJECT_BASE}/CN=${NAME}" 2>/dev/null
    openssl x509 -req -in "${NAME}.csr" -CA ca.crt -CAkey ca.key \
        -CAcreateserial -out "${NAME}.crt" -days ${DAYS} \
        -extfile "${NAME}.ext" 2>/dev/null

    rm -f "${NAME}.csr" "${NAME}.ext"
}

echo ""
echo "[3/3] Generating client certificates..."
generate_client_cert "device_simulator"
generate_client_cert "web_panel"
generate_client_cert "ids_monitor"

# Set file permissions so Mosquitto (running as the 'mosquitto' user) can read
chmod 644 *.crt
chmod 644 *.key

echo ""
echo "============================================"
echo "  Done. Certificates are in: ${CERT_DIR}"
echo "============================================"
ls -la
