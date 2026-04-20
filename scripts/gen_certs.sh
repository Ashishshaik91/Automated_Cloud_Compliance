#!/usr/bin/env bash
# ============================================================
#  scripts/gen_certs.sh — Generate self-signed TLS certificate
#  for local Docker development.
#
#  Usage:
#    bash scripts/gen_certs.sh
#
#  Output:
#    nginx/certs/cert.pem   ← certificate (safe to share)
#    nginx/certs/key.pem    ← private key (NEVER commit)
#
#  For production: replace these files with your real cert
#  (Let's Encrypt, ACM, etc.) — zero other config changes needed.
# ============================================================

set -euo pipefail

CERT_DIR="$(dirname "$0")/../nginx/certs"
mkdir -p "$CERT_DIR"

echo "[gen_certs] Generating RSA-2048 self-signed TLS certificate..."

openssl req -x509 \
  -newkey rsa:2048 \
  -keyout "$CERT_DIR/key.pem" \
  -out    "$CERT_DIR/cert.pem" \
  -days   365 \
  -nodes \
  -subj "/C=US/ST=Dev/L=Local/O=CloudCompliancePlatform/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "$CERT_DIR/key.pem"
chmod 644 "$CERT_DIR/cert.pem"

echo "[gen_certs] Done."
echo "  cert: $CERT_DIR/cert.pem"
echo "  key:  $CERT_DIR/key.pem"
echo ""
echo "  NOTE: Browsers will show a security warning for self-signed certs."
echo "  This is expected. Click 'Advanced → Proceed' to access the app."
echo "  All actual TLS security properties (encryption, Wireshark protection)"
echo "  are identical to a CA-signed cert."
