#!/usr/bin/env bash
# ============================================================
#  scripts/gen_jwt_keys.sh — Generate RSA-2048 key pair for RS256 JWTs
#
#  Usage:
#    bash scripts/gen_jwt_keys.sh
#
#  Output:
#    backend/keys/jwt_private.pem
#    backend/keys/jwt_public.pem
# ============================================================

set -euo pipefail

KEY_DIR="$(dirname "$0")/../backend/keys"
mkdir -p "$KEY_DIR"

echo "[gen_jwt_keys] Generating RSA-2048 key pair..."

# Generate private key
openssl genpkey -algorithm RSA -out "$KEY_DIR/jwt_private.pem" -pkeyopt rsa_keygen_bits:2048

# Extract public key
openssl rsa -pubout -in "$KEY_DIR/jwt_private.pem" -out "$KEY_DIR/jwt_public.pem"

chmod 600 "$KEY_DIR/jwt_private.pem"
chmod 644 "$KEY_DIR/jwt_public.pem"

echo "[gen_jwt_keys] Done."
echo "  private: $KEY_DIR/jwt_private.pem"
echo "  public:  $KEY_DIR/jwt_public.pem"
echo ""
echo "  Update your .env file with the contents of these files."
