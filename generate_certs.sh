#!/usr/bin/env bash
# generate_certs.sh — create a self-signed TLS certificate for local/dev use
# Outputs: certs/cert.pem  certs/key.pem
#
# For production use a real certificate (Let's Encrypt / certbot, or your CA).

set -euo pipefail

CERT_DIR="${1:-certs}"
DAYS="${2:-365}"
CN="${3:-localhost}"

mkdir -p "$CERT_DIR"

echo "Generating self-signed certificate in ./$CERT_DIR/"
echo "  CN   : $CN"
echo "  Valid: $DAYS days"
echo ""

openssl req -x509 \
  -newkey rsa:4096 \
  -keyout "$CERT_DIR/key.pem" \
  -out    "$CERT_DIR/cert.pem" \
  -days   "$DAYS" \
  -nodes \
  -subj   "/C=US/ST=Local/L=Local/O=DeceptivGuard/CN=$CN" \
  -addext "subjectAltName=DNS:$CN,DNS:localhost,IP:127.0.0.1"

chmod 600 "$CERT_DIR/key.pem"

echo ""
echo "Done:"
echo "  Certificate : $CERT_DIR/cert.pem"
echo "  Private key : $CERT_DIR/key.pem"
echo ""
echo "Set these in your .env:"
echo "  SSL_CERTFILE=$CERT_DIR/cert.pem"
echo "  SSL_KEYFILE=$CERT_DIR/key.pem"
echo ""
echo "Note: browsers and curl will warn about self-signed certs."
echo "  curl: use -k / --insecure"
echo "  Python httpx/requests: verify=False  (dev only)"
echo "  Production: replace with a cert from Let's Encrypt or your CA."
