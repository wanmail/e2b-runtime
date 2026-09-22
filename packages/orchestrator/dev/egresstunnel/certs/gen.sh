#!/usr/bin/env bash
# Generate a tunnel CA (signs sandbox client certs) and a gateway server cert
# that Envoy presents. Idempotent: overwrites files in this directory.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# RSA so Envoy's BoringSSL loads the PEM without "incomplete private key".
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout tunnel-ca.key -out tunnel-ca.crt -days 3650 \
  -subj "/CN=e2b egress tunnel CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,digitalSignature"
openssl pkcs8 -topk8 -nocrypt -in tunnel-ca.key -out tunnel-ca.pkcs8.key
mv tunnel-ca.pkcs8.key tunnel-ca.key

openssl req -newkey rsa:2048 -nodes \
  -keyout gateway.key -out gateway.csr \
  -subj "/CN=gateway.local"
openssl pkcs8 -topk8 -nocrypt -in gateway.key -out gateway.pkcs8.key
mv gateway.pkcs8.key gateway.key

cat > gateway.ext <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:gateway.local,DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -in gateway.csr -CA tunnel-ca.crt -CAkey tunnel-ca.key \
  -CAcreateserial -out gateway.crt -days 825 -extfile gateway.ext

# Same CA signs both for local mock simplicity: Envoy trusts tunnel-ca for
# clients; the smoke client trusts tunnel-ca for the gateway server cert.
cp tunnel-ca.crt gateway-ca.crt

rm -f gateway.csr gateway.ext tunnel-ca.srl

# Bind-mounted into the Envoy container (non-root); keep world-readable locally.
chmod 644 tunnel-ca.key gateway.key tunnel-ca.crt gateway.crt gateway-ca.crt
echo "wrote tunnel-ca.{crt,key} gateway.{crt,key} gateway-ca.crt in $DIR"
