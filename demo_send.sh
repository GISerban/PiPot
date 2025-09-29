#!/usr/bin/env bash
# demo_send.sh — testează rapid honeypot-urile HTTP, SSH și SMTP
set -euo pipefail

HOST="${1:-127.0.0.1}"

echo "=== [HTTP Honeypot Test] ==="
curl -s -X POST "http://${HOST}/api/generated" \
  -H "Content-Type: application/json" \
  -d '{"model":"llama3.1:8b","prompt":"Return JSON: {\"status\":200,\"headers\":{\"Content-Type\":\"text/plain\"},\"body\":\"Hello from HTTP honeypot\"}"}' \
  | head -n 5 || true
echo

echo "=== [SSH Honeypot Test] ==="
# trimitem doar banner negotiation (nu login complet)
echo "SSH-2.0-TestClient" | nc -w2 ${HOST} 2222 || true
echo

echo "=== [SMTP Honeypot Test] ==="
# conversație SMTP simplă cu EHLO, MAIL, RCPT, DATA, QUIT
{
  echo "EHLO test.local"
  echo "MAIL FROM:<alice@example.com>"
  echo "RCPT TO:<bob@example.com>"
  echo "DATA"
  echo "Subject: Honeypot demo"
  echo
  echo "Hello from SMTP honeypot demo!"
  echo "."
  echo "QUIT"
} | nc -w5 ${HOST} 25 || true
echo

echo "=== Done. Check ./data/meta/ for logs. ==="

