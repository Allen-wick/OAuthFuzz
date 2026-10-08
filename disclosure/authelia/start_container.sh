#!/usr/bin/env bash
# Run the STOCK authelia/authelia:latest image directly with the audit config.
# (Not via authelia_manager.py — that regenerates a single-client config on every start.)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAME="${NAME:-authelia-audit}"
IMAGE="${IMAGE:-authelia/authelia:latest}"

# fresh DB each run (audit secrets are stable, but a clean slate avoids stale sessions/codes)
docker rm -f "$NAME" >/dev/null 2>&1 || true
rm -f "$HERE"/work/* 2>/dev/null || true
mkdir -p "$HERE/work"

docker run -d --name "$NAME" \
  -p 9091:9091 \
  -v "$HERE/config:/config:ro" \
  -v "$HERE/work:/data" \
  -e TZ=UTC \
  "$IMAGE" \
  authelia --config /config/configuration.yml >/dev/null

echo "[*] container '$NAME' started; waiting for health..."
for i in $(seq 1 60); do
  s=$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:9091/api/health 2>/dev/null || echo 000)
  if [ "$s" = "200" ]; then echo "[+] healthy (${i}s)"; exit 0; fi
  if ! docker ps --format '{{.Names}}' | grep -q "^${NAME}$"; then
    echo "[!] container exited early. Logs:"; docker logs "$NAME" 2>&1 | tail -40; exit 1
  fi
  sleep 1
done
echo "[!] not healthy after 60s. Logs:"; docker logs "$NAME" 2>&1 | tail -40; exit 1
