#!/usr/bin/env bash
# Extra-lane Hydra provisioning (run_extra).
# hydra-cover:v2 has no sqlite driver compiled in (DSN=memory fails with
# "sqlite3 support was not compiled into the binary"), so the extra lane uses
# the battle-tested Postgres recipe from the OAuthLancer ablation lane
# (provision_pg_cover.sh), adapted: ports 4444/4445, dedicated containers,
# shared coverage dir (coverage accumulates as the union over the 3 seeds —
# run_extra is discovery-only, no per-seed statistics), mock provider on 3012.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"

NET=hydra-extra-net
PG=hydra-extra-pg
HYDRA=hydra-extra
IMG=hydra-cover:v2
PG_USER=hydra; PG_PASS=hydra; PG_DB=hydra
PUB_PORT=4444; ADM_PORT=4445
MOCK_PORT=3012
COVDIR="$HERE/results/extra/hydra_extra_cov"
ISSUER="http://127.0.0.1:${PUB_PORT}/"
SECRETS_SYSTEM=5459112d8ce081be79d3fbde1e451471363e0a80273a468373538f0dfe9849c1

mkdir -p "$COVDIR"

if docker ps --format '{{.Names}}' | grep -q "^${HYDRA}$"; then
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PUB_PORT}/.well-known/openid-configuration" 2>/dev/null || echo 000)
  if [ "$code" = "200" ]; then
    echo "[extra-hydra] already healthy"
    exit 0
  fi
fi

echo "[1/6] network + postgres"
docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET"
if ! docker ps --format '{{.Names}}' | grep -q "^${PG}$"; then
  docker rm -f "$PG" >/dev/null 2>&1 || true
  docker run -d --name "$PG" --network "$NET" \
    -e POSTGRES_USER="$PG_USER" -e POSTGRES_PASSWORD="$PG_PASS" -e POSTGRES_DB="$PG_DB" \
    postgres:16-alpine >/dev/null
fi
for i in $(seq 1 30); do
  docker exec "$PG" pg_isready -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1 && break
  sleep 1
done

DSN="postgres://${PG_USER}:${PG_PASS}@${PG}:5432/${PG_DB}?sslmode=disable"

echo "[2/6] migrate sql up"
docker run --rm --network "$NET" -e DSN="$DSN" "$IMG" migrate sql up -e -y 2>&1 | tail -3

echo "[3/6] start $HYDRA (cover build)"
docker rm -f "$HYDRA" >/dev/null 2>&1 || true
docker run -d --name "$HYDRA" --network "$NET" \
  -p "${PUB_PORT}:4444" -p "${ADM_PORT}:4445" \
  -v "$COVDIR":/cov -e GOCOVERDIR=/cov \
  -e DSN="$DSN" \
  -e "URLS_SELF_ISSUER=${ISSUER}" \
  -e URLS_LOGIN="http://127.0.0.1:${MOCK_PORT}/login" \
  -e URLS_CONSENT="http://127.0.0.1:${MOCK_PORT}/consent" \
  -e URLS_LOGOUT="http://127.0.0.1:${MOCK_PORT}/logout" \
  -e URLS_ERROR="http://127.0.0.1:${MOCK_PORT}/error" \
  -e "SECRETS_SYSTEM=${SECRETS_SYSTEM}" \
  -e SECRETS_COOKIE="${SECRETS_SYSTEM}" \
  -e OAUTH2_EXPOSE_INTERNAL_ERRORS=true \
  -e LOG_LEAK_SENSITIVE_VALUES=true \
  -e LOG_LEVEL=info \
  -e TTL_ACCESS_TOKEN=1h -e TTL_ID_TOKEN=1h -e TTL_AUTH_CODE=10m -e TTL_REFRESH_TOKEN=720h \
  "$IMG" serve all --dev >/dev/null

echo "[4/6] wait for public health"
for i in $(seq 1 40); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PUB_PORT}/.well-known/openid-configuration" 2>/dev/null || echo 000)
  [ "$code" = "200" ] && { echo "  ready"; break; }
  sleep 1
  [ "$i" -eq 40 ] && { docker logs "$HYDRA" 2>&1 | tail -30; exit 1; }
done

echo "[5/6] seed fuzz-client"
python3 - <<PYEOF
import requests
ADM = "http://127.0.0.1:${ADM_PORT}"
client = {
    "client_id": "fuzz-client", "client_secret": "fuzz-client-secret",
    "client_name": "fuzz-client",
    "redirect_uris": ["http://127.0.0.1:7777/callback"],
    "grant_types": ["authorization_code", "refresh_token", "client_credentials",
                     "urn:ietf:params:oauth:grant-type:jwt-bearer"],
    "response_types": ["code", "code id_token", "token"],
    "scope": "openid profile email offline_access",
    "token_endpoint_auth_method": "client_secret_basic",
}
try:
    r = requests.get(ADM + "/admin/clients/fuzz-client", timeout=10)
    if r.status_code == 200:
        requests.delete(ADM + "/admin/clients/fuzz-client", timeout=10)
    r = requests.post(ADM + "/admin/clients", json=client, timeout=10)
    print("  seed:", r.status_code, r.text[:120] if r.status_code >= 300 else "ok")
except Exception as e:
    print("  seed FAILED:", e)
    raise SystemExit(1)
PYEOF

echo "[6/6] mock provider on :${MOCK_PORT}"
if ! ss -ltn 2>/dev/null | grep -q ":${MOCK_PORT} "; then
  (HYDRA_ADMIN_URL="http://127.0.0.1:${ADM_PORT}" MOCK_LISTEN_PORT="${MOCK_PORT}" \
   nohup python3 "$REPO/validate/targets/hydra/poc/mock_login_provider.py" \
   > "$HERE/results/extra/mock_provider.log" 2>&1 &)
  sleep 2
fi
ss -ltn 2>/dev/null | grep -q ":${MOCK_PORT} " && echo "  mock up" || echo "  WARN: mock not listening"

echo "DONE. extra Hydra public http://127.0.0.1:${PUB_PORT} admin :${ADM_PORT} cov -> $COVDIR"
