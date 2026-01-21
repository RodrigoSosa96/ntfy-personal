#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
SECRETS_FILE="${SECRETS_FILE:-provision/out/secrets.env}"

if [[ -f "$SECRETS_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "$SECRETS_FILE"
  set +a
fi

require_var() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "ERROR: falta $name (setea env o $SECRETS_FILE)" >&2
    exit 2
  fi
}

http_status() {
  # $1: curl args
  curl -sS -o /tmp/ntfy_acl_body.$$ -w "%{http_code}" "$@" || true
}

expect_status() {
  local label="$1"
  local expected="$2"
  shift 2
  local code
  code=$(http_status "$@")
  if [[ "$code" != "$expected" ]]; then
    echo "FAIL: $label (esperado $expected, obtuvo $code)"
    echo "--- body ---"
    cat /tmp/ntfy_acl_body.$$
    echo "-----------"
    exit 1
  fi
  echo "OK: $label"
}

token_for_user() {
  local user="$1"
  if [[ -n "${TOKEN_OVERRIDE:-}" ]]; then
    echo "$TOKEN_OVERRIDE"
    return 0
  fi
  docker compose exec -T ntfy ntfy token list "$user" 2>/dev/null | grep -Eo "tk_[A-Za-z0-9]+" | head -n1
}

require_var NTFY_PASS_RODRIGO
require_var NTFY_PASS_MARTIN
require_var NTFY_PASS_DOKPLOY

echo "== ACL smoketest =="
echo "Base URL: $BASE_URL"

# 1) rodrigo puede publicar en user-rodrigo-*
expect_status "rodrigo publish user-rodrigo-test" 200 \
  -u "rodrigo:$NTFY_PASS_RODRIGO" \
  -d "hola rodrigo" \
  "$BASE_URL/user-rodrigo-test"

# 2) rodrigo puede leer su topic (JSON stream)
expect_status "rodrigo read user-rodrigo-test" 200 \
  -u "rodrigo:$NTFY_PASS_RODRIGO" \
  -H "Accept: application/json" \
  "$BASE_URL/user-rodrigo-test/json?poll=1"

# 3) martin NO puede publicar en deploy-* (solo read)
expect_status "martin publish deploy-test denied" 403 \
  -u "martin:$NTFY_PASS_MARTIN" \
  -d "no deberia" \
  "$BASE_URL/deploy-test"

# 4) dokploy puede publicar en deploy-*
expect_status "dokploy publish deploy-test" 200 \
  -u "dokploy:$NTFY_PASS_DOKPLOY" \
  -d "deploy ok" \
  "$BASE_URL/deploy-test"

# 5) martin puede leer deploy-* (read-only)
expect_status "martin read deploy-test" 200 \
  -u "martin:$NTFY_PASS_MARTIN" \
  -H "Accept: application/json" \
  "$BASE_URL/deploy-test/json?poll=1"

# 6) dokploy NO puede leer deploy-*
expect_status "dokploy read deploy-test denied" 403 \
  -u "dokploy:$NTFY_PASS_DOKPLOY" \
  -H "Accept: application/json" \
  "$BASE_URL/deploy-test/json?poll=1"

# 7) token publish para dokploy (si existe)
TOKEN_DOKPLOY="${TOKEN_DOKPLOY:-$(token_for_user dokploy)}"
if [[ -n "$TOKEN_DOKPLOY" ]]; then
  expect_status "token publish deploy-test" 200 \
    -H "Authorization: Bearer $TOKEN_DOKPLOY" \
    -d "deploy via token" \
    "$BASE_URL/deploy-test"
else
  echo "WARN: no pude resolver token de dokploy; salteo prueba de token"
fi

echo "== OK =="
