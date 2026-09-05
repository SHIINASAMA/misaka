#!/usr/bin/env bash
# Durable Object SQL behaviour tests for the Cloudflare Gateway, driven against
# the real Worker under `wrangler dev --local` (miniflare). These cover the DO
# SQL specifics that the native gateway-verify G01-G10 cannot: TTL refresh on a
# same-sequence re-announce, announce->peers visibility, and peers replay.
#
# Run from anywhere; assumes repo layout gateway/cloudflare/tests/do-sql.sh.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
GW="$HERE/.."
PORT=8799
BASE="http://127.0.0.1:$PORT"

NETWORK_ID="03030303-0303-0303-0303-030303030303"
AUTH_SECRET="0101010101010101010101010101010101010101010101010101010101010101"
SISTER_SECRET="0202020202020202020202020202020202020202020202020202020202020202"
SISTER_ID=10001
# Tiny TTL so expiry/renewal is observable in seconds.
TTL=4

SIGN="$REPO/target/debug/examples/sign_request"
fails=0

note() { echo "[do-sql] $*"; }
fail() { echo "[do-sql] FAIL: $*"; fails=$((fails+1)); }

post() { # post <path> <json-file-or-- > ; echoes status, writes body to /tmp/do_body
  local path="$1" body="$2"
  curl -s -o /tmp/do_body -w "%{http_code}" \
    -X POST "$BASE$path" -H 'content-type: application/json' --data "$body"
}

# Build the signer and resolve the authority public key.
( cd "$REPO" && cargo build -q -p misaka-gatewayd --example sign_request ) || { echo "sign build failed"; exit 2; }
AUTH_PUB="$("$SIGN" authority-pub "$AUTH_SECRET")"

# Start the Worker with a short record TTL. `wrangler dev --local` persists DO
# state (`.wrangler/state`) across runs; wipe it so nonces/peers start fresh.
rm -rf "$GW/.wrangler"
( cd "$GW" && npx wrangler dev --local --port "$PORT" \
    --var "NETWORK_ID:$NETWORK_ID" \
    --var "NETWORK_AUTHORITY_PUBLIC_KEY:$AUTH_PUB" \
    --var "GATEWAY_RECORD_TTL_SECS:$TTL" >/tmp/do_wrangler.log 2>&1 ) &
WRANGLER=$!
cleanup() { kill "$WRANGLER" 2>/dev/null; pkill -f "wrangler dev" 2>/dev/null; pkill -f workerd 2>/dev/null; }
trap cleanup EXIT

# Wait for readiness.
for _ in $(seq 1 60); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/.well-known/misaka")" = "200" ] && break
  sleep 1
done

announce() { "$SIGN" announce "$NETWORK_ID" "$AUTH_SECRET" "$SISTER_SECRET" "$SISTER_ID" "$1" 99999; }
peers()    { "$SIGN" peers    "$NETWORK_ID" "$AUTH_SECRET" "$SISTER_SECRET" "$SISTER_ID" "$1" 99999; }

# --- Test 1: announce then peers reads it back ---
code="$(post /v1/announce "$(announce 00000000000000000000000000000001)")"
[ "$code" = 204 ] || fail "announce #1 expected 204, got $code"
code="$(post /v1/peers "$(peers 0000000000000000000000000000000a)")"
[ "$code" = 200 ] || fail "peers expected 200, got $code"
grep -q "\"sister_id\":$SISTER_ID" /tmp/do_body || fail "peers did not return announced record"
[ $fails -eq 0 ] && note "test1 announce->peers: ok"

# --- Test 2: peers replay rejected (same nonce) ---
code="$(post /v1/peers "$(peers 0000000000000000000000000000000a)")"
[ "$code" = 401 ] || fail "peers replay expected 401, got $code"
note "test2 peers replay: got $code"

# --- Test 3: same-sequence re-announce refreshes the TTL ---
# Test 1's record (sequence 1) expires ~TTL after its announce. Re-announce the
# SAME sequence (a Sister re-publishing its unchanged locator) must renew it, so
# it is still visible past the original expiry but before the renewed one.
sleep $((TTL - 1))
code="$(post /v1/announce "$(announce 00000000000000000000000000000002)")"
[ "$code" = 204 ] || fail "re-announce expected 204, got $code"
sleep $((TTL - 1))
code="$(post /v1/peers "$(peers 0000000000000000000000000000000b)")"
grep -q "\"sister_id\":$SISTER_ID" /tmp/do_body \
  || fail "same-sequence re-announce did not refresh TTL (record gone)"
note "test3 same-sequence TTL refresh: peers now [$(grep -o "\"sister_id\":[0-9]*" /tmp/do_body | tr '\n' ' ')]"

# --- Control: without renewal, the record does lapse ---
sleep $((TTL + 1))
code="$(post /v1/peers "$(peers 0000000000000000000000000000000c)")"
grep -q "\"sister_id\":$SISTER_ID" /tmp/do_body \
  && fail "record still present after its renewed TTL elapsed"
note "control TTL expiry: got [$(cat /tmp/do_body | grep -o "\"sister_id\":[0-9]*" | tr '\n' ' ')]"

if [ "$fails" -eq 0 ]; then note "ALL DO SQL TESTS PASSED"; exit 0; else note "$fails test(s) failed"; exit 1; fi
