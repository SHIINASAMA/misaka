#!/usr/bin/env bash
# Durable Object SQL behaviour tests for the Cloudflare Gateway, driven against
# the real Worker under `wrangler dev --local` (miniflare). These cover DO SQL
# specifics the native gateway-verify G01-G10 cannot:
#   A. nonce-only GC: a /v1/peers call with an empty directory still arms the
#      alarm off the nonce expiry, so spent nonces are collected and reusable;
#   1. announce -> peers visibility;
#   2. peers replay rejected;
#   3. SAME-sequence re-announce refreshes the record's TTL (not a higher seq);
#   control: without renewal the record lapses.
#
# Run from anywhere; assumes repo layout gateway/cloudflare/tests/do-sql.sh.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
GW="$HERE/.."
PORT=8899
BASE="http://127.0.0.1:$PORT"

NETWORK_ID="03030303-0303-0303-0303-030303030303"
AUTH_SECRET="0101010101010101010101010101010101010101010101010101010101010101"
SISTER_SECRET="0202020202020202020202020202020202020202020202020202020202020202"
SISTER_ID=10001
# Fixed PeerRecord sequence reused across announces -> genuine renewal test.
SEQ=12345
# Tiny TTLs so expiry/renewal/GC are observable in seconds.
TTL=4        # GATEWAY_RECORD_TTL_SECS
NTTL=3       # GATEWAY_NONCE_TTL_SECS

SIGN="$REPO/target/debug/examples/sign_request"
fails=0

note() { echo "[do-sql] $*"; }
fail() { echo "[do-sql] FAIL: $*"; fails=$((fails+1)); }

# 16-byte nonce as 32 hex chars from a small integer (avoids length mistakes).
hex16() { printf '%032x' "$1"; }
post() { # post <path> <body-json> ; echoes status, writes body to /tmp/do_body
  curl -s -o /tmp/do_body -w "%{http_code}" \
    -X POST "$BASE$1" -H 'content-type: application/json' --data "$2"
}

# Build the signer and resolve the authority public key.
( cd "$REPO" && cargo build -q -p misaka-gatewayd --example sign_request ) || { echo "sign build failed"; exit 2; }
AUTH_PUB="$("$SIGN" authority-pub "$AUTH_SECRET")"

# Start the Worker with short TTLs. `wrangler dev --local` persists DO state
# (`.wrangler/state`) across runs; wipe it so nonces/peers start empty.
rm -rf "$GW/.wrangler"
# A prior CI step may leave workerd bound to a port; clear strays first.
pkill -f "wrangler dev" 2>/dev/null; pkill -f workerd 2>/dev/null; sleep 1
( cd "$GW" && npx wrangler dev --local --port "$PORT" \
    --var "NETWORK_ID:$NETWORK_ID" \
    --var "NETWORK_AUTHORITY_PUBLIC_KEY:$AUTH_PUB" \
    --var "GATEWAY_RECORD_TTL_SECS:$TTL" \
    --var "GATEWAY_NONCE_TTL_SECS:$NTTL" >/tmp/do_wrangler.log 2>&1 ) &
WRANGLER=$!
cleanup() { kill "$WRANGLER" 2>/dev/null; pkill -f "wrangler dev" 2>/dev/null; pkill -f workerd 2>/dev/null; }
trap cleanup EXIT

# Wait for readiness.
for _ in $(seq 1 60); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/.well-known/misaka")" = "200" ] && break
  sleep 1
done

announce() { "$SIGN" announce "$NETWORK_ID" "$AUTH_SECRET" "$SISTER_SECRET" "$SISTER_ID" "$(hex16 "$1")" 99999 "$SEQ"; }
peers()    { "$SIGN" peers    "$NETWORK_ID" "$AUTH_SECRET" "$SISTER_SECRET" "$SISTER_ID" "$(hex16 "$1")" 99999; }

# --- Test A: nonce-only GC with an empty directory (runs before any announce) ---
# peers writes a nonce row but there are no peer rows; the alarm must still be
# armed off the nonce expiry, delete it, and let the SAME nonce be fresh again.
code="$(post /v1/peers "$(peers 1)")";    [ "$code" = 200 ] || fail "nonce-GC: first peers expected 200, got $code"
code="$(post /v1/peers "$(peers 1)")";   [ "$code" = 401 ] || fail "nonce-GC: replay before expiry expected 401, got $code"
sleep $((NTTL + 2))
code="$(post /v1/peers "$(peers 1)")";   [ "$code" = 200 ] || fail "nonce-GC: nonce not collected after TTL (expected 200, got $code)"
note "testA nonce-only GC: first=200 replay=401 after-expiry=200 -> ok"

# --- Test 1: announce then peers reads it back ---
code="$(post /v1/announce "$(announce 100)")"
[ "$code" = 204 ] || fail "announce #1 expected 204, got $code"
code="$(post /v1/peers "$(peers 101)")"
[ "$code" = 200 ] || fail "peers expected 200, got $code"
grep -q "\"sister_id\":$SISTER_ID" /tmp/do_body || fail "peers did not return announced record"
note "test1 announce->peers: ok"

# --- Test 2: peers replay rejected (same nonce) ---
code="$(post /v1/peers "$(peers 101)")"
[ "$code" = 401 ] || fail "peers replay expected 401, got $code"
note "test2 peers replay: $code"

# --- Test 3: SAME-sequence re-announce refreshes the record's TTL ---
# The record (sequence $SEQ) was announced in Test 1 and expires ~TTL later.
# Re-announce the identical sequence (same record contents, fresh auth nonce):
# the directory must refresh last_seen/expires_at, not replace or drop.
sleep $((TTL - 1))
code="$(post /v1/announce "$(announce 102)")"
[ "$code" = 204 ] || fail "re-announce expected 204, got $code"
sleep $((TTL - 1))
code="$(post /v1/peers "$(peers 103)")"
grep -q "\"sister_id\":$SISTER_ID" /tmp/do_body \
  || fail "same-sequence re-announce did not refresh TTL (record gone)"
note "test3 same-sequence TTL refresh: present after > original TTL"

# --- Control: without renewal, the record does lapse ---
sleep $((TTL + 1))
code="$(post /v1/peers "$(peers 104)")"
grep -q "\"sister_id\":$SISTER_ID" /tmp/do_body \
  && fail "record still present after its renewed TTL elapsed"
note "control TTL expiry: record lapsed"

if [ "$fails" -eq 0 ]; then note "ALL DO SQL TESTS PASSED"; exit 0; else note "$fails test(s) failed"; exit 1; fi
