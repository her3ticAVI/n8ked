#!/usr/bin/env bash
set -uo pipefail
BASE="${1:-http://localhost:5678}"
COOKIE_JAR=$(mktemp)

log() { echo "[bootstrap] $*" >&2; }

is_placeholder() {
    # n8n serves a "n8n is starting up. Please wait" page (HTTP 200) from
    # what appears to be a separate, minimal pre-boot server that answers
    # ANY request regardless of auth -- not the real app. Confirm we're
    # past it before trusting any response or cookie.
    grep -qi 'starting up' "$1" 2>/dev/null
}

# --- Wait for n8n to be healthy ---
for i in {1..30}; do
    curl -sf "$BASE/healthz" >/dev/null 2>&1 && break
    sleep 2
    if [[ $i -eq 30 ]]; then
        log "n8n never became healthy at $BASE/healthz"
        exit 1
    fi
done
log "n8n reports healthy"

# --- Wait until the REAL app (not the placeholder) is serving requests ---
REAL_APP_UP=false
for i in {1..40}; do
    PROBE_FILE=$(mktemp)
    curl -sk -o "$PROBE_FILE" "$BASE/rest/settings" 2>/dev/null
    if ! is_placeholder "$PROBE_FILE"; then
        REAL_APP_UP=true
        log "real app confirmed up after $i probe(s)"
        break
    fi
    sleep 2
done
if [[ "$REAL_APP_UP" != true ]]; then
    log "FATAL: still seeing the startup placeholder after 80s"
    exit 1
fi

# --- Create the owner account, with retries ---
# /healthz and /rest/settings can both respond before the owner-setup
# route finishes registering (DB migrations still running), so a non-200
# on the first attempt does not necessarily mean the endpoint is wrong.
OWNER_PAYLOAD='{"email":"testadmin@example.com","firstName":"CI","lastName":"Bot","password":"TestPass123!"}'
OWNER_OK=false
for i in {1..10}; do
    OWNER_BODY_FILE=$(mktemp)
    OWNER_STATUS=$(curl -sk -c "$COOKIE_JAR" -X POST "$BASE/rest/owner/setup" \
        -H 'Content-Type: application/json' \
        --data "$OWNER_PAYLOAD" \
        -o "$OWNER_BODY_FILE" -w '%{http_code}' 2>/dev/null)
    log "owner setup attempt $i: HTTP $OWNER_STATUS"
    if [[ "$OWNER_STATUS" == "200" ]] && ! is_placeholder "$OWNER_BODY_FILE"; then
        OWNER_OK=true
        break
    fi
    log "response body: $(cat "$OWNER_BODY_FILE" | head -c 500)"
    sleep 3
done

if [[ "$OWNER_OK" != true ]]; then
    log "FATAL: owner setup never succeeded after 10 attempts."
    exit 1
fi
log "owner account created"

# --- Re-authenticate fresh, right before declaring bootstrap done ---
# Send both the modern field name (emailOrLdapLoginId, added when LDAP
# login support was introduced) and the legacy "email" field in the same
# request -- whichever one this version's login DTO actually reads will
# be picked up.
LOGIN_BODY_FILE=$(mktemp)
LOGIN_STATUS=$(curl -sk -c "$COOKIE_JAR" -X POST "$BASE/rest/login" \
    -H 'Content-Type: application/json' \
    --data '{"email":"testadmin@example.com","emailOrLdapLoginId":"testadmin@example.com","password":"TestPass123!"}' \
    -o "$LOGIN_BODY_FILE" -w '%{http_code}' 2>/dev/null)
log "fresh login: HTTP $LOGIN_STATUS"
if [[ "$LOGIN_STATUS" != "200" ]]; then
    log "FATAL: fresh login failed (HTTP $LOGIN_STATUS)"
    log "response body: $(cat "$LOGIN_BODY_FILE" | head -c 500)"
    exit 1
fi
log "fresh session established"

log "bootstrap complete"
