#!/usr/bin/env bash
set -uo pipefail
BASE="${1:-http://localhost:5678}"
COOKIE_JAR=$(mktemp)

log() { echo "[bootstrap] $*" >&2; }

is_placeholder() {
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

# --- Re-authenticate fresh, right before using the cookie for anything ---
# Send BOTH the modern field name (emailOrLdapLoginId, added when LDAP
# login support was introduced) and the legacy "email" field in the same
# request -- whichever one this version's login DTO actually reads will
# be picked up, and a 500 rather than 400 on prior attempts confirms this
# backend doesn't strictly reject unrecognized fields, so this is safe.
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

# --- Create a webhook workflow, with retries ---
WF_JSON='{"name":"ci-webhook","active":false,"nodes":[
  {"id":"1","name":"Webhook","type":"n8n-nodes-base.webhook","typeVersion":1,"position":[250,300],
   "parameters":{"path":"ci-test-hook","httpMethod":"GET","responseMode":"onReceived"}},
  {"id":"2","name":"Respond","type":"n8n-nodes-base.set","typeVersion":1,"position":[450,300],
   "parameters":{"values":{"string":[{"name":"ok","value":"true"}]}}}
],"connections":{"Webhook":{"main":[[{"node":"Respond","type":"main","index":0}]]}}}'

WF_ID=""
for i in {1..10}; do
    WF_BODY_FILE=$(mktemp)
    WF_STATUS=$(curl -sk -b "$COOKIE_JAR" -X POST "$BASE/rest/workflows" \
        -H 'Content-Type: application/json' --data "$WF_JSON" \
        -o "$WF_BODY_FILE" -w '%{http_code}' 2>/dev/null)
    log "create workflow attempt $i: HTTP $WF_STATUS"

    if [[ "$WF_STATUS" == "200" ]] && jq -e . "$WF_BODY_FILE" >/dev/null 2>&1; then
        CANDIDATE_ID=$(jq -r '.data.id // empty' "$WF_BODY_FILE")
        if [[ -n "$CANDIDATE_ID" ]]; then
            WF_ID="$CANDIDATE_ID"
            break
        fi
    fi
    log "response body: $(cat "$WF_BODY_FILE" | head -c 300)"
    sleep 3
done

if [[ -z "$WF_ID" ]]; then
    log "FATAL: workflow creation never succeeded with a valid id after 10 attempts."
    exit 1
fi
log "workflow created: id=$WF_ID"

# --- Activate it (full-object PATCH, not a bare partial) ---
GET_BODY_FILE=$(mktemp)
GET_STATUS=$(curl -sk -b "$COOKIE_JAR" "$BASE/rest/workflows/$WF_ID" \
    -o "$GET_BODY_FILE" -w '%{http_code}' 2>/dev/null)
log "fetch workflow before activation: HTTP $GET_STATUS"
if [[ "$GET_STATUS" != "200" ]]; then
    log "FATAL: could not fetch workflow $WF_ID before activation (HTTP $GET_STATUS)"
    log "response body: $(cat "$GET_BODY_FILE" | head -c 300)"
    exit 1
fi

FULL_WF_JSON=$(jq -c '.data | .active = true' "$GET_BODY_FILE")

ACT_BODY_FILE=$(mktemp)
ACT_STATUS=$(curl -sk -b "$COOKIE_JAR" -X PATCH "$BASE/rest/workflows/$WF_ID" \
    -H 'Content-Type: application/json' \
    --data "$FULL_WF_JSON" \
    -o "$ACT_BODY_FILE" -w '%{http_code}' 2>/dev/null)
log "activate workflow: HTTP $ACT_STATUS"
if [[ "$ACT_STATUS" != "200" ]]; then
    log "FATAL: workflow activation failed (HTTP $ACT_STATUS)"
    log "response body: $(cat "$ACT_BODY_FILE" | head -c 500)"
    exit 1
fi

# --- Verify the webhook is ACTUALLY live before declaring bootstrap done ---
WEBHOOK_LIVE=false
for i in {1..20}; do
    WH_BODY_FILE=$(mktemp)
    WH_STATUS=$(curl -sk -o "$WH_BODY_FILE" -w '%{http_code}' "$BASE/webhook/ci-test-hook" 2>/dev/null)
    if [[ "$WH_STATUS" =~ ^2 ]] && ! grep -qi 'not registered' "$WH_BODY_FILE"; then
        WEBHOOK_LIVE=true
        log "webhook verified live after $i attempt(s) (HTTP $WH_STATUS)"
        break
    fi
    sleep 1
done

if [[ "$WEBHOOK_LIVE" != true ]]; then
    log "FATAL: webhook never became live at $BASE/webhook/ci-test-hook after 20s"
    log "last status: HTTP $WH_STATUS, body: $(cat "$WH_BODY_FILE" | head -c 300)"
    exit 1
fi

echo "$WF_ID" > /tmp/ci_workflow_id.txt
log "bootstrap complete"
