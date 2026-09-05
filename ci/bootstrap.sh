#!/usr/bin/env bash
set -uo pipefail
BASE="${1:-http://localhost:5678}"
COOKIE_JAR=$(mktemp)

log() { echo "[bootstrap] $*" >&2; }

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

# --- Create the owner account, with retries ---
# /healthz can return 200 before n8n's Express routes finish registering
# (DB migrations still running), so a non-200 on the first attempt does
# NOT necessarily mean the endpoint is wrong -- retry before giving up.
OWNER_PAYLOAD='{"email":"testadmin@example.com","firstName":"CI","lastName":"Bot","password":"TestPass123!"}'
OWNER_OK=false
for i in {1..10}; do
    OWNER_BODY_FILE=$(mktemp)
    OWNER_STATUS=$(curl -sk -c "$COOKIE_JAR" -X POST "$BASE/rest/owner/setup" \
        -H 'Content-Type: application/json' \
        --data "$OWNER_PAYLOAD" \
        -o "$OWNER_BODY_FILE" -w '%{http_code}' 2>/dev/null)
    log "owner setup attempt $i: HTTP $OWNER_STATUS"
    if [[ "$OWNER_STATUS" == "200" ]]; then
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

# --- Sanity-check the session cookie actually works before using it ---
SETTINGS_STATUS=$(curl -sk -b "$COOKIE_JAR" -o /dev/null -w '%{http_code}' "$BASE/rest/login")
log "session probe (/rest/login): HTTP $SETTINGS_STATUS"

# --- Create a webhook workflow, with retries ---
# Some versions return HTTP 200 with n8n's own "n8n is starting up.
# Please wait" placeholder body while internal services are still coming
# up, even though auth routes already work. Retry until the response is
# real JSON with an id, not just a 200 status.
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

# --- Activate it ---
# A bare {"active": true} PATCH can flip the DB flag without triggering
# the webhook-registration hook on some versions -- that hook appears to
# only fire when the FULL current workflow object is resent, mirroring
# what the editor UI does when you flip the Active toggle (it always
# saves the complete current workflow state, not a partial delta). So:
# fetch the full workflow first, flip active=true on that object, then
# PATCH the whole thing back.
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
