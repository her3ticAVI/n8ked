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
# (DB migrations still running), so a 404 on the very first attempt does
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

# --- Create a webhook workflow ---
WF_JSON='{"name":"ci-webhook","active":false,"nodes":[
  {"id":"1","name":"Webhook","type":"n8n-nodes-base.webhook","typeVersion":1,"position":[250,300],
   "parameters":{"path":"ci-test-hook","httpMethod":"GET","responseMode":"onReceived"}},
  {"id":"2","name":"Respond","type":"n8n-nodes-base.set","typeVersion":1,"position":[450,300],
   "parameters":{"values":{"string":[{"name":"ok","value":"true"}]}}}
],"connections":{"Webhook":{"main":[[{"node":"Respond","type":"main","index":0}]]}}}'

WF_BODY_FILE=$(mktemp)
WF_STATUS=$(curl -sk -b "$COOKIE_JAR" -X POST "$BASE/rest/workflows" \
    -H 'Content-Type: application/json' --data "$WF_JSON" \
    -o "$WF_BODY_FILE" -w '%{http_code}' 2>/dev/null)
log "create workflow: HTTP $WF_STATUS"

if [[ "$WF_STATUS" != "200" ]]; then
    log "FATAL: workflow creation failed."
    log "response body: $(cat "$WF_BODY_FILE" | head -c 500)"
    exit 1
fi

if ! jq -e . "$WF_BODY_FILE" >/dev/null 2>&1; then
    log "FATAL: workflow creation response wasn't valid JSON:"
    log "$(cat "$WF_BODY_FILE" | head -c 500)"
    exit 1
fi

WF_ID=$(jq -r '.data.id' "$WF_BODY_FILE")
if [[ -z "$WF_ID" || "$WF_ID" == "null" ]]; then
    log "FATAL: no workflow id in response: $(cat "$WF_BODY_FILE")"
    exit 1
fi
log "workflow created: id=$WF_ID"

# --- Activate it (makes the persistent /webhook/ci-test-hook path live) ---
# NOTE: the internal/session-cookie API (/rest/...) has NO dedicated
# "/activate" route -- that only exists on the Public API (/api/v1/...,
# API-key auth). On the internal API, activation is a PATCH to the
# workflow itself with {"active": true} -- the same call the editor UI
# makes when you flip the Active toggle.
ACT_BODY_FILE=$(mktemp)
ACT_STATUS=$(curl -sk -b "$COOKIE_JAR" -X PATCH "$BASE/rest/workflows/$WF_ID" \
    -H 'Content-Type: application/json' \
    --data '{"active":true}' \
    -o "$ACT_BODY_FILE" -w '%{http_code}' 2>/dev/null)
log "activate workflow: HTTP $ACT_STATUS"
if [[ "$ACT_STATUS" != "200" ]]; then
    log "FATAL: workflow activation failed (HTTP $ACT_STATUS)"
    log "response body: $(cat "$ACT_BODY_FILE" | head -c 500)"
    exit 1
fi

echo "$WF_ID" > /tmp/ci_workflow_id.txt
log "bootstrap complete"
