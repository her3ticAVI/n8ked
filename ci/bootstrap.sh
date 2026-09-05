#!/usr/bin/env bash
set -uo pipefail
BASE="${1:-http://localhost:5678}"
COOKIE_JAR=$(mktemp)

log() { echo "[bootstrap] $*" >&2; }

is_placeholder() {
    grep -qi 'starting up' "$1" 2>/dev/null
}

webhook_is_live() {
    # webhook_is_live <path> -> true/false via return code
    local wh_body_file status
    wh_body_file=$(mktemp)
    status=$(curl -sk -o "$wh_body_file" -w '%{http_code}' "$BASE/webhook/$1" 2>/dev/null)
    if [[ "$status" =~ ^2 ]] && ! grep -qi 'not registered' "$wh_body_file"; then
        return 0
    fi
    return 1
}

poll_webhook() {
    # poll_webhook <path> <attempts> -> true/false via return code
    local path="$1" attempts="$2" i
    for ((i=1; i<=attempts; i++)); do
        if webhook_is_live "$path"; then
            log "webhook verified live after $i attempt(s)"
            return 0
        fi
        sleep 1
    done
    return 1
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

# --- Re-authenticate fresh ---
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

set_active() {
    # set_active <true|false> -> exits nonzero on failure
    local desired="$1"
    local get_body_file act_body_file get_status act_status full_json
    get_body_file=$(mktemp)
    get_status=$(curl -sk -b "$COOKIE_JAR" "$BASE/rest/workflows/$WF_ID" \
        -o "$get_body_file" -w '%{http_code}' 2>/dev/null)
    [[ "$get_status" == "200" ]] || { log "FATAL: could not fetch workflow (HTTP $get_status)"; return 1; }

    full_json=$(jq -c --argjson v "$desired" '.data | .active = $v' "$get_body_file")
    act_body_file=$(mktemp)
    act_status=$(curl -sk -b "$COOKIE_JAR" -X PATCH "$BASE/rest/workflows/$WF_ID" \
        -H 'Content-Type: application/json' --data "$full_json" \
        -o "$act_body_file" -w '%{http_code}' 2>/dev/null)
    log "set active=$desired: HTTP $act_status"
    [[ "$act_status" == "200" ]] || { log "FATAL: PATCH failed (HTTP $act_status): $(cat "$act_body_file" | head -c 300)"; return 1; }
    return 0
}

# --- Activate, then verify the webhook is ACTUALLY live ---
set_active true || exit 1

if poll_webhook "ci-test-hook" 10; then
    echo "$WF_ID" > /tmp/ci_workflow_id.txt
    log "bootstrap complete"
    exit 0
fi

# --- Known n8n bug workaround #1: deactivate/reactivate cycle ---
# Confirmed in n8n-io/n8n#34038, #21614, #14646: workflows created AND
# activated purely via API can show active=true in the DB while never
# actually registering the webhook in the in-memory webhook service.
# Toggling off then on is a reported (if unofficial) workaround.
log "webhook not live after activation -- trying deactivate/reactivate cycle (known n8n bug workaround)"
set_active false || exit 1
sleep 2
set_active true || exit 1

if poll_webhook "ci-test-hook" 10; then
    echo "$WF_ID" > /tmp/ci_workflow_id.txt
    log "bootstrap complete (via deactivate/reactivate workaround)"
    exit 0
fi

# --- Known n8n bug workaround #2: restart the container ---
# Per the same GitHub issues, webhooks DO register correctly for
# workflows already active in the DB at container startup.
log "deactivate/reactivate didn't help -- restarting n8n container (known n8n bug workaround)"
if ! docker compose -f ci/docker-compose.ci.yml restart n8n; then
    log "FATAL: could not restart n8n container"
    exit 1
fi

for i in {1..30}; do
    curl -sf "$BASE/healthz" >/dev/null 2>&1 && break
    sleep 2
    if [[ $i -eq 30 ]]; then
        log "FATAL: n8n never became healthy again after restart"
        exit 1
    fi
done
log "n8n healthy again after restart"

if poll_webhook "ci-test-hook" 20; then
    echo "$WF_ID" > /tmp/ci_workflow_id.txt
    log "bootstrap complete (via container restart workaround)"
    exit 0
fi

log "FATAL: webhook still not live even after container restart -- giving up"
exit 1
