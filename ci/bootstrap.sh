#!/usr/bin/env bash
set -euo pipefail
BASE="${1:-http://localhost:5678}"
COOKIE_JAR=$(mktemp)

# Wait for n8n to be ready
for i in {1..30}; do
    curl -sf "$BASE/healthz" >/dev/null && break
    sleep 2
    [[ $i -eq 30 ]] && { echo "n8n never became healthy"; exit 1; }
done

# Create the owner account (skips the setup wizard) -- this is the
# non-interactive equivalent of clicking through the first-run UI.
curl -sk -c "$COOKIE_JAR" -X POST "$BASE/rest/owner/setup" \
    -H 'Content-Type: application/json' \
    --data '{"email":"testadmin@example.com","firstName":"CI","lastName":"Bot","password":"TestPass123!"}' \
    -o /dev/null -w "owner setup: %{http_code}\n"

# Create a webhook workflow and activate it
WF_JSON='{"name":"ci-webhook","active":false,"nodes":[
  {"id":"1","name":"Webhook","type":"n8n-nodes-base.webhook","typeVersion":1,"position":[250,300],
   "parameters":{"path":"ci-test-hook","httpMethod":"GET","responseMode":"onReceived"}},
  {"id":"2","name":"Respond","type":"n8n-nodes-base.set","typeVersion":1,"position":[450,300],
   "parameters":{"values":{"string":[{"name":"ok","value":"true"}]}}}
],"connections":{"Webhook":{"main":[[{"node":"Respond","type":"main","index":0}]]}}}'

WF_ID=$(curl -sk -b "$COOKIE_JAR" -X POST "$BASE/rest/workflows" \
    -H 'Content-Type: application/json' --data "$WF_JSON" | jq -r '.data.id')
curl -sk -b "$COOKIE_JAR" -X POST "$BASE/rest/workflows/$WF_ID/activate" -o /dev/null -w "activate: %{http_code}\n"

echo "$WF_ID" > /tmp/ci_workflow_id.txt
echo "bootstrap complete"
