#!/usr/bin/env bash
#
# n8ked.sh — n8n unauthenticated exposure & misconfiguration auditor
#
# Goes beyond version/MFA fingerprinting: checks whether n8n's sensitive
# REST endpoints are reachable without authentication (workflows,
# credentials, users, executions, the public API, Prometheus metrics),
# scans anything that comes back exposed for hardcoded secrets (API keys,
# bearer tokens, private keys, connection strings, etc.), checks security
# headers, CORS configuration, and common accidentally-exposed config
# files (.env, .git, package.json). Everything is read-only GET traffic —
# no exploitation, no brute forcing beyond one optional user-supplied
# credential pair.
#
# Usage:
#   ./n8ked.sh <target> [options]
#   ./n8ked.sh --file targets.txt [options]
#   ./n8ked.sh --eyewitness /path/to/EyeWitness-Results [options]
#
# Options:
#   --file FILE              Scan every host in FILE (one target per line)
#   --eyewitness DIR         Pull candidate hosts from an EyeWitness results
#                            folder (open_ports.csv and/or report*.html),
#                            probe each for n8n, and audit only the hits
#   --json                   Output one JSON object per host instead of the pretty report
#   --test-cred user:pass    Try exactly one credential pair against /rest/login
#   --reveal-secrets         Print full secret values instead of masked previews
#   --nuclei                 Also run nuclei's n8n-tagged templates if installed
#   --no-color               Disable ANSI colors
#   -h, --help               Show this help
#
# Examples:
#   ./n8ked.sh http://10.0.0.5:5678
#   ./n8ked.sh 10.0.0.5:5678 --test-cred admin@example.com:changeme
#   ./n8ked.sh --file scope-hosts.txt --json > results.jsonl
#   ./n8ked.sh --eyewitness ~/engagements/acme/EyeWitness-Results
#
# Exit codes: 0 = no Critical/High findings on any target, 1 = at least
# one Critical/High finding, 2 = target(s) not identifiable as n8n.
#
set -uo pipefail

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
TARGET=""
TARGET_FILE=""
EW_DIR=""
JSON_OUT=false
TEST_CRED=""
RUN_NUCLEI=false
NO_COLOR=false
REVEAL_SECRETS=false

print_help() { sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --file) TARGET_FILE="${2:-}"; shift 2 ;;
        --eyewitness) EW_DIR="${2:-}"; shift 2 ;;
        --json) JSON_OUT=true; shift ;;
        --test-cred) TEST_CRED="${2:-}"; shift 2 ;;
        --reveal-secrets) REVEAL_SECRETS=true; shift ;;
        --nuclei) RUN_NUCLEI=true; shift ;;
        --no-color) NO_COLOR=true; shift ;;
        -h|--help) print_help; exit 0 ;;
        *)
            if [[ -z "$TARGET" ]]; then TARGET="$1"; else echo "Unexpected argument: $1" >&2; exit 1; fi
            shift ;;
    esac
done

if [[ -z "$TARGET" && -z "$TARGET_FILE" && -z "$EW_DIR" ]]; then
    print_help
    exit 1
fi

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
if [[ -t 1 && "$NO_COLOR" == false ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
    C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
    C_MAG=$'\033[35m'; C_CYN=$'\033[36m'; C_WHT=$'\033[97m'
else
    C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GRN=""; C_YEL=""
    C_MAG=""; C_CYN=""; C_WHT=""
fi

hr()      { printf "%s%s%s\n" "$C_DIM" "$(printf '─%.0s' $(seq 1 74))" "$C_RESET"; }
section() { echo; printf "%s%s┌─ %s%s\n" "$C_BOLD" "$C_CYN" "$1" "$C_RESET"; }
footer()  { printf "%s└──────────────────────────────────────────────────────────────────%s\n" "$C_CYN" "$C_RESET"; }
kv() {
    local key="$1" val="$2" color="${3:-$C_WHT}"
    printf "%s│%s  %-34s %s%s%s\n" "$C_CYN" "$C_RESET" "$key" "$color" "$val" "$C_RESET"
}

# ---------------------------------------------------------------------------
# JSON helper — prefer jq, fall back to python3
# ---------------------------------------------------------------------------
if command -v jq >/dev/null 2>&1; then
    JSON_ENGINE="jq"
elif command -v python3 >/dev/null 2>&1; then
    JSON_ENGINE="python3"
else
    echo "Error: this tool needs either 'jq' or 'python3' installed to parse JSON." >&2
    exit 1
fi
HAVE_PY=false
command -v python3 >/dev/null 2>&1 && HAVE_PY=true

jget() {
    # jget <json> <dotted.path> [default]
    local json="$1" path="$2" default="${3:-}"
    local val=""
    if [[ "$JSON_ENGINE" == "jq" ]]; then
        # Deliberately not `// empty` — jq's alternative operator treats
        # `false`/0/"" as falsy, which would silently turn real "false"
        # values (e.g. mfa.enforced=false) into the default.
        val=$(echo "$json" | jq -r "(.${path}) as \$v | if \$v == null then \"\" else (\$v|tostring) end" 2>/dev/null)
    else
        val=$(JGET_JSON="$json" python3 -c '
import json, os, sys
path, default = sys.argv[1], sys.argv[2]
try:
    data = json.loads(os.environ.get("JGET_JSON", ""))
except Exception:
    print(default); sys.exit()
cur = data
for part in path.split("."):
    if isinstance(cur, dict) and part in cur:
        cur = cur[part]
    else:
        print(default); sys.exit()
if isinstance(cur, bool):
    print(str(cur).lower())
elif cur is None:
    print(default)
else:
    print(cur)
' "$path" "$default" 2>/dev/null)
    fi
    [[ -z "$val" ]] && val="$default"
    echo "$val"
}

json_escape() {
    if [[ "$HAVE_PY" == true ]]; then
        python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'
    else
        # crude fallback
        sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g' | sed '1s/^/"/;$s/$/"/'
    fi
}

CURL="curl -sk --max-time 10"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# ---------------------------------------------------------------------------
# Secret scanning patterns (python3 only — most reliable regex engine we
# can count on being present since it's also our JSON fallback)
# ---------------------------------------------------------------------------
SECRET_SCANNER='
import re, sys

PATTERNS = [
    ("AWS Access Key ID",        r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Access Key",    r"(?i)aws(.{0,20})?secret(.{0,20})?[\"\x27]?\s*[:=]\s*[\"\x27][0-9a-zA-Z/+]{40}[\"\x27]"),
    ("Generic API key",          r"(?i)(api[_-]?key|apikey)[\"\x27]?\s*[:=]\s*[\"\x27][A-Za-z0-9_\-]{16,}[\"\x27]"),
    ("Bearer token",             r"Bearer [A-Za-z0-9\-_\.]{20,}"),
    ("JWT",                      r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{5,}"),
    ("Slack token",              r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    ("Private key block",        r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ("Generic password field",   r"(?i)\"password\"\s*:\s*\"[^\"\s]{3,}\""),
    ("Generic secret field",     r"(?i)\"(secret|token|client_secret|access_token|refresh_token)\"\s*:\s*\"[^\"\s]{3,}\""),
    ("DB connection string",     r"(?i)(mongodb|postgres(ql)?|mysql|redis)://[^\s\"\x27]{6,}"),
    ("Google API key",           r"AIza[0-9A-Za-z\-_]{35}"),
    ("GitHub token",             r"gh[pousr]_[A-Za-z0-9]{36,}"),
]

def mask(v, reveal):
    if reveal:
        return v
    if len(v) <= 8:
        return v[0] + "****"
    return v[:4] + "..." + v[-4:]

def main():
    path, label, reveal = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
    try:
        with open(path, "r", errors="ignore") as f:
            body = f.read()
    except Exception:
        return
    seen = set()
    for name, pat in PATTERNS:
        for m in re.finditer(pat, body):
            val = m.group(0)
            key = (name, val)
            if key in seen:
                continue
            seen.add(key)
            print(f"{name}|{label}|{mask(val, reveal)}")

main()
'

secret_scan_file() {
    # secret_scan_file <bodyfile> <label>
    [[ "$HAVE_PY" == true ]] || return 0
    local reveal=0
    [[ "$REVEAL_SECRETS" == true ]] && reveal=1
    python3 -c "$SECRET_SCANNER" "$1" "$2" "$reveal" 2>/dev/null
}

# Recognizes n8n's common `{"data": [...]}` / `{"data": {}}` envelope as
# empty when the inner payload has nothing in it, not just a bare [] or {}.
EMPTY_CHECKER='
import json, sys

def is_empty(v):
    if v is None:
        return True
    if isinstance(v, (list, dict)):
        if len(v) == 0:
            return True
        if isinstance(v, dict) and set(v.keys()) <= {"data", "count", "nextCursor"}:
            return is_empty(v.get("data"))
        return False
    return False

try:
    with open(sys.argv[1], "r", errors="ignore") as f:
        data = json.load(f)
except Exception:
    print("no")
    sys.exit()
print("yes" if is_empty(data) else "no")
'

is_empty_body() {
    # is_empty_body <bodyfile> -> prints "yes" or "no"
    local f="$1"
    if [[ "$HAVE_PY" == true ]]; then
        python3 -c "$EMPTY_CHECKER" "$f" 2>/dev/null || echo "no"
    else
        local b; b=$(cat "$f" 2>/dev/null | tr -d '[:space:]')
        if [[ -z "$b" || "$b" == "[]" || "$b" == "{}" || "$b" == '{"data":[]}' || "$b" == '{"data":{}}' ]]; then
            echo "yes"
        else
            echo "no"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Per-target scan
# ---------------------------------------------------------------------------
scan_target() {
    local RAW_TARGET="$1"
    local TARGET="$RAW_TARGET"
    if [[ "$TARGET" != http://* && "$TARGET" != https://* ]]; then
        TARGET="http://${TARGET}"
    fi
    TARGET="${TARGET%/}"

    local FINDINGS=()   # "SEV|message"
    local ROOT_HEADERS ROOT_STATUS SERVER_HDR ROOT_BODY_FILE
    ROOT_BODY_FILE="$TMPDIR/root.body"
    ROOT_HEADERS=$($CURL -D - -o "$ROOT_BODY_FILE" "$TARGET/" 2>/dev/null)
    ROOT_STATUS=$(echo "$ROOT_HEADERS" | head -1 | tr -d '\r')
    SERVER_HDR=$(echo "$ROOT_HEADERS" | grep -i '^server:' | head -1 | cut -d' ' -f2- | tr -d '\r')

    local SETTINGS_JSON HEALTHZ_JSON WEBHOOK_STATUS
    SETTINGS_JSON=$($CURL "$TARGET/rest/settings" 2>/dev/null)
    HEALTHZ_JSON=$($CURL "$TARGET/healthz" 2>/dev/null)
    WEBHOOK_STATUS=$($CURL -o /dev/null -w '%{http_code}' "$TARGET/webhook-test/" 2>/dev/null)

    if ! echo "$SETTINGS_JSON" | grep -q '"instanceId"'; then
        if [[ "$JSON_OUT" == true ]]; then
            echo "{\"target\":\"$TARGET\",\"error\":\"not an n8n instance (no instanceId in /rest/settings)\"}"
        else
            echo
            echo "${C_RED}✗ ${TARGET} does not look like an n8n instance (no instanceId in /rest/settings response).${C_RESET}"
        fi
        NOT_N8N_SEEN=true
        return
    fi

    vget() { jget "$SETTINGS_JSON" "data.$1" "${2:-}"; }

    local VERSION RELEASE_CHANNEL INSTANCE_ID SETTINGS_MODE AUTH_METHOD SHOW_SETUP SMTP_SETUP
    local MFA_ENABLED MFA_ENFORCED SAML_ON LDAP_ON OIDC_ON OIDC_LOGIN_URL OIDC_CB_URL
    local OAUTH1_CB OAUTH2_CB TELEMETRY_ON TELEMETRY_PROXY AUTHCOOKIE_SECURE HEALTH_STATUS
    VERSION=$(vget versionCli "unknown")
    RELEASE_CHANNEL=$(vget releaseChannel "unknown")
    INSTANCE_ID=$(vget instanceId "unknown")
    SETTINGS_MODE=$(vget settingsMode "unknown")
    AUTH_METHOD=$(vget userManagement.authenticationMethod "unknown")
    SHOW_SETUP=$(vget userManagement.showSetupOnFirstLoad "unknown")
    SMTP_SETUP=$(vget userManagement.smtpSetup "unknown")
    MFA_ENABLED=$(vget mfa.enabled "unknown")
    MFA_ENFORCED=$(vget mfa.enforced "unknown")
    SAML_ON=$(vget sso.saml.loginEnabled "unknown")
    LDAP_ON=$(vget sso.ldap.loginEnabled "unknown")
    OIDC_ON=$(vget sso.oidc.loginEnabled "unknown")
    OIDC_LOGIN_URL=$(vget sso.oidc.loginUrl "")
    OIDC_CB_URL=$(vget sso.oidc.callbackUrl "")
    OAUTH1_CB=$(vget oauthCallbackUrls.oauth1 "")
    OAUTH2_CB=$(vget oauthCallbackUrls.oauth2 "")
    TELEMETRY_ON=$(vget telemetry.enabled "unknown")
    TELEMETRY_PROXY=$(vget telemetry.config.proxy "")
    AUTHCOOKIE_SECURE=$(vget authCookie.secure "unknown")
    HEALTH_STATUS=$(jget "$HEALTHZ_JSON" "status" "unreachable")

    local INTERNAL_HOST=""
    for u in "$OAUTH2_CB" "$OAUTH1_CB" "$OIDC_LOGIN_URL" "$OIDC_CB_URL"; do
        if [[ -n "$u" && "$u" != "null" ]]; then
            h=$(echo "$u" | sed -E 's#^https?://##; s#/.*##')
            if [[ -n "$h" ]]; then INTERNAL_HOST="$h"; break; fi
        fi
    done

    # -------------------------------------------------------------------
    # Access control: unauthenticated REST/API endpoint exposure
    # -------------------------------------------------------------------
    # path | label | severity-if-exposed
    local ENDPOINTS=(
        "/rest/workflows|Workflow definitions|CRIT"
        "/rest/credentials|Stored credentials list|CRIT"
        "/api/v1/workflows|Public API - workflows (no API key)|CRIT"
        "/rest/users|User list|HIGH"
        "/rest/executions|Execution history|HIGH"
        "/rest/active-workflows|Active workflow list|HIGH"
        "/rest/owner|Owner/setup info|MED"
        "/rest/community-packages|Installed community nodes|LOW"
        "/metrics|Prometheus metrics|MED"
    )
    local EXPOSED_BODIES=()   # "file|label"
    local ENDPOINT_RESULTS=() # "path|label|verdict|status"

    for entry in "${ENDPOINTS[@]}"; do
        IFS='|' read -r ep label sev <<< "$entry"
        local bodyfile="$TMPDIR/ep_$(echo "$ep" | tr '/?&=' '____').body"
        local status
        status=$($CURL -o "$bodyfile" -w '%{http_code}' "$TARGET$ep" 2>/dev/null)
        local body
        body=$(cat "$bodyfile" 2>/dev/null)
        local verdict="PROTECTED"

        if [[ "$status" == "401" || "$status" == "403" ]]; then
            verdict="PROTECTED"
        elif [[ "$status" == "404" ]]; then
            verdict="NOT-ENABLED"
        elif [[ "$status" == "200" ]]; then
            # Guard against SPA catch-all routes returning 200 with the
            # same index.html for literally any path.
            if diff -q "$bodyfile" "$ROOT_BODY_FILE" >/dev/null 2>&1; then
                verdict="NOT-ENABLED"
            elif echo "$body" | grep -qE '"code"[[:space:]]*:[[:space:]]*(401|403)'; then
                verdict="PROTECTED"
            elif [[ -z "$body" ]] || [[ "$(is_empty_body "$bodyfile")" == "yes" ]]; then
                verdict="EMPTY"
            else
                verdict="EXPOSED"
                EXPOSED_BODIES+=("$bodyfile|$label")
            fi
        else
            verdict="OTHER($status)"
        fi

        ENDPOINT_RESULTS+=("$ep|$label|$verdict|$status")
        if [[ "$verdict" == "EXPOSED" ]]; then
            FINDINGS+=("$sev|Unauthenticated access to $ep ($label) — HTTP $status returned real data with no auth required")
        fi
    done

    # -------------------------------------------------------------------
    # Secret scan across everything that came back exposed (plus settings)
    # -------------------------------------------------------------------
    echo "$SETTINGS_JSON" > "$TMPDIR/settings.body"
    local SECRET_HITS=()
    if [[ "$HAVE_PY" == true ]]; then
        for pair in "${EXPOSED_BODIES[@]}" "$TMPDIR/settings.body|/rest/settings"; do
            IFS='|' read -r f lbl <<< "$pair"
            [[ -f "$f" ]] || continue
            while IFS= read -r line; do
                [[ -n "$line" ]] && SECRET_HITS+=("$line")
            done < <(secret_scan_file "$f" "$lbl")
        done
    fi
    for hit in "${SECRET_HITS[@]}"; do
        IFS='|' read -r stype slabel sval <<< "$hit"
        FINDINGS+=("CRIT|Hardcoded secret found — $stype in $slabel: $sval")
    done

    # -------------------------------------------------------------------
    # Security headers
    # -------------------------------------------------------------------
    local HAS_HSTS=false HAS_XFO=false HAS_XCTO=false HAS_CSP=false
    echo "$ROOT_HEADERS" | grep -qi '^strict-transport-security:' && HAS_HSTS=true
    echo "$ROOT_HEADERS" | grep -qi '^x-frame-options:' && HAS_XFO=true
    echo "$ROOT_HEADERS" | grep -qi '^x-content-type-options:' && HAS_XCTO=true
    echo "$ROOT_HEADERS" | grep -qi '^content-security-policy:' && HAS_CSP=true
    local IS_HTTPS=false
    [[ "$TARGET" == https://* ]] && IS_HTTPS=true

    if [[ "$IS_HTTPS" == false ]]; then
        FINDINGS+=("HIGH|Service reachable over plain HTTP (no TLS) at $TARGET")
    elif [[ "$HAS_HSTS" == false ]]; then
        FINDINGS+=("LOW|HSTS header missing over HTTPS")
    fi
    [[ "$HAS_XFO" == false ]] && FINDINGS+=("LOW|X-Frame-Options header missing (clickjacking hardening)")
    [[ "$HAS_XCTO" == false ]] && FINDINGS+=("LOW|X-Content-Type-Options header missing")
    [[ "$HAS_CSP" == false ]] && FINDINGS+=("LOW|Content-Security-Policy header missing")

    # -------------------------------------------------------------------
    # CORS check
    # -------------------------------------------------------------------
    local CORS_HEADERS ACAO ACAC
    CORS_HEADERS=$($CURL -D - -o /dev/null -H "Origin: https://n8ked-cors-probe.invalid" "$TARGET/rest/settings" 2>/dev/null)
    ACAO=$(echo "$CORS_HEADERS" | grep -i '^access-control-allow-origin:' | head -1 | cut -d' ' -f2- | tr -d '\r')
    ACAC=$(echo "$CORS_HEADERS" | grep -i '^access-control-allow-credentials:' | head -1 | cut -d' ' -f2- | tr -d '\r')
    local CORS_VERDICT="none"
    if [[ -n "$ACAO" ]]; then
        if [[ "$ACAO" == "https://n8ked-cors-probe.invalid" && "${ACAC,,}" == "true" ]]; then
            CORS_VERDICT="reflect-credentialed"
            FINDINGS+=("CRIT|CORS reflects arbitrary Origin with Access-Control-Allow-Credentials: true — any website can make authenticated requests on a victim's behalf")
        elif [[ "$ACAO" == "https://n8ked-cors-probe.invalid" ]]; then
            CORS_VERDICT="reflect"
            FINDINGS+=("MED|CORS reflects arbitrary Origin header (no credentials flag) — verify intent")
        elif [[ "$ACAO" == "*" ]]; then
            CORS_VERDICT="wildcard"
            FINDINGS+=("LOW|CORS Access-Control-Allow-Origin: * (no credentials observed)")
        fi
    fi

    # -------------------------------------------------------------------
    # Common accidentally-exposed files
    # -------------------------------------------------------------------
    local EXPOSE_PATHS=(/.env /.git/config /.git/HEAD /package.json /docker-compose.yml /config.json)
    local EXPOSED_FILES=()
    for p in "${EXPOSE_PATHS[@]}"; do
        local bf="$TMPDIR/file_$(echo "$p" | tr '/.' '__').body"
        local st
        st=$($CURL -o "$bf" -w '%{http_code}' "$TARGET$p" 2>/dev/null)
        if [[ "$st" == "200" ]] && ! diff -q "$bf" "$ROOT_BODY_FILE" >/dev/null 2>&1 && [[ -s "$bf" ]]; then
            EXPOSED_FILES+=("$p")
            FINDINGS+=("MED|Possible file exposure at $p (HTTP 200, distinct content — verify manually)")
        fi
    done

    # -------------------------------------------------------------------
    # Existing checks: webhook-test, credential test, nuclei
    # -------------------------------------------------------------------
    if [[ "$WEBHOOK_STATUS" =~ ^2 ]]; then
        FINDINGS+=("LOW|Webhook test endpoint responded with HTTP $WEBHOOK_STATUS (may expose triggerable automations)")
    fi
    if [[ -n "$INTERNAL_HOST" ]]; then
        FINDINGS+=("LOW|Internal/real hostname disclosed via OAuth/OIDC callback URL: $INTERNAL_HOST")
    fi
    if [[ "$MFA_ENFORCED" != "true" ]]; then
        FINDINGS+=("HIGH|MFA not enforced org-wide (enabled=$MFA_ENABLED, enforced=$MFA_ENFORCED)")
    fi
    if [[ "$SHOW_SETUP" != "false" ]]; then
        FINDINGS+=("HIGH|Setup wizard may still be open (no owner account confirmed) — potential unauthenticated admin takeover")
    fi

    local CRED_RESULT=""
    if [[ -n "$TEST_CRED" ]]; then
        local CU="${TEST_CRED%%:*}" CP="${TEST_CRED#*:}"
        local LOGIN_RESP
        LOGIN_RESP=$($CURL -X POST "$TARGET/rest/login" -H "Content-Type: application/json" \
            --data "{\"emailOrLdapLoginId\":\"${CU}\",\"password\":\"${CP}\"}" 2>/dev/null)
        if echo "$LOGIN_RESP" | grep -qE '"code"[[:space:]]*:[[:space:]]*401'; then
            CRED_RESULT="fail"
        elif echo "$LOGIN_RESP" | grep -q '"id"' && echo "$LOGIN_RESP" | grep -qi '"email"'; then
            CRED_RESULT="success"
            FINDINGS+=("CRIT|Supplied credentials ($CU) are VALID — full editor access obtained")
        else
            CRED_RESULT="unknown"
        fi
    fi

    local NUCLEI_OUT=""
    if [[ "$RUN_NUCLEI" == true ]]; then
        if command -v nuclei >/dev/null 2>&1; then
            NUCLEI_OUT=$(nuclei -u "$TARGET" -tags n8n -silent 2>/dev/null)
        else
            NUCLEI_OUT="nuclei not installed — skipped"
        fi
    fi

    # Fold nuclei matches into the same risk summary as everything else,
    # instead of leaving them in their own disconnected section. Nuclei's
    # own severity tag drives ours; multiple matchers on the same template
    # (e.g. "CVE-2026-21858:status-2", ":dsl-3", ":word-1") are the same
    # underlying finding and get collapsed to one line, not three.
    if [[ -n "$NUCLEI_OUT" && "$NUCLEI_OUT" != "nuclei not installed"* ]]; then
        local -A NUCLEI_SEEN=()
        while IFS= read -r nline; do
            [[ -z "$nline" ]] && continue
            if [[ "$nline" =~ ^\[([^\]]+)\]\ \[([^\]]+)\]\ \[([^\]]+)\]\ (.*)$ ]]; then
                local ntmpl="${BASH_REMATCH[1]}" nproto="${BASH_REMATCH[2]}" nsev="${BASH_REMATCH[3]}" nrest="${BASH_REMATCH[4]}"
                local nbase="${ntmpl%%:*}"
                local nmysev=""
                case "${nsev,,}" in
                    critical) nmysev="CRIT" ;;
                    high)     nmysev="HIGH" ;;
                    medium)   nmysev="MED" ;;
                    low)      nmysev="LOW" ;;
                    *)        nmysev="" ;;  # info/unknown - detection only, not a risk line
                esac
                if [[ -n "$nmysev" && -z "${NUCLEI_SEEN[$nbase]:-}" ]]; then
                    NUCLEI_SEEN[$nbase]=1
                    FINDINGS+=("$nmysev|nuclei: $nbase ($nproto, $nsev) — $nrest")
                fi
            fi
        done <<< "$NUCLEI_OUT"
    fi

    # -------------------------------------------------------------------
    # Output
    # -------------------------------------------------------------------
    if [[ "$JSON_OUT" == true ]]; then
        local findings_json="[]"
        if [[ "$HAVE_PY" == true && ${#FINDINGS[@]} -gt 0 ]]; then
            findings_json=$(printf '%s\n' "${FINDINGS[@]}" | python3 -c '
import json, sys
out = []
for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    sev, _, msg = line.partition("|")
    out.append({"severity": sev, "message": msg})
print(json.dumps(out))
')
        fi
        cat <<EOF
{
  "target": "$TARGET",
  "version": "$VERSION",
  "instance_id": "$INSTANCE_ID",
  "auth_method": "$AUTH_METHOD",
  "mfa_enabled": "$MFA_ENABLED",
  "mfa_enforced": "$MFA_ENFORCED",
  "internal_hostname_disclosed": "$INTERNAL_HOST",
  "credential_test": "$([ -n "$TEST_CRED" ] && echo "$CRED_RESULT" || echo "not run")",
  "cors": "$CORS_VERDICT",
  "endpoint_exposure": [$(
      for e in "${ENDPOINT_RESULTS[@]}"; do
          IFS='|' read -r ep label verdict status <<< "$e"
          printf '{"path":"%s","label":"%s","verdict":"%s","status":"%s"},' "$ep" "$label" "$verdict" "$status"
      done | sed 's/,$//'
  )],
  "findings": $findings_json
}
EOF
        return
    fi

    echo
    printf "%s%s  _   _  __ _              %s\n" "$C_BOLD" "$C_MAG" "$C_RESET"
    printf "%s%s | \\ | |/ _\` |___  _____  __| %s\n" "$C_BOLD" "$C_MAG" "$C_RESET"
    printf "%s%s |  \\| | (_| |___|/ / _ \\/ _\` |  n8ked — n8n exposure auditor%s\n" "$C_BOLD" "$C_MAG" "$C_RESET"
    printf "%s%s |_|\\_|\\__,_|   /_/\\___/\\__,_| %s\n" "$C_BOLD" "$C_MAG" "$C_RESET"
    hr
    printf "%sTarget:%s %s    %sChecked:%s %s\n" "$C_BOLD" "$C_RESET" "$TARGET" "$C_BOLD" "$C_RESET" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    hr

    section "Instance Fingerprint"
    kv "HTTP root status"     "$ROOT_STATUS"
    kv "Server header"        "${SERVER_HDR:-none disclosed}"
    kv "n8n version (CLI)"    "$VERSION" "$C_YEL"
    kv "Release channel"      "$RELEASE_CHANNEL"
    kv "Instance ID"          "$INSTANCE_ID" "$C_DIM"
    kv "/healthz"             "$HEALTH_STATUS"
    footer

    section "Authentication & SSO"
    kv "Auth method"          "$AUTH_METHOD"
    kv "Setup already done"   "$( [[ "$SHOW_SETUP" == "false" ]] && echo "yes (admin exists)" || echo "NO — first-run setup may be open" )" \
        "$( [[ "$SHOW_SETUP" == "false" ]] && echo "$C_GRN" || echo "$C_RED" )"
    kv "MFA enabled / enforced" "$MFA_ENABLED / $MFA_ENFORCED"
    kv "SAML / LDAP / OIDC"   "$SAML_ON / $LDAP_ON / $OIDC_ON"
    kv "Auth cookie 'secure'" "$AUTHCOOKIE_SECURE"
    footer

    section "Access Control — Unauthenticated Endpoint Exposure"
    for e in "${ENDPOINT_RESULTS[@]}"; do
        IFS='|' read -r ep label verdict status <<< "$e"
        case "$verdict" in
            EXPOSED)
                printf "%s│%s  %s✗ EXPOSED %-8s%s %-28s %s(%s)%s\n" "$C_CYN" "$C_RESET" "$C_RED" "[$status]" "$C_RESET" "$ep" "$C_DIM" "$label" "$C_RESET" ;;
            PROTECTED)
                printf "%s│%s  %s✓ ok %-13s%s %-28s %s(%s)%s\n" "$C_CYN" "$C_RESET" "$C_GRN" "[$status]" "$C_RESET" "$ep" "$C_DIM" "$label" "$C_RESET" ;;
            EMPTY)
                printf "%s│%s  %s✓ empty %-10s%s %-28s %s(%s)%s\n" "$C_CYN" "$C_RESET" "$C_GRN" "[$status]" "$C_RESET" "$ep" "$C_DIM" "$label" "$C_RESET" ;;
            NOT-ENABLED)
                printf "%s│%s  %s- n/a %-13s%s %-28s %s(%s)%s\n" "$C_CYN" "$C_RESET" "$C_DIM" "[$status]" "$C_RESET" "$ep" "$C_DIM" "$label" "$C_RESET" ;;
            *)
                printf "%s│%s  %s? %-16s%s %-28s %s(%s)%s\n" "$C_CYN" "$C_RESET" "$C_YEL" "[$verdict]" "$C_RESET" "$ep" "$C_DIM" "$label" "$C_RESET" ;;
        esac
    done
    footer

    if [[ ${#SECRET_HITS[@]} -gt 0 ]]; then
        section "Secret Scan"
        for hit in "${SECRET_HITS[@]}"; do
            IFS='|' read -r stype slabel sval <<< "$hit"
            printf "%s│%s  %s✗ %s%s in %s: %s%s%s\n" "$C_CYN" "$C_RESET" "$C_RED" "$stype" "$C_RESET" "$slabel" "$C_BOLD" "$sval" "$C_RESET"
        done
        [[ "$REVEAL_SECRETS" == false ]] && printf "%s│%s  %s(values masked — rerun with --reveal-secrets to see full values)%s\n" "$C_CYN" "$C_RESET" "$C_DIM" "$C_RESET"
        footer
    fi

    section "Security Headers & Transport"
    kv "TLS"                  "$( [[ "$IS_HTTPS" == true ]] && echo "https" || echo "plain HTTP" )" "$( [[ "$IS_HTTPS" == true ]] && echo "$C_GRN" || echo "$C_RED" )"
    kv "Strict-Transport-Security" "$HAS_HSTS"
    kv "X-Frame-Options"      "$HAS_XFO"
    kv "X-Content-Type-Options" "$HAS_XCTO"
    kv "Content-Security-Policy" "$HAS_CSP"
    kv "CORS (probe origin)"  "$CORS_VERDICT"
    footer

    if [[ ${#EXPOSED_FILES[@]} -gt 0 ]]; then
        section "Possible Config/File Exposure"
        for p in "${EXPOSED_FILES[@]}"; do
            printf "%s│%s  %s⚠ %s%s returned distinct HTTP 200 content — verify manually\n" "$C_CYN" "$C_RESET" "$C_YEL" "$p" "$C_RESET"
        done
        footer
    fi

    section "Other Disclosure"
    if [[ -n "$INTERNAL_HOST" ]]; then
        printf "%s│%s  %s⚠ Internal hostname disclosed:%s %s\n" "$C_CYN" "$C_RESET" "$C_YEL" "$C_RESET" "$INTERNAL_HOST"
    else
        printf "%s│%s  %s✓ No internal hostname found in OAuth/OIDC callback URLs%s\n" "$C_CYN" "$C_RESET" "$C_GRN" "$C_RESET"
    fi
    kv "Telemetry enabled"    "$TELEMETRY_ON"
    if [[ "$WEBHOOK_STATUS" =~ ^2 ]]; then
        printf "%s│%s  %s⚠ Webhook test endpoint live (HTTP %s)%s\n" "$C_CYN" "$C_RESET" "$C_YEL" "$WEBHOOK_STATUS" "$C_RESET"
    else
        printf "%s│%s  %s✓ Webhook test path not live (HTTP %s)%s\n" "$C_CYN" "$C_RESET" "$C_GRN" "${WEBHOOK_STATUS:-n/a}" "$C_RESET"
    fi
    footer

    if [[ -n "$TEST_CRED" ]]; then
        section "Credential Test"
        kv "Tested" "${TEST_CRED%%:*}"
        case "$CRED_RESULT" in
            success) printf "%s│%s  %s✗ Login SUCCEEDED — valid credentials%s\n" "$C_CYN" "$C_RESET" "$C_RED" "$C_RESET" ;;
            fail)    printf "%s│%s  %s✓ Login rejected (401)%s\n" "$C_CYN" "$C_RESET" "$C_GRN" "$C_RESET" ;;
            *)       printf "%s│%s  %s⚠ Unexpected response — review manually%s\n" "$C_CYN" "$C_RESET" "$C_YEL" "$C_RESET" ;;
        esac
        footer
    fi

    if [[ "$RUN_NUCLEI" == true ]]; then
        section "nuclei (tag: n8n)"
        if [[ -z "$NUCLEI_OUT" ]]; then
            printf "%s│%s  %s✓ No matches%s\n" "$C_CYN" "$C_RESET" "$C_GRN" "$C_RESET"
        else
            echo "$NUCLEI_OUT" | while IFS= read -r line; do
                printf "%s│%s  %s\n" "$C_CYN" "$C_RESET" "$line"
            done
        fi
        footer
    fi

    # -------------------------------------------------------------------
    # Risk summary
    # -------------------------------------------------------------------
    local n_crit=0 n_high=0 n_med=0 n_low=0
    echo
    printf "%s%sRisk Summary%s\n" "$C_BOLD" "$C_YEL" "$C_RESET"
    for f in "${FINDINGS[@]}"; do
        IFS='|' read -r sev msg <<< "$f"
        case "$sev" in
            CRIT) ((n_crit++)); printf "  %s[CRITICAL]%s %s\n" "$C_RED$C_BOLD" "$C_RESET" "$msg" ;;
        esac
    done
    for f in "${FINDINGS[@]}"; do
        IFS='|' read -r sev msg <<< "$f"
        case "$sev" in
            HIGH) ((n_high++)); printf "  %s[HIGH]%s     %s\n" "$C_RED" "$C_RESET" "$msg" ;;
        esac
    done
    for f in "${FINDINGS[@]}"; do
        IFS='|' read -r sev msg <<< "$f"
        case "$sev" in
            MED)  ((n_med++));  printf "  %s[MEDIUM]%s   %s\n" "$C_YEL" "$C_RESET" "$msg" ;;
        esac
    done
    for f in "${FINDINGS[@]}"; do
        IFS='|' read -r sev msg <<< "$f"
        case "$sev" in
            LOW)  ((n_low++));  printf "  %s[LOW]%s      %s\n" "$C_DIM" "$C_RESET" "$msg" ;;
        esac
    done
    if [[ ${#FINDINGS[@]} -eq 0 ]]; then
        printf "  %sNo issues flagged.%s\n" "$C_GRN" "$C_RESET"
    fi
    echo
    printf "%s%d critical, %d high, %d medium, %d low%s\n" "$C_BOLD" "$n_crit" "$n_high" "$n_med" "$n_low" "$C_RESET"
    echo

    if [[ $((n_crit + n_high)) -gt 0 ]]; then
        HAD_HIGH_OR_CRIT=true
    fi
}

# ---------------------------------------------------------------------------
# EyeWitness folder discovery — pulls every URL EyeWitness saw
# (open_ports.csv rows, plus any href="http(s)://..." in report*.html) and
# probes each origin's /rest/settings for an n8n instanceId before handing
# confirmed hits to scan_target. Non-n8n hosts are skipped silently rather
# than being run through the full audit.
# ---------------------------------------------------------------------------
EW_PYTHON_EXTRACTOR='
import csv, glob, os, re, sys

d = sys.argv[1]
origins = set()

csv_path = os.path.join(d, "open_ports.csv")
if os.path.isfile(csv_path):
    with open(csv_path, newline="", errors="ignore") as f:
        rows = list(csv.reader(f))
    for row in rows[1:]:
        if not row:
            continue
        url = row[0].strip()
        m = re.match(r"^(https?://[^/]+)", url)
        if m:
            origins.add(m.group(1))

for path in glob.glob(os.path.join(d, "report*.html")):
    try:
        with open(path, "r", errors="ignore") as f:
            html = f.read()
    except Exception:
        continue
    for m in re.finditer(r"href=\"(https?://[^\"/]+)[^\"]*\"", html):
        origins.add(m.group(1))

for o in sorted(origins):
    print(o)
'

discover_eyewitness_candidates() {
    # discover_eyewitness_candidates <dir> -> writes unique origins to stdout
    local dir="$1"
    if [[ "$HAVE_PY" == true ]]; then
        python3 -c "$EW_PYTHON_EXTRACTOR" "$dir" 2>/dev/null
    else
        # Fallback: open_ports.csv only (no python3 available for HTML parsing)
        if [[ -f "$dir/open_ports.csv" ]]; then
            tail -n +2 "$dir/open_ports.csv" | awk -F',' '{print $1}' | tr -d '\r' \
                | grep -oE '^https?://[^/]+'
        fi
    fi | sort -u
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
HAD_HIGH_OR_CRIT=false
NOT_N8N_SEEN=false

if [[ -n "$EW_DIR" ]]; then
    [[ -d "$EW_DIR" ]] || { echo "Error: not a directory: $EW_DIR" >&2; exit 1; }
    CAND_FILE="$TMPDIR/ew_candidates.txt"
    discover_eyewitness_candidates "$EW_DIR" > "$CAND_FILE"
    TOTAL_CAND=$(wc -l < "$CAND_FILE" | tr -d ' ')
    echo "[n8ked] Parsed EyeWitness data: $TOTAL_CAND candidate host(s). Probing for n8n..." >&2

    FOUND=0
    while IFS= read -r origin; do
        [[ -z "$origin" ]] && continue
        probe=$(curl -sk --max-time 6 "$origin/rest/settings" 2>/dev/null)
        if echo "$probe" | grep -q '"instanceId"'; then
            FOUND=$((FOUND + 1))
            echo "[n8ked]   -> n8n confirmed: $origin" >&2
            scan_target "$origin"
        fi
    done < "$CAND_FILE"

    echo "[n8ked] Done. $FOUND n8n instance(s) found out of $TOTAL_CAND candidate(s)." >&2
    if [[ "$FOUND" -eq 0 ]]; then
        NOT_N8N_SEEN=true
    fi
elif [[ -n "$TARGET_FILE" ]]; then
    [[ -f "$TARGET_FILE" ]] || { echo "Error: file not found: $TARGET_FILE" >&2; exit 1; }
    while IFS= read -r line; do
        line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [[ -z "$line" || "$line" == \#* ]] && continue
        scan_target "$line"
    done < "$TARGET_FILE"
else
    scan_target "$TARGET"
fi

if [[ "$HAD_HIGH_OR_CRIT" == true ]]; then
    exit 1
elif [[ "$NOT_N8N_SEEN" == true ]]; then
    exit 2
fi
exit 0
