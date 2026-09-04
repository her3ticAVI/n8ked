#!/usr/bin/env bash
#
# n8ked.sh — n8n unauthenticated exposure & misconfiguration auditor
#            (+ authenticated post-session checks via the `auth` subcommand)
#
# Usage:
#   ./n8ked.sh <target> [options]                    # unauthenticated scan
#   ./n8ked.sh --file targets.txt [options]
#   ./n8ked.sh --eyewitness /path/to/EyeWitness-Results [options]
#   ./n8ked.sh auth <target> [options]               # authenticated checks
#
# --- Scan mode options -------------------------------------------------
#   --file FILE              Scan every host in FILE (one target per line)
#   --eyewitness DIR         Pull candidate hosts from an EyeWitness folder,
#                            probe each for n8n, and audit only the hits
#   --json                   Output one JSONL object per host
#   --csv-out FILE           Append one CSV row per finding to FILE
#   --test-cred user:pass    Try exactly one credential pair against /rest/login
#   --userpass FILE          Try every "user:pass" line in FILE against /rest/login
#   --brute-delay SECONDS    Delay between --userpass attempts (default: 1)
#   --no-stop-on-success     Keep testing remaining pairs after a valid hit
#   --check-lockout          Probe /rest/login for rate-limiting/lockout
#   --webhook-brute FILE     Try every path in FILE against the webhook base
#   --webhook-methods LIST   HTTP methods to try per path (default: GET,POST)
#   --webhook-delay SECONDS  Delay between --webhook-brute attempts (default: 0.3)
#   --include-test-webhooks  Also try /webhook-test/ in addition to /webhook/
#   --save-cookies [FILE]    On a successful --test-cred/--userpass hit, save
#                            the resulting session cookie for later use with
#                            `auth`. Defaults to $N8KED_COOKIE if set, else
#                            ~/.n8ked/session.cookie — same slot `auth` reads
#                            from automatically. Off by default; the cookie
#                            file is tagged with the target it was captured
#                            against.
#   --reveal-secrets         Print full secret values instead of masked previews
#   --nuclei                 Also run nuclei's n8n-tagged templates
#   --poc                    Check detected version against known n8n CVEs
#   --no-color               Disable ANSI colors
#   -h, --help               Show this help
#
# --- `auth` subcommand ---------------------------------------------------
# Runs authenticated, read-only post-session checks using either a fresh
# login or a previously saved session cookie. See `./n8ked.sh auth --help`.
#
#   ./n8ked.sh auth 10.0.0.5:5678
#   ./n8ked.sh auth 10.0.0.5:5678 --test-cred admin@example.com:changeme --save-cookies
#   ./n8ked.sh auth 10.0.0.5:5678 --cookie-file ./mysession.cookie
#   ./n8ked.sh auth 10.0.0.5:5678 --export-workflows ./loot --reveal-secrets
#
# Exit codes: 0 = no Critical/High findings, 1 = at least one Critical/High
# finding, 2 = target(s) not identifiable as n8n (scan mode only).
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
SAVE_COOKIES=false
SAVE_COOKIES_PATH=""

AUTH_MODE=false
AUTH_ARGS=()

print_help() {
    cat <<'HELPEOF'
n8ked.sh — n8n unauthenticated exposure & misconfiguration auditor
           (+ authenticated post-session checks via the `auth` subcommand)

Usage:
  ./n8ked.sh <target> [options]
  ./n8ked.sh --file targets.txt [options]
  ./n8ked.sh --eyewitness /path/to/EyeWitness-Results [options]
  ./n8ked.sh auth <target> [options]        (see `./n8ked.sh auth --help`)

Scan mode options:
  --file FILE              Scan every host in FILE (one target per line)
  --eyewitness DIR         Pull candidate hosts from an EyeWitness folder
  --json                   Output one JSONL object per host
  --csv-out FILE           Append one CSV row per finding to FILE
  --test-cred user:pass    Try exactly one credential pair against /rest/login
  --userpass FILE          Try every "user:pass" line in FILE against /rest/login
  --brute-delay SECONDS    Delay between --userpass attempts (default: 1)
  --no-stop-on-success     Keep testing remaining pairs after a valid hit
  --check-lockout          Probe /rest/login for rate-limiting/lockout
  --webhook-brute FILE     Try every path in FILE against the webhook base
  --webhook-methods LIST   HTTP methods to try per path (default: GET,POST)
  --webhook-delay SECONDS  Delay between --webhook-brute attempts (default: 0.3)
  --include-test-webhooks  Also try /webhook-test/ in addition to /webhook/
  --save-cookies [FILE]    On a successful --test-cred/--userpass hit, save
                           the session cookie for later use with `auth`.
                           Defaults to $N8KED_COOKIE or ~/.n8ked/session.cookie.
  --reveal-secrets         Print full secret values instead of masked previews
  --nuclei                 Also run nuclei's n8n-tagged templates
  --poc                    Check detected version against known n8n CVEs
  --no-color               Disable ANSI colors
  -h, --help               Show this help

Subcommand:
  auth <target> [options]  Authenticated post-session checks. Run
                           `./n8ked.sh auth --help` for its options.

Exit codes: 0 = no Critical/High findings, 1 = at least one Critical/High
finding, 2 = target(s) not identifiable as n8n (scan mode only).
HELPEOF
}

# Detect --no-color regardless of mode (scan vs `auth`), before colors are
# configured below, so it applies no matter where in the arg list it appears.
for _pre_a in "$@"; do
    [[ "$_pre_a" == "--no-color" ]] && NO_COLOR=true
done

# ---------------------------------------------------------------------------
# Subcommand dispatch — `auth` gets its own argument grammar (see auth_main
# further down) and is never treated as a scan target. Detected here, before
# the normal scan-mode arg loop, so "auth" can't be mistaken for a hostname.
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "auth" ]]; then
    AUTH_MODE=true
    shift
    AUTH_ARGS=("$@")
else
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
            --save-cookies)
                SAVE_COOKIES=true
                # Optional path argument — only consume $2 if it doesn't look
                # like another flag, so `--save-cookies --nuclei` still works.
                if [[ -n "${2:-}" && "${2:0:2}" != "--" ]]; then
                    SAVE_COOKIES_PATH="$2"; shift 2
                else
                    shift
                fi
                ;;
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
fi

if [[ "$AUTH_MODE" == false ]]; then
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

CURL="curl -skL --post301 --post302 --post303 --max-time 10"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# ---------------------------------------------------------------------------
# Secret scanning patterns (python3 only)
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
    [[ "$HAVE_PY" == true ]] || return 0
    python3 -c "$SENTRY_VERSION_EXTRACTOR" "$1" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Session cookie helpers — used by scan mode's --save-cookies and by the
# `auth` subcommand's session resolution. One generic slot by default
# (like KRB5CCNAME for a Kerberos ccache): $N8KED_COOKIE if set, else
# ~/.n8ked/session.cookie. Every saved jar gets a sidecar ".meta" file
# recording which target it was captured against, so `auth` can warn (and
# refuse, unless --force) if the file doesn't match the target it's asked
# to run against.
# ---------------------------------------------------------------------------
resolve_cookie_path() {
    if [[ -n "$SAVE_COOKIES_PATH" ]]; then
        echo "$SAVE_COOKIES_PATH"
    elif [[ -n "${N8KED_COOKIE:-}" ]]; then
        echo "$N8KED_COOKIE"
    else
        echo "$HOME/.n8ked/session.cookie"
    fi
}

save_cookie_jar() {
    # save_cookie_jar <jar_src> <target> <dest>
    local jar_src="$1" target="$2" dest="$3"
    [[ -s "$jar_src" ]] || return 1
    mkdir -p "$(dirname "$dest")" 2>/dev/null
    cp "$jar_src" "$dest" 2>/dev/null || return 1
    chmod 600 "$dest" 2>/dev/null
    {
        echo "TARGET=$target"
        echo "SAVED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "${dest}.meta"
    chmod 600 "${dest}.meta" 2>/dev/null
}

check_cookie_target_match() {
    # check_cookie_target_match <meta_file> <target> -> match | mismatch:<saved> | unknown
    local meta="$1" target="$2"
    [[ -f "$meta" ]] || { echo "unknown"; return; }
    local saved_target
    saved_target=$(grep '^TARGET=' "$meta" 2>/dev/null | head -1 | cut -d'=' -f2-)
    if [[ -z "$saved_target" ]]; then
        echo "unknown"
    elif [[ "$saved_target" == "$target" ]]; then
        echo "match"
    else
        echo "mismatch:$saved_target"
    fi
}

# n8n_try_login <target> <user> <pass> [jar] -> prints "success" | "fail" | "unknown"
# If <jar> is given, curl's cookie jar is written there on this request —
# used by scan mode to hand a successful session off to --save-cookies, and
# by `auth --test-cred` to get a fresh session directly.
n8n_try_login() {
    local tgt="$1" cu="$2" cp="$3" jar="${4:-}"
    local jar_args=()
    [[ -n "$jar" ]] && jar_args=(-c "$jar")
    local resp
    resp=$($CURL "${jar_args[@]}" -X POST "$tgt/rest/login" -H "Content-Type: application/json" \
        --data "{\"emailOrLdapLoginId\":\"${cu}\",\"password\":\"${cp}\"}" 2>/dev/null)
    if echo "$resp" | grep -qE '"code"[[:space:]]*:[[:space:]]*401'; then
        echo "fail"
    elif echo "$resp" | grep -q '"id"' && echo "$resp" | grep -qi '"email"'; then
        echo "success"
    else
        echo "unknown"
    fi
}

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
# Known-CVE proof-of-concept database (used by --poc, and cross-referenced
# by `auth --check-permissions`)
# ---------------------------------------------------------------------------
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
    if [[ "$1" =~ ^[0-9.]+$ ]]; then
        awk -v c="$1" 'BEGIN{ if (c>=9) print "CRIT"; else if (c>=7) print "HIGH"; else if (c>=4) print "MED"; else print "LOW"; }'
    else
        echo "HIGH"
    fi
}
cve_src_label() {
    case "$1" in
        nuclei)  echo "nuclei — actively probed & confirmed against this target" ;;
        version) echo "version range — NOT actively confirmed, verify manually" ;;
        *)       echo "$1" ;;
    esac
}
wrap_flat() {
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

declare -a CVE_DB_ID=() CVE_DB_NAME=() CVE_DB_MINVER=() CVE_DB_MAXVER=() CVE_DB_AUTH=() CVE_DB_CVSS=() CVE_DB_NOTE=() CVE_DB_CMD=()
add_cve_row() {
    CVE_DB_ID+=("$1"); CVE_DB_NAME+=("$2"); CVE_DB_MINVER+=("$3"); CVE_DB_MAXVER+=("$4")
    CVE_DB_AUTH+=("$5"); CVE_DB_CVSS+=("$6"); CVE_DB_NOTE+=("$7"); CVE_DB_CMD+=("$8")
}
add_cve_row "CVE-2025-68613" \
    "n8n expression-sandbox escape -> authenticated RCE" \
    "0.211.0" "1.120.4" "authenticated" "9.9" \
    "Requires an authenticated session or API key (any role that can create/edit workflows). Publicly detailed by SecureLayer7." \
    "# See the auth expression-sandbox writeup — requires an authenticated session with workflow create/edit rights."
add_cve_row "CVE-2026-21858" \
    "\"Ni8mare\" — unauthenticated arbitrary file read -> RCE chain" \
    "1.65.0" "1.121.0" "unauthenticated*" "10.0" \
    "Requires a public-facing Form/Webhook workflow with a file-upload field. Public PoC tool: Chocapikk/CVE-2026-21858 on GitHub." \
    "git clone https://github.com/Chocapikk/CVE-2026-21858.git && cd CVE-2026-21858"
add_cve_row "CVE-2026-1470" \
    "Expression-sandbox bypass via decoy constructor in a 'with' statement -> authenticated RCE" \
    "0.0.0" "1.123.17" "authenticated*" "9.9" \
    "Requires workflow create/edit permission. No independently-confirmed working payload string as of this writing." \
    "# No confirmed public PoC payload — see SonicWall's CVE-2026-1470 writeup."

# ---------------------------------------------------------------------------
# Helpers shared by `auth` mode
# ---------------------------------------------------------------------------
COUNT_EXTRACTOR='
import json, sys
def count(v):
    if isinstance(v, list):
        return len(v)
    if isinstance(v, dict):
        if "data" in v:
            return count(v["data"])
        if "count" in v and isinstance(v["count"], int):
            return v["count"]
        return len(v)
    return 0
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except Exception:
    print(-1)
    sys.exit()
print(count(data))
'
count_json_items() {
    [[ "$HAVE_PY" == true ]] || { echo -1; return; }
    python3 -c "$COUNT_EXTRACTOR" "$1" 2>/dev/null || echo -1
}

WORKFLOW_CRED_REF_EXTRACTOR='
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except Exception:
    sys.exit()
nodes = data.get("nodes", []) if isinstance(data, dict) else []
for n in nodes:
    creds = n.get("credentials", {})
    if not isinstance(creds, dict):
        continue
    for ctype, cval in creds.items():
        cname = cval.get("name", "?") if isinstance(cval, dict) else str(cval)
        print(f"{n.get(\"name\",\"?\")}|{n.get(\"type\",\"?\")}|{ctype}|{cname}")
'

# ===========================================================================
# `auth` subcommand
# ===========================================================================
auth_print_help() {
    cat <<'AUTHEOF'
n8ked.sh auth <target> [options]

Uses a previously captured n8n session (or fresh credentials given right
here) to run authenticated, read-only post-session checks against an n8n
instance you already have valid credentials for.

Session source (pick one; if none is given, falls back to the cookie file
described below):
  --test-cred user:pass    Log in fresh right now and use that session
                            (no saved cookie file required)
  --cookie-file FILE       Use this specific cookie jar instead of the
                            default/env-configured one

If neither is given, the session comes from $N8KED_COOKIE if that's set,
or ~/.n8ked/session.cookie otherwise — the same slot scan mode's
--save-cookies writes to. One generic slot, used automatically unless
told otherwise (the same pattern KRB5CCNAME uses for a Kerberos ccache).

Options:
  --save-cookies           With --test-cred, also persist the resulting
                            session to the slot above
  --force                  Proceed even if the cookie file's saved target
                            doesn't match the target given on this run
  --enumerate              Re-check sensitive endpoints authenticated and
                            report real counts (default if no feature flag
                            below is given)
  --list-credentials       List stored credential names/types (values stay
                            encrypted at rest — not retrievable even
                            authenticated)
  --check-permissions      Look up this account's role and whether it can
                            create/edit workflows or mint a Public API key
  --export-workflows DIR   Pull every workflow's full JSON to DIR and scan
                            it for hardcoded secrets and credential
                            references
  --reveal-secrets         Print full secret values instead of masked
  --no-color               Disable ANSI colors
  -h, --help               Show this help

Examples:
  ./n8ked.sh auth 10.0.0.5:5678
  ./n8ked.sh auth 10.0.0.5:5678 --test-cred admin@example.com:changeme --save-cookies
  ./n8ked.sh auth 10.0.0.5:5678 --export-workflows ./loot --reveal-secrets

Everything here is read-only against the target (GET requests reusing the
existing session) except the one-time login when --test-cred is given.
Nothing here creates, edits, or runs a workflow, and no exploitation is
attempted — this only enumerates what the compromised session can see.
AUTHEOF
}

auth_feature_enumerate() {
    local tgt="$1" jar="$2"
    local -n findings_ref="$3"

    section "Authenticated Enumeration"
    local -A EP_BODY=()
    local -a EPS=(
        "/rest/workflows|Workflows"
        "/rest/executions|Executions"
        "/rest/users|Users"
        "/rest/credentials|Credentials"
        "/rest/active-workflows|Active workflows"
    )
    local entry ep label bf status count
    for entry in "${EPS[@]}"; do
        IFS='|' read -r ep label <<< "$entry"
        bf="$TMPDIR/auth_enum_$(echo "$ep" | tr '/?&=' '____').body"
        status=$($CURL -b "$jar" -o "$bf" -w '%{http_code}' "$tgt$ep" 2>/dev/null)
        EP_BODY["$ep"]="$bf"
        if [[ "$status" == "200" ]]; then
            count=$(count_json_items "$bf")
            [[ "$count" == "-1" ]] && count="unknown"
            kv "$label" "$count"
        else
            kv "$label" "HTTP $status"
        fi
    done
    footer

    local cred_count
    cred_count=$(count_json_items "${EP_BODY[/rest/credentials]}" 2>/dev/null)
    if [[ "$cred_count" =~ ^[0-9]+$ && "$cred_count" -gt 0 ]]; then
        findings_ref+=("MED|auth-enum|Authenticated session confirms $cred_count stored credential(s) exist on this instance")
    fi

    local user_count
    user_count=$(count_json_items "${EP_BODY[/rest/users]}" 2>/dev/null)
    if [[ "$user_count" =~ ^[0-9]+$ && "$user_count" -gt 1 ]]; then
        findings_ref+=("LOW|auth-enum|Authenticated session can enumerate all $user_count user account(s) on this instance")
    fi
}

auth_feature_list_credentials() {
    local tgt="$1" jar="$2"
    section "Stored Credentials (metadata only)"
    local bf="$TMPDIR/auth_creds.body"
    local status
    status=$($CURL -b "$jar" -o "$bf" -w '%{http_code}' "$tgt/rest/credentials" 2>/dev/null)
    if [[ "$status" != "200" ]]; then
        printf "%s│%s  %s✗ Could not list credentials (HTTP %s)%s\n" "$C_CYN" "$C_RESET" "$C_YEL" "$status" "$C_RESET"
        footer
        return
    fi
    if [[ "$HAVE_PY" == true ]]; then
        python3 -c '
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except Exception:
    sys.exit()
items = data.get("data", data) if isinstance(data, dict) else data
if not isinstance(items, list):
    sys.exit()
for c in items:
    name = c.get("name", "?")
    typ = c.get("type", "?")
    cid = c.get("id", "?")
    print(f"{name}|{typ}|{cid}")
' "$bf" | while IFS='|' read -r cname ctype cid; do
            [[ -z "$cname" ]] && continue
            printf "%s│%s  %-30s %-20s %sid:%s%s\n" "$C_CYN" "$C_RESET" "$cname" "$ctype" "$C_DIM" "$cid" "$C_RESET"
        done
    fi
    printf "%s│%s  %s(names/types only — values are encrypted at rest and not retrievable via this endpoint, authenticated or not)%s\n" "$C_CYN" "$C_RESET" "$C_DIM" "$C_RESET"
    footer
}

auth_feature_check_permissions() {
    local tgt="$1" jar="$2"
    local -n findings_ref="$3"

    section "Account Role & Permissions"
    # NOTE: n8n doesn't expose one stable unauthenticated-safe endpoint for
    # "who am I" across every version. GET /rest/login with the session
    # cookie attached is the closest documented equivalent on most recent
    # releases — verify the exact endpoint for the target's specific
    # version if this comes back empty.
    local bf="$TMPDIR/auth_me.body"
    local status
    status=$($CURL -b "$jar" -o "$bf" -w '%{http_code}' "$tgt/rest/login" 2>/dev/null)
    local role=""
    if [[ "$HAVE_PY" == true && "$status" == "200" ]]; then
        role=$(python3 -c '
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except Exception:
    sys.exit()
d = data.get("data", data) if isinstance(data, dict) else {}
gr = d.get("globalRole")
print(gr.get("name", "") if isinstance(gr, dict) else d.get("role", ""))
' "$bf" 2>/dev/null)
    fi
    [[ -z "$role" ]] && role="unknown (verify manually — endpoint varies by n8n version)"
    kv "Role" "$role"

    local can_edit_workflows="unknown"
    case "${role,,}" in
        owner|admin) can_edit_workflows="yes" ;;
        member) can_edit_workflows="likely — depends on per-project permissions, verify manually" ;;
    esac
    kv "Can create/edit workflows" "$can_edit_workflows"

    if [[ "$can_edit_workflows" == "yes" ]]; then
        findings_ref+=("HIGH|auth-enum|Account role '$role' can create/edit workflows — satisfies the authenticated precondition for n8n expression-sandbox RCE CVEs (CVE-2025-68613, CVE-2026-1470); see --poc for the corresponding entries")
    fi
    footer
}

auth_feature_export_workflows() {
    local tgt="$1" jar="$2" dir="$3"
    local -n findings_ref="$4"

    mkdir -p "$dir" 2>/dev/null
    section "Workflow Export & Secret Scan"

    local list_bf="$TMPDIR/auth_wf_list.body"
    local status
    status=$($CURL -b "$jar" -o "$list_bf" -w '%{http_code}' "$tgt/rest/workflows" 2>/dev/null)
    if [[ "$status" != "200" || "$HAVE_PY" != true ]]; then
        printf "%s│%s  %s✗ Could not list workflows (HTTP %s)%s\n" "$C_CYN" "$C_RESET" "$C_YEL" "$status" "$C_RESET"
        footer
        return
    fi

    local ids_names
    ids_names=$(python3 -c '
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except Exception:
    sys.exit()
items = data.get("data", data) if isinstance(data, dict) else data
if not isinstance(items, list):
    sys.exit()
for w in items:
    print(f"{w.get(\"id\", \"\")}|{w.get(\"name\", \"unnamed\")}")
' "$list_bf")

    local exported=0 wid wname
    while IFS='|' read -r wid wname; do
        [[ -z "$wid" ]] && continue
        exported=$((exported + 1))
        local safe_name; safe_name=$(echo "$wname" | tr -c '[:alnum:]._-' '_')
        local wf_bf="$dir/${wid}_${safe_name}.json"
        $CURL -b "$jar" -o "$wf_bf" "$tgt/rest/workflows/$wid" 2>/dev/null

        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            IFS='|' read -r stype slabel sval <<< "$line"
            findings_ref+=("CRIT|workflow-secret|Hardcoded secret found in workflow '$wname' ($stype): $sval")
        done < <(secret_scan_file "$wf_bf" "workflow:$wname")

        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            IFS='|' read -r nname ntype credtype credname <<< "$line"
            findings_ref+=("LOW|workflow-cred-ref|Workflow '$wname' node '$nname' ($ntype) references credential '$credname' (type $credtype)")
        done < <(python3 -c "$WORKFLOW_CRED_REF_EXTRACTOR" "$wf_bf" 2>/dev/null)
    done <<< "$ids_names"

    printf "%s│%s  %s✓ Exported %d workflow(s) to %s%s\n" "$C_CYN" "$C_RESET" "$C_GRN" "$exported" "$dir" "$C_RESET"
    footer
}

auth_main() {
    local A_TARGET="" A_TEST_CRED="" A_COOKIE_FILE="" A_SAVE_COOKIES=false A_FORCE=false
    local A_ENUMERATE=false A_LIST_CREDS=false A_CHECK_PERMS=false A_EXPORT_DIR=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --test-cred) A_TEST_CRED="${2:-}"; shift 2 ;;
            --cookie-file) A_COOKIE_FILE="${2:-}"; shift 2 ;;
            --save-cookies) A_SAVE_COOKIES=true; shift ;;
            --force) A_FORCE=true; shift ;;
            --enumerate) A_ENUMERATE=true; shift ;;
            --list-credentials) A_LIST_CREDS=true; shift ;;
            --check-permissions) A_CHECK_PERMS=true; shift ;;
            --export-workflows) A_EXPORT_DIR="${2:-}"; shift 2 ;;
            --reveal-secrets) REVEAL_SECRETS=true; shift ;;
            --no-color) NO_COLOR=true; shift ;;
            -h|--help) auth_print_help; exit 0 ;;
            *)
                if [[ -z "$A_TARGET" ]]; then A_TARGET="$1"; else echo "Unexpected argument: $1" >&2; exit 1; fi
                shift ;;
        esac
    done

    if [[ -z "$A_TARGET" ]]; then
        auth_print_help
        exit 1
    fi

    local TARGET="$A_TARGET"
    if [[ "$TARGET" != http://* && "$TARGET" != https://* ]]; then
        TARGET="http://${TARGET}"
    fi
    TARGET="${TARGET%/}"

    # -----------------------------------------------------------------
    # Resolve a session: fresh login > explicit --cookie-file > default slot
    # -----------------------------------------------------------------
    local JAR="" JAR_SOURCE=""
    if [[ -n "$A_TEST_CRED" ]]; then
        local CU="${A_TEST_CRED%%:*}" CP="${A_TEST_CRED#*:}"
        local login_jar="$TMPDIR/auth_login.jar"
        local result
        result=$(n8n_try_login "$TARGET" "$CU" "$CP" "$login_jar")
        if [[ "$result" != "success" ]]; then
            echo "[n8ked] auth: login with supplied credentials failed against $TARGET — aborting." >&2
            exit 1
        fi
        JAR="$login_jar"
        JAR_SOURCE="fresh login ($CU)"
        if [[ "$A_SAVE_COOKIES" == true ]]; then
            local dest; dest=$(resolve_cookie_path)
            save_cookie_jar "$JAR" "$TARGET" "$dest"
            echo "[n8ked] Session saved to $dest" >&2
        fi
    elif [[ -n "$A_COOKIE_FILE" ]]; then
        [[ -f "$A_COOKIE_FILE" ]] || { echo "Error: --cookie-file not found: $A_COOKIE_FILE" >&2; exit 1; }
        JAR="$A_COOKIE_FILE"
        JAR_SOURCE="explicit --cookie-file"
        local match; match=$(check_cookie_target_match "${A_COOKIE_FILE}.meta" "$TARGET")
        if [[ "$match" == mismatch:* ]]; then
            local saved="${match#mismatch:}"
            echo "[n8ked] WARNING: this cookie file was saved for '$saved', not '$TARGET'." >&2
            if [[ "$A_FORCE" != true ]]; then
                echo "[n8ked] Refusing to continue — rerun with --force to use it anyway." >&2
                exit 1
            fi
            echo "[n8ked] --force given, continuing with mismatched session." >&2
        fi
    else
        local default_jar; default_jar=$(resolve_cookie_path)
        if [[ ! -f "$default_jar" ]]; then
            echo "Error: no session found. Supply --test-cred user:pass, --cookie-file FILE, or run a scan with --save-cookies first (looked for: $default_jar)." >&2
            exit 1
        fi
        JAR="$default_jar"
        JAR_SOURCE="default session slot ($default_jar)"
        local match; match=$(check_cookie_target_match "${default_jar}.meta" "$TARGET")
        if [[ "$match" == mismatch:* ]]; then
            local saved="${match#mismatch:}"
            echo "[n8ked] WARNING: the saved session was captured against '$saved', not '$TARGET'." >&2
            if [[ "$A_FORCE" != true ]]; then
                echo "[n8ked] Refusing to continue — rerun with --force to use it anyway." >&2
                exit 1
            fi
            echo "[n8ked] --force given, continuing with mismatched session." >&2
        elif [[ "$match" == "unknown" ]]; then
            echo "[n8ked] Note: no target metadata found for this cookie file — can't verify it belongs to $TARGET." >&2
        fi
    fi

    # -----------------------------------------------------------------
    # Liveness check — fail fast rather than running every feature
    # against a dead session
    # -----------------------------------------------------------------
    local live_bf="$TMPDIR/auth_live.body"
    local live_status
    live_status=$($CURL -b "$JAR" -o "$live_bf" -w '%{http_code}' "$TARGET/rest/workflows" 2>/dev/null)
    if [[ "$live_status" == "401" || "$live_status" == "403" ]]; then
        echo "[n8ked] Session appears dead (HTTP $live_status on /rest/workflows). Re-run --test-cred/--userpass with --save-cookies to get a fresh one." >&2
        exit 1
    fi
    echo "[n8ked] Session live (source: $JAR_SOURCE) — proceeding." >&2

    if [[ "$A_ENUMERATE" == false && "$A_LIST_CREDS" == false && "$A_CHECK_PERMS" == false && -z "$A_EXPORT_DIR" ]]; then
        A_ENUMERATE=true
        echo "[n8ked] No feature flag given — defaulting to --enumerate. Other options: --list-credentials, --check-permissions, --export-workflows DIR" >&2
    fi

    local AUTH_FINDINGS=()

    echo
    printf "%s%sn8ked auth — authenticated session checks%s\n" "$C_BOLD" "$C_MAG" "$C_RESET"
    hr
    printf "%sTarget:%s %s    %sSession:%s %s\n" "$C_BOLD" "$C_RESET" "$TARGET" "$C_BOLD" "$C_RESET" "$JAR_SOURCE"

    [[ "$A_ENUMERATE" == true ]] && auth_feature_enumerate "$TARGET" "$JAR" AUTH_FINDINGS
    [[ "$A_LIST_CREDS" == true ]] && auth_feature_list_credentials "$TARGET" "$JAR"
    [[ "$A_CHECK_PERMS" == true ]] && auth_feature_check_permissions "$TARGET" "$JAR" AUTH_FINDINGS
    [[ -n "$A_EXPORT_DIR" ]] && auth_feature_export_workflows "$TARGET" "$JAR" "$A_EXPORT_DIR" AUTH_FINDINGS

    echo
    printf "%s%sAuth Findings%s\n" "$C_BOLD" "$C_YEL" "$C_RESET"
    local n_crit=0 n_high=0 n_med=0 n_low=0 f sev cat msg
    for f in "${AUTH_FINDINGS[@]}"; do
        IFS='|' read -r sev cat msg <<< "$f"
        [[ "$sev" == "CRIT" ]] && { ((n_crit++)); printf "  %s[CRITICAL]%s %s\n" "$C_RED$C_BOLD" "$C_RESET" "$msg"; }
    done
    for f in "${AUTH_FINDINGS[@]}"; do
        IFS='|' read -r sev cat msg <<< "$f"
        [[ "$sev" == "HIGH" ]] && { ((n_high++)); printf "  %s[HIGH]%s     %s\n" "$C_RED" "$C_RESET" "$msg"; }
    done
    for f in "${AUTH_FINDINGS[@]}"; do
        IFS='|' read -r sev cat msg <<< "$f"
        [[ "$sev" == "MED" ]] && { ((n_med++)); printf "  %s[MEDIUM]%s   %s\n" "$C_YEL" "$C_RESET" "$msg"; }
    done
    for f in "${AUTH_FINDINGS[@]}"; do
        IFS='|' read -r sev cat msg <<< "$f"
        [[ "$sev" == "LOW" ]] && { ((n_low++)); printf "  %s[LOW]%s      %s\n" "$C_DIM" "$C_RESET" "$msg"; }
    done
    if [[ ${#AUTH_FINDINGS[@]} -eq 0 ]]; then
        printf "  %sNo issues flagged.%s\n" "$C_GRN" "$C_RESET"
    fi
    echo
    printf "%s%d critical, %d high, %d medium, %d low%s\n" "$C_BOLD" "$n_crit" "$n_high" "$n_med" "$n_low" "$C_RESET"
    echo

    if [[ $((n_crit + n_high)) -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

# ---------------------------------------------------------------------------
# Per-target scan (unauthenticated + opt-in active checks)
# ---------------------------------------------------------------------------
scan_target() {
    local RAW_TARGET="$1"
    local TARGET="$RAW_TARGET"
    if [[ "$TARGET" != http://* && "$TARGET" != https://* ]]; then
        TARGET="http://${TARGET}"
    fi
    TARGET="${TARGET%/}"
    local FINDINGS=()
    local ROOT_HEADERS ROOT_STATUS SERVER_HDR ROOT_BODY_FILE
    ROOT_BODY_FILE="$TMPDIR/root.body"
    ROOT_HEADERS=$($CURL -D - -o "$ROOT_BODY_FILE" "$TARGET/" 2>/dev/null)
    ROOT_STATUS=$(echo "$ROOT_HEADERS" | head -1 | tr -d '\r')
    SERVER_HDR=$(echo "$ROOT_HEADERS" | grep -i '^server:' | head -1 | cut -d' ' -f2- | tr -d '\r')

    local SETTINGS_JSON HEALTHZ_JSON
    SETTINGS_JSON=$($CURL "$TARGET/rest/settings" 2>/dev/null)
    HEALTHZ_JSON=$($CURL "$TARGET/healthz" 2>/dev/null)

    local ROOT_HAS_META=false
    grep -q 'name="n8n:config' "$ROOT_BODY_FILE" 2>/dev/null && ROOT_HAS_META=true
    if ! echo "$SETTINGS_JSON" | grep -qE '"instanceId"|"settingsMode"|"userManagement"' && [[ "$ROOT_HAS_META" == false ]]; then
        local not_n8n_msg="not an n8n instance (no instanceId/settingsMode/userManagement in /rest/settings, no n8n:config meta tag on root page)"
        if [[ "$JSON_OUT" == true ]]; then
            echo "{\"target\":\"$TARGET\",\"error\":\"$not_n8n_msg\"}"
        else
            echo
            echo "${C_RED}✗ ${TARGET} does not look like an n8n instance.${C_RESET}"
        fi
        NOT_N8N_SEEN=true
        return
    fi

    vget() { jget "$SETTINGS_JSON" "data.$1" "${2:-}"; }
    local VERSION AUTH_METHOD SHOW_SETUP MFA_ENABLED MFA_ENFORCED HEALTH_STATUS
    VERSION=$(vget versionCli "unknown")
    if [[ "$VERSION" == "unknown" ]]; then
        local SENTRY_VERSION; SENTRY_VERSION=$(extract_sentry_version "$ROOT_BODY_FILE")
        [[ -n "$SENTRY_VERSION" ]] && VERSION="$SENTRY_VERSION"
    fi
    AUTH_METHOD=$(vget userManagement.authenticationMethod "unknown")
    SHOW_SETUP=$(vget userManagement.showSetupOnFirstLoad "unknown")
    MFA_ENABLED=$(vget mfa.enabled "unknown")
    MFA_ENFORCED=$(vget mfa.enforced "unknown")
    HEALTH_STATUS=$(jget "$HEALTHZ_JSON" "status" "unreachable")

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
    local EXPOSED_BODIES=() ENDPOINT_RESULTS=()
    for entry in "${ENDPOINTS[@]}"; do
        IFS='|' read -r ep label sev <<< "$entry"
        local bodyfile="$TMPDIR/ep_$(echo "$ep" | tr '/?&=' '____').body"
        local status; status=$($CURL -o "$bodyfile" -w '%{http_code}' "$TARGET$ep" 2>/dev/null)
        local body; body=$(cat "$bodyfile" 2>/dev/null)
        local verdict="PROTECTED"
        if [[ "$status" == "401" || "$status" == "403" ]]; then
            verdict="PROTECTED"
        elif [[ "$status" == "404" ]]; then
            verdict="NOT-ENABLED"
        elif [[ "$status" == "200" ]]; then
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
        [[ "$verdict" == "EXPOSED" ]] && FINDINGS+=("$sev|access-control|Unauthenticated access to $ep ($label) — HTTP $status returned real data with no auth required")
    done

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

    local IS_HTTPS=false
    [[ "$TARGET" == https://* ]] && IS_HTTPS=true
    [[ "$IS_HTTPS" == false ]] && echo "$ROOT_HEADERS" | grep -qi '^location: https://' && IS_HTTPS=true
    [[ "$IS_HTTPS" == false ]] && FINDINGS+=("MED|tls|Service reachable over plain HTTP (no TLS) at $TARGET")

    if [[ "$MFA_ENFORCED" == "false" ]]; then
        FINDINGS+=("HIGH|mfa|MFA not enforced org-wide (enabled=$MFA_ENABLED, enforced=$MFA_ENFORCED)")
    fi
    [[ "$SHOW_SETUP" != "false" ]] && FINDINGS+=("HIGH|setup|Setup wizard may still be open (no owner account confirmed)")

    local CRED_RESULT=""
    if [[ -n "$TEST_CRED" ]]; then
        local CU="${TEST_CRED%%:*}" CP="${TEST_CRED#*:}"
        local test_jar="$TMPDIR/testcred.jar"
        CRED_RESULT=$(n8n_try_login "$TARGET" "$CU" "$CP" "$test_jar")
        if [[ "$CRED_RESULT" == "success" ]]; then
            FINDINGS+=("CRIT|credential-test|Supplied credentials ($CU) are VALID — full editor access obtained")
            if [[ "$SAVE_COOKIES" == true ]]; then
                local cookie_dest; cookie_dest=$(resolve_cookie_path)
                if save_cookie_jar "$test_jar" "$TARGET" "$cookie_dest"; then
                    echo "[n8ked] Session cookie saved to $cookie_dest — use './n8ked.sh auth $TARGET' to continue" >&2
                fi
            fi
        fi
    fi

    local BRUTE_TRIED=0 BRUTE_TOTAL=0 BRUTE_VALID=()
    if [[ -n "$USERPASS_FILE" ]]; then
        BRUTE_TOTAL=$(grep -cE '.:.' "$USERPASS_FILE" 2>/dev/null || echo 0)
        echo "[n8ked] Brute forcing $TARGET/rest/login — $BRUTE_TOTAL pair(s) from $USERPASS_FILE, ${BRUTE_DELAY}s delay..." >&2
        while IFS= read -r pair; do
            pair="$(echo "$pair" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
            [[ -z "$pair" || "$pair" == \#* || "$pair" != *:* ]] && continue
            BRUTE_TRIED=$((BRUTE_TRIED + 1))
            local bu="${pair%%:*}" bp="${pair#*:}"
            local bjar="$TMPDIR/brute_${BRUTE_TRIED}.jar"
            local bres; bres=$(n8n_try_login "$TARGET" "$bu" "$bp" "$bjar")
            if [[ "$bres" == "success" ]]; then
                BRUTE_VALID+=("$pair")
                FINDINGS+=("CRIT|credential-test|Brute force via --userpass found VALID credentials ($bu) — full editor access obtained")
                echo "[n8ked]   -> VALID: $bu" >&2
                if [[ "$SAVE_COOKIES" == true ]]; then
                    local cookie_dest; cookie_dest=$(resolve_cookie_path)
                    if save_cookie_jar "$bjar" "$TARGET" "$cookie_dest"; then
                        echo "[n8ked] Session cookie saved to $cookie_dest — use './n8ked.sh auth $TARGET' to continue" >&2
                    fi
                fi
                [[ "$STOP_ON_SUCCESS" == true ]] && break
            fi
            sleep "$BRUTE_DELAY" 2>/dev/null
        done < "$USERPASS_FILE"
        echo "[n8ked] Brute force done: tried $BRUTE_TRIED/$BRUTE_TOTAL pair(s), ${#BRUTE_VALID[@]} valid." >&2
    fi

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
            FINDINGS+=("MED|lockout|No rate-limiting/lockout observed on /rest/login after 8 rapid failed attempts")
        fi
    fi

    local WEBHOOK_BRUTE_HITS=()
    if [[ -n "$WEBHOOK_BRUTE_FILE" ]]; then
        local wh_bases=("webhook")
        [[ "$INCLUDE_TEST_WEBHOOKS" == true ]] && wh_bases+=("webhook-test")
        IFS=',' read -r -a wh_methods <<< "$WEBHOOK_METHODS"
        echo "[n8ked] WARNING: --webhook-brute sends REAL requests. A hit is a LIVE trigger, not passive recon." >&2
        while IFS= read -r cand; do
            cand="$(echo "$cand" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//;s#^/##')"
            [[ -z "$cand" || "$cand" == \#* ]] && continue
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
                            TRIGGERED) FINDINGS+=("CRIT|webhook|Unauthenticated webhook triggered — /$wh_base/$cand ($wh_method) HTTP $wh_status — live invocation") ;;
                            ERROR)     FINDINGS+=("HIGH|webhook|Registered webhook — /$wh_base/$cand ($wh_method) HTTP $wh_status (errored on invocation)") ;;
                            AUTH-REQUIRED) FINDINGS+=("MED|webhook|Registered webhook — /$wh_base/$cand ($wh_method) requires its own auth (HTTP $wh_status)") ;;
                            TIMEOUT)   FINDINGS+=("MED|webhook|Possible webhook trigger — /$wh_base/$cand ($wh_method) timed out") ;;
                            *)         FINDINGS+=("MED|webhook|Unexpected response from /$wh_base/$cand ($wh_method): HTTP $wh_status") ;;
                        esac
                    fi
                    sleep "$WEBHOOK_DELAY" 2>/dev/null
                done
            done
        done < "$WEBHOOK_BRUTE_FILE"
    fi

    local NUCLEI_OUT=""
    if [[ "$RUN_NUCLEI" == true ]]; then
        if command -v nuclei >/dev/null 2>&1; then
            NUCLEI_OUT=$(nuclei -u "$TARGET" -tags n8n -silent -no-color 2>/dev/null)
        else
            NUCLEI_OUT="nuclei not installed — skipped"
        fi
    fi

    if [[ "$CVE_MODE" == true ]]; then
        echo
        printf "%s%sCVE Proof-of-Concept%s\n" "$C_BOLD" "$C_YEL" "$C_RESET"
        local -a matches=()
        local idx
        for idx in "${!CVE_DB_ID[@]}"; do
            if ver_ge "$VERSION" "${CVE_DB_MINVER[$idx]}" && ver_lt "$VERSION" "${CVE_DB_MAXVER[$idx]}"; then
                matches+=("$idx")
            fi
        done
        if [[ ${#matches[@]} -eq 0 ]]; then
            printf "  %s✓ No known-CVE version ranges matched (detected version: %s)%s\n" "$C_GRN" "$VERSION" "$C_RESET"
        else
            for idx in "${matches[@]}"; do
                printf "  %s[%s]%s %s — CVSS %s, %s\n" "$C_RED$C_BOLD" "$(cvss_to_sev "${CVE_DB_CVSS[$idx]}")" "$C_RESET" "${CVE_DB_ID[$idx]}" "${CVE_DB_CVSS[$idx]}" "${CVE_DB_AUTH[$idx]}"
                wrap_flat "      " "Preconditions: " "${CVE_DB_NOTE[$idx]}"
            done
        fi
    fi

    local n_crit_ec=0 n_high_ec=0
    for f in "${FINDINGS[@]}"; do
        IFS='|' read -r sev _cat_ec _msg_ec <<< "$f"
        case "$sev" in CRIT) ((n_crit_ec++)) ;; HIGH) ((n_high_ec++)) ;; esac
    done
    [[ $((n_crit_ec + n_high_ec)) -gt 0 ]] && HAD_HIGH_OR_CRIT=true

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
    parts = line.split("|", 2)
    out.append({"severity": parts[0], "category": parts[1] if len(parts) > 1 else "", "message": parts[2] if len(parts) > 2 else ""})
print(json.dumps(out))
')
        fi
        echo "{\"target\":\"$TARGET\",\"version\":\"$VERSION\",\"findings\":$findings_json}"
        return
    fi

    echo
    printf "%s%s /░ /░    /█▀▀█    /░/░    /█▀▀▀/    /░░░ %s\n" "$C_BOLD" "$C_MAG" "$C_RESET"
    printf "%s%s│ ▒▒ ▒   │ ▓▓▓▓   │ ▒▒/   │ ▓▓▓     │-▒_/▒%s\n" "$C_BOLD" "$C_MAG" "$C_RESET"
    printf "%s%s│ ▓│▓▓   │ ▒ /▒   │ ▓▓    │_▒_/     │ ▓│ ▓  n8ked — n8n exposure auditor%s\n" "$C_BOLD" "$C_MAG" "$C_RESET"
    printf "%s%s│ █│ █   │ ░░░░   │ █ █   │ ░░░░    │ ███/%s\n" "$C_BOLD" "$C_MAG" "$C_RESET"
    printf "%s%s│//│//   │/___/   │////   │/___/    │/__/ %s\n" "$C_BOLD" "$C_MAG" "$C_RESET"
    hr
    printf "%sTarget:%s %s    %sChecked:%s %s\n" "$C_BOLD" "$C_RESET" "$TARGET" "$C_BOLD" "$C_RESET" "$(date '+%Y-%m-%d %H:%M:%S %Z')"

    section "Instance Fingerprint"
    kv "HTTP root status" "$ROOT_STATUS"
    kv "Server header" "${SERVER_HDR:-none disclosed}"
    kv "n8n version (CLI)" "$VERSION" "$C_YEL"
    kv "/healthz" "$HEALTH_STATUS"
    footer

    section "Access Control — Unauthenticated Endpoint Exposure"
    for e in "${ENDPOINT_RESULTS[@]}"; do
        IFS='|' read -r ep label verdict status <<< "$e"
        case "$verdict" in
            EXPOSED) printf "%s│%s  %s✗ EXPOSED %-8s%s %-28s %s(%s)%s\n" "$C_CYN" "$C_RESET" "$C_RED" "[$status]" "$C_RESET" "$ep" "$C_DIM" "$label" "$C_RESET" ;;
            PROTECTED) printf "%s│%s  %s✓ ok %-13s%s %-28s %s(%s)%s\n" "$C_CYN" "$C_RESET" "$C_GRN" "[$status]" "$C_RESET" "$ep" "$C_DIM" "$label" "$C_RESET" ;;
            EMPTY) printf "%s│%s  %s✓ empty %-10s%s %-28s %s(%s)%s\n" "$C_CYN" "$C_RESET" "$C_GRN" "[$status]" "$C_RESET" "$ep" "$C_DIM" "$label" "$C_RESET" ;;
            NOT-ENABLED) printf "%s│%s  %s- n/a %-13s%s %-28s %s(%s)%s\n" "$C_CYN" "$C_RESET" "$C_DIM" "[$status]" "$C_RESET" "$ep" "$C_DIM" "$label" "$C_RESET" ;;
            *) printf "%s│%s  %s? %-16s%s %-28s %s(%s)%s\n" "$C_CYN" "$C_RESET" "$C_YEL" "[$verdict]" "$C_RESET" "$ep" "$C_DIM" "$label" "$C_RESET" ;;
        esac
    done
    footer

    if [[ ${#SECRET_HITS[@]} -gt 0 ]]; then
        section "Secret Scan"
        for hit in "${SECRET_HITS[@]}"; do
            IFS='|' read -r stype slabel sval <<< "$hit"
            printf "%s│%s  %s✗ %s%s in %s: %s%s%s\n" "$C_CYN" "$C_RESET" "$C_RED" "$stype" "$C_RESET" "$slabel" "$C_BOLD" "$sval" "$C_RESET"
        done
        footer
    fi

    if [[ -n "$TEST_CRED" || -n "$USERPASS_FILE" || "$CHECK_LOCKOUT" == true ]]; then
        section "Credential Testing"
        [[ -n "$TEST_CRED" ]] && kv "Single cred tested" "${TEST_CRED%%:*} -> $CRED_RESULT"
        [[ -n "$USERPASS_FILE" ]] && kv "Brute force" "$BRUTE_TRIED/$BRUTE_TOTAL tried, ${#BRUTE_VALID[@]} valid"
        [[ "$CHECK_LOCKOUT" == true ]] && kv "Lockout probe" "$LOCKOUT_RESULT"
        footer
    fi

    if [[ -n "$WEBHOOK_BRUTE_FILE" ]]; then
        section "Webhook Path Discovery"
        if [[ ${#WEBHOOK_BRUTE_HITS[@]} -eq 0 ]]; then
            printf "%s│%s  %s✓ No registered webhook paths found%s\n" "$C_CYN" "$C_RESET" "$C_GRN" "$C_RESET"
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
            echo "$NUCLEI_OUT" | while IFS= read -r line; do printf "%s│%s  %s\n" "$C_CYN" "$C_RESET" "$line"; done
        fi
        footer
    fi

    local n_crit=0 n_high=0 n_med=0 n_low=0
    echo
    printf "%s%sRisk Summary%s\n" "$C_BOLD" "$C_YEL" "$C_RESET"
    for f in "${FINDINGS[@]}"; do
        IFS='|' read -r sev _cat msg <<< "$f"
        [[ "$sev" == "CRIT" ]] && { ((n_crit++)); printf "  %s[CRITICAL]%s %s\n" "$C_RED$C_BOLD" "$C_RESET" "$msg"; }
    done
    for f in "${FINDINGS[@]}"; do
        IFS='|' read -r sev _cat msg <<< "$f"
        [[ "$sev" == "HIGH" ]] && { ((n_high++)); printf "  %s[HIGH]%s     %s\n" "$C_RED" "$C_RESET" "$msg"; }
    done
    for f in "${FINDINGS[@]}"; do
        IFS='|' read -r sev _cat msg <<< "$f"
        [[ "$sev" == "MED" ]] && { ((n_med++)); printf "  %s[MEDIUM]%s   %s\n" "$C_YEL" "$C_RESET" "$msg"; }
    done
    for f in "${FINDINGS[@]}"; do
        IFS='|' read -r sev _cat msg <<< "$f"
        [[ "$sev" == "LOW" ]] && { ((n_low++)); printf "  %s[LOW]%s      %s\n" "$C_DIM" "$C_RESET" "$msg"; }
    done
    [[ ${#FINDINGS[@]} -eq 0 ]] && printf "  %sNo issues flagged.%s\n" "$C_GRN" "$C_RESET"
    echo
    printf "%s%d critical, %d high, %d medium, %d low%s\n" "$C_BOLD" "$n_crit" "$n_high" "$n_med" "$n_low" "$C_RESET"
    echo
    [[ $((n_crit + n_high)) -gt 0 ]] && HAD_HIGH_OR_CRIT=true
}

# ---------------------------------------------------------------------------
# EyeWitness folder discovery
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
    local dir="$1"
    if [[ "$HAVE_PY" == true ]]; then
        python3 -c "$EW_PYTHON_EXTRACTOR" "$dir" 2>/dev/null
    else
        if [[ -f "$dir/open_ports.csv" ]]; then
            tail -n +2 "$dir/open_ports.csv" | awk -F',' '{print $1}' | tr -d '\r' | grep -oE '^https?://[^/]+'
        fi
    fi | sort -u
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
HAD_HIGH_OR_CRIT=false
NOT_N8N_SEEN=false

if [[ "$AUTH_MODE" == true ]]; then
    auth_main "${AUTH_ARGS[@]}"
    exit $?
fi

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
    [[ "$FOUND" -eq 0 ]] && NOT_N8N_SEEN=true
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
