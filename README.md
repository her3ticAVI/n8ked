<div align="center">
<a href="https://blackhillsinfosec.com"><img width="500" height="500" src="img/n8ked-logo.png" alt="n8ked Logo" /></a>
<hr>
  <a href="https://github.com/blackhillsinfosec/n8ked/actions"><img alt="GitHub Workflow Status" src="https://img.shields.io/github/actions/workflow/status/her3ticAVI/n8ked/.github%2Fworkflows%2Fpython-app.yml?style=flat-square"></a>
  &nbsp;
  <a href="https://discord.com/invite/bhis"><img alt="Discord" src="https://img.shields.io/discord/967097582721572934?label=Discord&color=7289da&style=flat-square" /></a>
  &nbsp;
  <a href="https://github.com/her3ticAVI/n8ked/graphs/contributors"><img alt="Contributors" src="https://img.shields.io/github/contributors-anon/her3ticAVI/n8ked?color=yellow&style=flat-square" /></a>
  &nbsp;
  <a href="https://x.com/BHinfoSecurity"><img src="https://img.shields.io/badge/follow-BHIS-1DA1F2?logo=twitter&style=flat-square" alt="BHIS Twitter" /></a>
  &nbsp;
  <a href="https://github.com/her3ticAVI/n8ked/stargazers"><img src="https://img.shields.io/github/stars/her3ticAVI/n8ked?style=flat-square&color=rgb(255%2C218%2C185)" alt="n8ked Stars" /></a>

<p class="align center">
<h4><code>n8ked</code> is an unauthenticated exposure and misconfiguration auditor for <a href="https://n8n.io">n8n</a> instances found during external/internal recon. It starts from n8n's by-design unauthenticated endpoints, checks whether endpoints that shouldn't be reachable without a login actually are, scans what comes back for hardcoded secrets, and — as opt-in, clearly-flagged active checks — can test credentials and discover unauthenticated webhook triggers, the two preconditions most n8n RCE-style CVEs need.</h4>
</p>

<div style="text-align: center;">
  <h4>
    <a target="_blank" href="#usage" rel="dofollow"><strong>Usage</strong></a>&nbsp;·&nbsp;
    <a target="_blank" href="#features" rel="dofollow"><strong>Features</strong></a>&nbsp;·&nbsp;
    <a target="_blank" href="#understanding-the-output" rel="dofollow"><strong>Understanding Output</strong></a>&nbsp;·&nbsp;
    <a target="_blank" href="#for-testers" rel="dofollow"><strong>For Testers</strong></a>&nbsp;·&nbsp;
    <a target="_blank" href="#scope-and-safety-notes" rel="dofollow"><strong>Scope &amp; Safety</strong></a>
  </h4>
</div>
<hr>
</div>

<div align="left">

## Why

Fingerprinting an n8n instance's version tells you if it's patched. It doesn't tell you whether someone left `/rest/workflows` reachable with no login, a hardcoded Slack token sitting in a node's parameters, or a webhook that fires a workflow for anyone who guesses the path. This checks for that — and, since several n8n RCE-class CVEs need either valid credentials or a reachable webhook to trigger, it can also test for both of those preconditions directly when you opt in.

## Features

**Instance fingerprint** — version, release channel, instance ID, auth method, SSO config, health status. Recent n8n releases stopped disclosing `versionCli` (and several other fields) to unauthenticated callers, so when the REST API comes back empty on version the tool falls back to decoding the `n8n:config:sentry` meta tag n8n still ships on the root page, which nuclei's own `n8n-panel` template uses for the same reason.

**MFA posture** — enabled vs. enforced are flagged separately, and the tool distinguishes a confirmed `enforced: false` (High) from an instance that simply no longer discloses `mfa.*` fields unauthenticated (Low, flagged for manual/credentialed verification rather than assumed off).

**Access control sweep** — probes 17 sensitive REST/API endpoints unauthenticated:
`/rest/workflows`, `/rest/credentials`, `/api/v1/workflows`, `/rest/users`, `/rest/executions`, `/rest/active-workflows`, `/rest/credentials/for-workflow`, `/rest/variables`, `/rest/external-secrets/providers`, `/rest/source-control/preferences`, `/rest/owner`, `/rest/orchestration/health`, `/rest/insights/summary`, `/rest/tags`, `/rest/license`, `/rest/community-packages`, `/metrics`.
Each gets a verdict: `PROTECTED`, `EXPOSED`, `NOT-ENABLED`, or `EMPTY` — with guards against false positives from SPA catch-all routing and n8n's `{"data": []}` empty-response envelope.

**HTTP method tampering** — every endpoint that comes back `PROTECTED` on `GET` is retried with `HEAD`, to catch reverse-proxy/framework configs that only enforce auth on one verb and let another straight through to the real handler.

**Header disclosure scan** — beyond the standard four security headers, the tool scans every response header for signs of internal info leaking out (`x-n8n-*`, `x-powered-by`, `x-internal-*`, `x-real-ip`, `x-forwarded-*`, `x-runtime`, `x-served-by`, `x-backend`, `x-upstream`) — this is what catches things like an `X-N8N-Origin` header naming the internal host or deployment.

**Secret scanning** — anything that comes back exposed is scanned for AWS keys, Slack tokens, JWTs, bearer tokens, PEM private key blocks, database connection strings, GitHub tokens, and generic password/secret/token fields. Matches are masked by default.

**CORS check** — flags credentialed reflection of arbitrary `Origin` headers (a website can make authenticated requests on a logged-in victim's behalf).

**Security headers** — HSTS, X-Frame-Options, X-Content-Type-Options, CSP, and whether the service is even on TLS (redirect-aware, so a host that only serves HTTPS via a forced redirect isn't misreported as plain HTTP).

**Config/file exposure** — checks for `.env`, `.git/config`, `.git/HEAD`, `package.json`, `docker-compose.yml`, `config.json`, with root-page diffing to avoid false positives on SPA fallback routing.

**Internal hostname disclosure** — pulls real internal hostnames leaked via OAuth/OIDC callback URLs, even when the instance is only reachable by IP. Only flagged when the disclosed host actually differs from the one being scanned, so an OIDC callback that simply points back at its own public domain isn't misreported as a leak.

**Webhook exposure** — checks both `/webhook-test/` (only live while a workflow is open in the editor) and the production `/webhook/` base (the persistent, always-on trigger surface), each diffed against the root page to rule out SPA catch-all false positives.

**Single credential test** (`--test-cred`) — check exactly one pair against `/rest/login`.

**Credential brute force** (`--userpass`) — try a list of `user:pass` pairs against `/rest/login`, paced with a configurable delay, stopping at the first valid hit by default.

**Lockout/rate-limit probe** (`--check-lockout`) — fires a bounded, fixed number of bad-credential attempts and reports whether `/rest/login` ever throttles (HTTP 429) or just returns 401 indefinitely. Off by default since it's active and noisy.

**Webhook path discovery** (`--webhook-brute`) — tries a wordlist of candidate paths against the production webhook base (and optionally `/webhook-test/`) across configurable HTTP methods, using n8n's own "not registered" 404 wording to separate real hits from misses far more reliably than a bare status code. This is the tool's answer to the "or a reachable webhook" half of the RCE precondition — see [Scope and safety notes](#scope-and-safety-notes) before using it, since a hit here is a live trigger, not recon.

**Optional nuclei pass** (`--nuclei`) — runs nuclei's own signed `n8n`-tagged templates for known CVEs instead of any custom exploit logic.

**Multi-host** — scan a list of targets, or point it at an EyeWitness results folder and it'll find the n8n instances for you.

**Risk-scored output** — every finding gets Critical/High/Medium/Low, with a rollup summary and an exit code that reflects the worst finding.

## Requirements

- `bash`, `curl` (with redirect support — the tool follows redirects and preserves POST/PUT across them via `--post301/302/303`, since several n8n deployments sit behind a reverse proxy or CDN that forces HTTP→HTTPS)
- `jq` **or** `python3` (JSON parsing — jq preferred, python3 fallback)
- `python3` specifically needed for secret scanning, the sentry-tag version fallback, and the EyeWitness HTML/CSV parser (falls back to a CSV-only parser without it)
- GNU coreutils (`timeout`, standard on any modern Linux box) — used to bound webhook probes
- `nuclei` — only if you pass `--nuclei`

Tested on Kali; should run anywhere with a reasonably modern bash and GNU coreutils.

## Installation

```bash
git clone https://github.com/blackhillsinfosec/n8ked.git
cd n8ked
chmod +x n8ked.sh
```

No dependencies to install beyond what's already on a typical pentest box.

## Usage

```bash
./n8ked.sh <target> [options]
./n8ked.sh --file targets.txt [options]
./n8ked.sh --eyewitness /path/to/EyeWitness-Results [options]
```

### Examples

```bash
# Single host
./n8ked.sh http://10.0.0.5:5678

# Single host, with one credential to test
./n8ked.sh 10.0.0.5:5678 --test-cred admin@example.com:changeme

# List of hosts, JSON output piped to a file (one object per line)
./n8ked.sh --file scope-hosts.txt --json > results.jsonl

# Point it at an EyeWitness results folder — it finds the n8n instances for you
./n8ked.sh --eyewitness ~/engagements/acme/EyeWitness-Results

# Full secret values instead of masked previews
./n8ked.sh http://10.0.0.5:5678 --reveal-secrets

# Also run nuclei's n8n-tagged CVE templates
./n8ked.sh http://10.0.0.5:5678 --nuclei

# Brute force a list of credentials, paced 2s apart, testing every pair
# instead of stopping at the first hit
./n8ked.sh 10.0.0.5:5678 --userpass creds.txt --brute-delay 2 --no-stop-on-success

# Check whether /rest/login has any rate-limiting/lockout at all
./n8ked.sh 10.0.0.5:5678 --check-lockout

# Discover unauthenticated webhook triggers from a path wordlist
./n8ked.sh 10.0.0.5:5678 --webhook-brute paths.txt --webhook-methods GET,POST

# Also check /webhook-test/ (only live while someone has a workflow open)
./n8ked.sh 10.0.0.5:5678 --webhook-brute paths.txt --include-test-webhooks

# Everything at once
./n8ked.sh 10.0.0.5:5678 --nuclei --userpass creds.txt --check-lockout \
    --webhook-brute paths.txt --reveal-secrets --json > n8n-audit.jsonl
```

### Options

| Flag | Description |
|---|---|
| `--file FILE` | Scan every host in `FILE`, one target per line (`#` comments allowed) |
| `--eyewitness DIR` | Pull candidate hosts from an EyeWitness results folder (`open_ports.csv` and/or `report*.html`), probe each for n8n, and only run the full audit against confirmed hits |
| `--json` | Output one JSON object per host instead of the pretty terminal report |
| `--test-cred user:pass` | Try exactly one credential pair against `/rest/login` |
| `--userpass FILE` | Try every `user:pass` line in `FILE` against `/rest/login`. Stops at the first valid hit unless `--no-stop-on-success` is given |
| `--brute-delay SECONDS` | Delay between `--userpass` attempts (default: `1`) |
| `--no-stop-on-success` | With `--userpass`, keep testing remaining pairs after a valid hit instead of stopping at the first one |
| `--check-lockout` | Fire a handful of bad-credential attempts at `/rest/login` to check for rate-limiting/lockout. Noisy — generates extra auth-failure log entries on the target; off by default |
| `--webhook-brute FILE` | Try every path in `FILE` against the production webhook base (`/webhook/<path>`) with each method in `--webhook-methods`. **A hit is a real, live invocation of that workflow** — not passive recon |
| `--webhook-methods LIST` | Comma-separated HTTP methods to try per path with `--webhook-brute` (default: `GET,POST`) |
| `--webhook-delay SECONDS` | Delay between `--webhook-brute` attempts (default: `0.3`) |
| `--include-test-webhooks` | With `--webhook-brute`, also try the `/webhook-test/` base (only live while a workflow is open in the editor) in addition to the production `/webhook/` base |
| `--reveal-secrets` | Print full secret values instead of masked previews |
| `--nuclei` | Also run nuclei's `n8n`-tagged templates, if nuclei is installed |
| `--no-color` | Disable ANSI colors (useful when piping to a file) |
| `-h`, `--help` | Show usage |

## How the EyeWitness mode works

`--eyewitness` reads `open_ports.csv` and any `report*.html` files in the given folder, extracts every unique host origin EyeWitness recorded, and sends a lightweight unauthenticated probe (`GET /rest/settings`, checking for `instanceId`, `settingsMode`, or `userManagement` — whichever fields that release still discloses — with a root-page `n8n:config` meta-tag check as a fallback) to each one. Only confirmed n8n instances get the full audit — everything else is skipped silently, so you can point it at a folder with a hundred unrelated web hosts and it'll only spend real time on the ones that matter.

## How webhook path discovery works

Random, auto-generated n8n webhook IDs are effectively un-guessable, but plenty of real-world workflows are built with a human-chosen path (`contact-form`, `intake`, a department name) instead — the same reason directory wordlist fuzzing works on web apps in general. `--webhook-brute` runs that idea against n8n's webhook base specifically, and uses a signal a lot more reliable than a bare status code: n8n's webhook router returns a distinctive "is not registered" 404 body for a path/method combo that doesn't exist, so the tool treats anything else — a 2xx, a 5xx, a 401/403, or a timeout — as a real hit rather than guessing from status alone. Each hit gets one of four verdicts:

| Verdict | Meaning |
|---|---|
| `TRIGGERED` | 2xx response — the webhook fired successfully. This is a live, real invocation of that workflow |
| `ERROR` | 5xx response — the path/method is real and reachable, but the workflow errored on invocation |
| `AUTH-REQUIRED` | 401/403 — the path is confirmed to exist but has its own auth barrier |
| `TIMEOUT` | The request never came back — the workflow may still be executing |

Because a webhook node is registered for one specific HTTP method, `--webhook-methods` (default `GET,POST`) controls which methods get tried per candidate path — widening it catches workflows built for PUT/DELETE/PATCH at the cost of more requests per path.

## Understanding the output

Each endpoint in the access control sweep gets one of four verdicts:

| Verdict | Meaning |
|---|---|
| `PROTECTED` | Returned 401/403 — access control is working |
| `EXPOSED` | Returned real data with no auth required — this is a finding |
| `EMPTY` | Reachable without auth but returned no meaningful data (e.g. no workflows exist yet) |
| `NOT-ENABLED` | 404, or the response was identical to the root SPA page (routing catch-all, not a real endpoint) |

Findings roll up into a severity-tagged summary at the end of each report:

- **Critical** — unauthenticated access to workflows/credentials/the public API, hardcoded secrets, credentialed CORS misconfiguration, valid tested/brute-forced credentials, a triggered unauthenticated webhook (`--webhook-brute` `TRIGGERED`)
- **High** — unauthenticated access to users/executions/active-workflow lists/credential-for-workflow metadata/Variables, plain HTTP with no TLS, setup wizard potentially still open, confirmed MFA not enforced, an HTTP-method auth bypass, the production webhook base itself responding live, a registered webhook that errored on invocation (`ERROR`)
- **Medium** — unauthenticated metrics/owner/external-secrets/source-control endpoint exposure, possible config file exposure, non-credentialed CORS Origin reflection, no rate-limiting observed on `/rest/login`, a webhook path confirmed to exist behind its own auth (`AUTH-REQUIRED`) or that timed out (`TIMEOUT`)
- **Low** — missing security headers, header-based internal info disclosure (e.g. `X-N8N-Origin`), internal hostname disclosure, wildcard (non-credentialed) CORS, unauthenticated queue-topology/analytics/tags/license/community-package endpoint exposure, a live `webhook-test` endpoint, MFA posture that couldn't be determined from this n8n release's API response

Exit codes: `0` = nothing Critical/High found on any target, `1` = at least one Critical/High finding, `2` = target(s) couldn't be confirmed as n8n.

## For Testers

### Report language

For write-ups, use something like the following in the methodology/tools section — **split it by what was actually run**, since the passive checks and the opt-in active flags carry different disclosure implications.

**Passive/read-only checks** (always run; edit to match what was actually enabled):

> n8ked was used to audit the n8n instance(s) in scope for unauthenticated exposure and misconfiguration. The tool issued read-only HTTP requests via curl against n8n's documented REST and API endpoints to determine whether access controls, MFA enforcement, CORS policy, and security headers were configured as expected, and inspected any data returned from unauthenticated requests for hardcoded secrets such as API keys, tokens, and credentials. Where nuclei was used, only official, signed `n8n`-tagged templates were run against known CVEs; no custom or hand-rolled exploit code was executed against the target(s).

**If `--test-cred` or `--userpass` was used**, add:

> A limited number of credential pairs were tested against the instance's `/rest/login` endpoint to assess authentication strength. [State the number of pairs tested and their source — client-provided, commonly-leaked patterns, etc.]

**If `--check-lockout` was used**, add:

> A bounded number of deliberately invalid login attempts were sent to `/rest/login` to determine whether the instance enforces any rate-limiting or account lockout policy.

**If `--webhook-brute` was used**, add — and be specific here, since this is the one active check that can have real side effects on the client's environment:

> A wordlist of candidate paths was tested against the instance's webhook endpoint(s) to determine whether any workflow could be triggered without authentication. Any path that returned a successful response represents a live invocation of the corresponding workflow at the time of testing; this may have caused the associated automation to execute (e.g., sending a notification, calling a third-party API, or performing whatever action the workflow was built to perform). [Document which paths returned a hit, and coordinate with the client on any workflow that appears to have executed as a result.]

### Defensibility of n8ked

n8ked was created to audit n8n instances. The core tool relies on data returned from multiple endpoints that self-report information; secrets matched by regex are reported the same way. None of the information reported by the passive checks is presumed — it's only flagged if supporting information is actually returned by the n8n instance. The opt-in active flags (`--test-cred`, `--userpass`, `--check-lockout`, `--webhook-brute`) are a deliberate exception to that "read-only" posture and should be represented as such: they are authentication attempts and, in the case of `--webhook-brute`, live workflow invocations — not passive observation.

## Scope and safety notes

- By default, every check is a `GET` request except the endpoint sweep's method-tampering follow-up (`HEAD`, on paths that already came back protected on `GET`) and the optional `--test-cred`, which sends exactly one `POST /rest/login` with the credentials you supply.
- `--userpass` and `--check-lockout` send real authentication attempts against `/rest/login`. Both are paced (`--brute-delay`, default 1s) but can still trip a real account lockout policy or generate a burst of auth-failure log entries — confirm this is within scope and, ideally, that you know the target's lockout policy before running either broadly.
- `--webhook-brute` is the most consequential active flag in the tool: a non-miss result is a genuine, live invocation of whatever that workflow does, not recon. It can send real emails, hit real third-party APIs, or execute arbitrary code if the workflow itself is the RCE vector you're trying to prove. Treat every hit as something that already happened on the client's system, not just a finding to write down.
- Secret values are masked by default specifically so they don't end up on a shared screen or in a screenshot during report review; use `--reveal-secrets` deliberately when you need the real value.
- This tool identifies exposure and misconfiguration, and — via the opt-in active flags — the two preconditions (creds or a webhook) that several n8n RCE-class CVEs need. It does not itself attempt exploitation of any CVE. If you want to check a specific CVE, use `--nuclei` (official, signed templates) rather than hand-rolled payloads.
- Use only against hosts you are authorized to test.

## Roadmap / ideas

- Normalize duplicate origins in `--eyewitness` mode (e.g. `host` and `host:80` currently probe separately)
- Optional concurrency for large `--file`/`--eyewitness` runs
- CSV output alongside `--json`
- Bundle a default webhook-path wordlist with the repo
- Follow-up basic-auth guessing against `--webhook-brute` hits that come back `AUTH-REQUIRED`

</div>

<hr>
<div align="center">
Made with ❤️ by The Heretic
</div>
