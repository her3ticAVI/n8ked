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
<h4><code>n8ked</code> is an unauthenticated exposure and misconfiguration auditor for <a href="https://n8n.io">n8n</a> instances found during external/internal recon. It starts from n8n's by-design unauthenticated endpoints, checks whether endpoints that shouldn't be reachable without a login actually are, scans what comes back for hardcoded secrets, and — as opt-in, clearly-flagged active checks — can test credentials, discover unauthenticated webhook triggers, and check the fingerprinted version against a curated database of known n8n CVEs, printing the exact command to attempt each one it finds. Once a credential check or brute force actually succeeds, the same session can optionally be handed off to the <code>auth</code> subcommand for read-only, authenticated follow-up — enumerating scope, listing credential metadata, checking role permissions, and pulling workflows to scan for hardcoded secrets.</h4>
</p>

<div style="text-align: center;">
  <h4>
    <a target="_blank" href="#usage" rel="dofollow"><strong>Usage</strong></a>&nbsp;·&nbsp;
    <a target="_blank" href="#features" rel="dofollow"><strong>Features</strong></a>&nbsp;·&nbsp;
    <a target="_blank" href="#the-auth-subcommand" rel="dofollow"><strong>Auth Subcommand</strong></a>&nbsp;·&nbsp;
    <a target="_blank" href="#understanding-the-output" rel="dofollow"><strong>Understanding Output</strong></a>&nbsp;·&nbsp;
    <a target="_blank" href="#for-testers" rel="dofollow"><strong>For Testers</strong></a>&nbsp;·&nbsp;
    <a target="_blank" href="#scope-and-safety-notes" rel="dofollow"><strong>Scope &amp; Safety</strong></a>
  </h4>
</div>
<hr>
</div>

<div align="left">

## Why

Fingerprinting an n8n instance's version tells you if it's patched. It doesn't tell you whether someone left `/rest/workflows` reachable with no login, a hardcoded Slack token sitting in a node's parameters, or a webhook that fires a workflow for anyone who guesses the path. This checks for that — and, since several n8n RCE-class CVEs need either valid credentials or a reachable webhook to trigger, it can also test for both of those preconditions directly when you opt in. Once you have a version, `--poc` goes one step further: it checks that version against a small, curated database of real, currently-known n8n CVEs and prints the exact preconditions and command to attempt each one that matches — sourced from public vendor/researcher advisories, not guessed.

Finding valid credentials or a live webhook is usually where a tool like this stops and a manual follow-up begins. `n8ked` now bridges that gap a little: a successful `--test-cred` or `--userpass` hit can optionally save its session cookie, and the new `auth` subcommand can pick that session back up (or take fresh credentials directly) to run read-only, authenticated checks — how many workflows/credentials/users actually exist, what this account's role can do, and whether any workflow has a hardcoded secret sitting in it. It still doesn't create, edit, or run anything on the target; it just tells you what the compromised session can already see.

## Features

**Instance fingerprint** — version, release channel, instance ID, auth method, SSO config, health status. Recent n8n releases stopped disclosing `versionCli` (and several other fields) to unauthenticated callers, so when the REST API comes back empty on version the tool falls back to decoding the `n8n:config:sentry` meta tag n8n still ships on the root page, which nuclei's own `n8n-panel` template uses for the same reason.

**MFA posture** — enabled vs. enforced are flagged separately, and the tool distinguishes a confirmed `enforced: false` (High) from an instance that simply no longer discloses `mfa.*` fields unauthenticated (Low, flagged for manual/credentialed verification rather than assumed off).

**Access control sweep** — probes sensitive REST/API endpoints unauthenticated: `/rest/workflows`, `/rest/credentials`, `/api/v1/workflows`, `/rest/users`, `/rest/executions`, `/rest/active-workflows`, `/rest/owner`, `/rest/community-packages`, `/metrics`, and more. Each gets a verdict: `PROTECTED`, `EXPOSED`, `NOT-ENABLED`, or `EMPTY` — with guards against false positives from SPA catch-all routing and n8n's `{"data": []}` empty-response envelope.

**Secret scanning** — anything that comes back exposed is scanned for AWS keys, Slack tokens, JWTs, bearer tokens, PEM private key blocks, database connection strings, GitHub tokens, and generic password/secret/token fields. Matches are masked by default.

**Security headers & CORS** — HSTS, X-Frame-Options, X-Content-Type-Options, CSP, whether the service is even on TLS (redirect-aware), and credentialed reflection of arbitrary `Origin` headers.

**Single credential test** (`--test-cred`) — check exactly one pair against `/rest/login`.

**Credential brute force** (`--userpass`) — try a list of `user:pass` pairs against `/rest/login`, paced with a configurable delay, stopping at the first valid hit by default.

**Lockout/rate-limit probe** (`--check-lockout`) — fires a bounded, fixed number of bad-credential attempts and reports whether `/rest/login` ever throttles (HTTP 429) or just returns 401 indefinitely. Off by default since it's active and noisy.

**Webhook path discovery** (`--webhook-brute`) — tries a wordlist of candidate paths against the production webhook base across configurable HTTP methods, using n8n's own "not registered" 404 wording to separate real hits from misses. A hit here is a live trigger, not recon — see [Scope and safety notes](#scope-and-safety-notes) before using it.

**Session capture** (`--save-cookies`) — off by default. When a `--test-cred` or `--userpass` attempt actually succeeds, this persists the resulting session cookie to a file (tagged with which target it came from) so it can be picked back up later by the [`auth` subcommand](#the-auth-subcommand) without logging in again.

**Optional nuclei pass** (`--nuclei`) — runs nuclei's own signed `n8n`-tagged templates for known CVEs instead of any custom exploit logic.

**Known-CVE PoC lookup** (`--poc`) — checks the fingerprinted version against a small, hand-curated database of real, currently-known n8n CVEs and, for every match, prints the preconditions and the exact command(s) publicly documented to attempt it. **This only ever prints commands — it makes no additional requests to the target and never executes anything itself.**

**Multi-host** — scan a list of targets, or point it at an EyeWitness results folder and it'll find the n8n instances for you.

**Risk-scored output** — every finding gets Critical/High/Medium/Low, with a rollup summary at the end and an exit code that reflects the worst finding.

**Machine-readable output** — `--json` emits true JSONL and `--csv-out FILE` appends one CSV row per finding.

## Requirements

- `bash`, `curl` (with redirect support)
- `jq` **or** `python3` (JSON parsing — jq preferred, python3 fallback)
- `python3` specifically needed for secret scanning, the sentry-tag version fallback, `--csv-out`, the EyeWitness HTML/CSV parser, and every `auth` subcommand feature (`--enumerate`, `--list-credentials`, `--check-permissions`, `--export-workflows` all parse JSON via python3 — there's no jq fallback for these)
- GNU coreutils (`timeout`, `fold`)
- `awk`
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
./n8ked.sh auth <target> [options]
```

### Examples

```bash
# Single host
./n8ked.sh http://10.0.0.5:5678

# Single host, with one credential to test
./n8ked.sh 10.0.0.5:5678 --test-cred admin@example.com:changeme

# Same, but save the session if it's valid, for later authenticated follow-up
./n8ked.sh 10.0.0.5:5678 --test-cred admin@example.com:changeme --save-cookies

# Brute force a list of credentials and save the session on a hit
./n8ked.sh 10.0.0.5:5678 --userpass creds.txt --save-cookies

# List of hosts, JSON output piped to a file (one object per line)
./n8ked.sh --file scope-hosts.txt --json > results.jsonl

# CSV output instead (or alongside --json) — one row per finding
./n8ked.sh --file scope-hosts.txt --csv-out findings.csv

# Point it at an EyeWitness results folder — it finds the n8n instances for you
./n8ked.sh --eyewitness ~/engagements/acme/EyeWitness-Results

# Also run nuclei's n8n-tagged CVE templates
./n8ked.sh http://10.0.0.5:5678 --nuclei

# Check the detected version against known n8n CVEs and print PoC commands
./n8ked.sh http://10.0.0.5:5678 --poc

# Discover unauthenticated webhook triggers from a path wordlist
./n8ked.sh 10.0.0.5:5678 --webhook-brute paths.txt --webhook-methods GET,POST

# --- auth subcommand: pick up the session saved above ---

# Uses the default session slot automatically — no flags needed
./n8ked.sh auth 10.0.0.5:5678

# Log in fresh right now instead of relying on a saved session
./n8ked.sh auth 10.0.0.5:5678 --test-cred admin@example.com:changeme

# Enumerate real counts behind the authenticated endpoints
./n8ked.sh auth 10.0.0.5:5678 --enumerate

# Check what this account's role can actually do
./n8ked.sh auth 10.0.0.5:5678 --check-permissions

# Pull every workflow and scan it for hardcoded secrets
./n8ked.sh auth 10.0.0.5:5678 --export-workflows ./loot --reveal-secrets
```

### Options

| Flag | Description |
|---|---|
| `--file FILE` | Scan every host in `FILE`, one target per line |
| `--eyewitness DIR` | Pull candidate hosts from an EyeWitness results folder, probe each for n8n, and only run the full audit against confirmed hits |
| `--json` | Output one JSON object per host instead of the pretty terminal report |
| `--csv-out FILE` | Append one CSV row per finding to `FILE` |
| `--test-cred user:pass` | Try exactly one credential pair against `/rest/login` |
| `--userpass FILE` | Try every `user:pass` line in `FILE` against `/rest/login`. Stops at the first valid hit unless `--no-stop-on-success` is given |
| `--brute-delay SECONDS` | Delay between `--userpass` attempts (default: `1`) |
| `--no-stop-on-success` | With `--userpass`, keep testing remaining pairs after a valid hit |
| `--check-lockout` | Fire a handful of bad-credential attempts at `/rest/login` to check for rate-limiting/lockout. Off by default |
| `--webhook-brute FILE` | Try every path in `FILE` against the production webhook base. **A hit is a real, live invocation of that workflow** |
| `--webhook-methods LIST` | Comma-separated HTTP methods to try per path (default: `GET,POST`) |
| `--webhook-delay SECONDS` | Delay between `--webhook-brute` attempts (default: `0.3`) |
| `--include-test-webhooks` | Also try the `/webhook-test/` base in addition to `/webhook/` |
| `--save-cookies [FILE]` | On a successful `--test-cred`/`--userpass` hit, save the session cookie to `FILE` (default: `$N8KED_COOKIE`, or `~/.n8ked/session.cookie`). Off by default — nothing persists unless this is given |
| `--reveal-secrets` | Print full secret values instead of masked previews |
| `--nuclei` | Also run nuclei's `n8n`-tagged templates, if nuclei is installed |
| `--poc` | Check the fingerprinted version against known n8n CVEs and print PoC commands. **Only ever prints — never executes anything** |
| `--no-color` | Disable ANSI colors |
| `-h`, `--help` | Show usage |

## The `auth` subcommand

```
./n8ked.sh auth <target> [options]
```

Everything in the default scan mode is unauthenticated by design. `auth` is the other half: once you've established that a credential pair or brute-forced hit is valid, it runs read-only checks *as that authenticated session* — no exploitation, no workflow creation or execution, just enumeration of what the session can already reach.

### Getting a session

`auth` needs a session cookie to work with, resolved in this order:

1. **`--test-cred user:pass`** — logs in right now and uses the resulting session. No saved cookie file required.
2. **`--cookie-file FILE`** — uses that specific cookie jar directly, skipping login entirely.
3. **Nothing given** — falls back to a single, generic session slot: `$N8KED_COOKIE` if that environment variable is set, otherwise `~/.n8ked/session.cookie`. This is the same file scan mode's `--save-cookies` writes to by default — the intent is the same one-slot-by-default pattern `KRB5CCNAME` uses for a Kerberos ccache: capture a session once, and every later command just picks it up automatically.

Every saved cookie file is tagged with the target it was captured against (a small `.meta` sidecar next to it). If `auth` is run against a *different* target than the one the session was saved for, it warns loudly and refuses to continue unless `--force` is passed — the file could genuinely still work (n8n sessions aren't always host-bound), but this stops that from happening silently.

Before running any feature, `auth` does a liveness check against the target — if the session is expired or invalid, it says so immediately and exits rather than running every feature against a dead cookie.

### Options

| Flag | Description |
|---|---|
| `--test-cred user:pass` | Log in fresh right now and use that session |
| `--cookie-file FILE` | Use this specific cookie jar instead of the default/env-configured one |
| `--save-cookies` | With `--test-cred`, also persist the resulting session to the default slot (or `$N8KED_COOKIE`) |
| `--force` | Proceed even if the cookie file's saved target doesn't match the target given on this run |
| `--enumerate` | Re-check sensitive endpoints authenticated and report real counts — workflows, executions, users, credentials, active workflows. Default if no other feature flag is given |
| `--list-credentials` | List stored credential names/types. **Values remain encrypted at rest and are not retrievable even authenticated** — this is metadata only, for scoping impact, not a secrets dump |
| `--check-permissions` | Look up this account's role and whether it can create/edit workflows — directly confirms (or rules out) the authenticated precondition several `--poc` CVE entries need |
| `--export-workflows DIR` | Pull every workflow's full JSON to `DIR` and scan it for hardcoded secrets and credential references. Read-only `GET` requests only — nothing is created, edited, or run |
| `--reveal-secrets` | Print full secret values instead of masked previews |
| `--no-color` | Disable ANSI colors |
| `-h`, `--help` | Show usage |

### Why `--list-credentials` isn't a secrets dump

n8n encrypts credential values at rest with an instance-level encryption key. Even an authenticated pull of `/rest/credentials` returns names, types, and which nodes use them — never the decrypted secret. `--list-credentials` reports exactly that: useful for scoping ("this instance has a credential named `prod-aws-key`"), not for recovering values.

`--export-workflows` is where actual secrets tend to show up instead: it's extremely common for someone to skip the credential store entirely and paste an API key directly into a `Set` node, an HTTP Request node's headers, or a `Code` node body — none of which is encrypted. The same secret-scanning regex set used against unauthenticated exposure in scan mode runs against every exported workflow, flagging any hardcoded secret by workflow name and, where the surrounding JSON makes it identifiable, the node it was found in. It separately flags credential *references* (which node uses which stored credential) as a lower-severity, informational finding — useful context even when the referenced value itself is safely encrypted.

### What `auth` deliberately does not do

No workflow is created, edited, or executed, and no `--poc` command is run automatically even when `--check-permissions` confirms its precondition is met. That stays a manual, out-of-scope-by-default step, same as it already is for `--poc` in the base scan — `auth` only tells you what's true about the session and what it can see, not what you could do with it.

## How the EyeWitness mode works

`--eyewitness` reads `open_ports.csv` and any `report*.html` files in the given folder, extracts every unique host origin EyeWitness recorded, and sends a lightweight unauthenticated probe (`GET /rest/settings`) to each one. Only confirmed n8n instances get the full audit.

## How webhook path discovery works

`--webhook-brute` runs wordlist-style discovery against n8n's webhook base, using n8n's distinctive "is not registered" 404 body to separate real hits from misses far more reliably than a bare status code. Each hit gets one of four verdicts:

| Verdict | Meaning |
|---|---|
| `TRIGGERED` | 2xx response — the webhook fired successfully. This is a live, real invocation of that workflow |
| `ERROR` | 5xx response — the path/method is real and reachable, but the workflow errored on invocation |
| `AUTH-REQUIRED` | 401/403 — the path is confirmed to exist but has its own auth barrier |
| `TIMEOUT` | The request never came back — the workflow may still be executing |

## How the CVE PoC check works

`--poc` is a local lookup against the version already detected (plus any CVE IDs `--nuclei` confirmed), never an additional request to the target. Matching happens two ways:

- **Version-range match** — not independently confirmed against the live target; flagged as "verify manually."
- **Nuclei-confirmed** — an active probe already matched a real `CVE-YYYY-NNNNN` ID against the live target; takes priority over a version-range guess for the same CVE.

The database currently covers:

| CVE | Name | CVSS | Precondition |
|---|---|---|---|
| CVE-2025-68613 | n8n expression-sandbox escape → RCE | 9.9 | Authenticated (any role that can create/edit workflows) |
| CVE-2026-21858 ("Ni8mare") | Unauthenticated arbitrary file read → RCE chain | 10.0 | Needs a public-facing Form/Webhook workflow with a file-upload field — pair with `--webhook-brute` to find one |
| CVE-2026-21877 | Authenticated code injection, chainable with CVE-2026-21858 | Critical (unspecified CVSS) | Authenticated |
| CVE-2026-1470 | Expression-sandbox bypass via a decoy constructor in a `with` statement | 9.9 | Authenticated, workflow create/edit permission |

`auth --check-permissions` can directly confirm the "authenticated, workflow create/edit permission" precondition several of these need, rather than leaving it as "verify manually."

## Understanding the output

Every scan-mode report opens with a one-line severity scorecard right under the target header. Each endpoint in the access control sweep gets one of four verdicts: `PROTECTED`, `EXPOSED`, `EMPTY`, `NOT-ENABLED`.

Findings roll up into a severity-tagged summary at the end of each report:

- **Critical** — unauthenticated access to workflows/credentials/the public API, hardcoded secrets (unauthenticated *or* found via `auth --export-workflows`), credentialed CORS misconfiguration, valid tested/brute-forced credentials, a triggered unauthenticated webhook, a Critical-rated known-CVE match
- **High** — unauthenticated access to users/executions/active-workflow lists, plain HTTP with no TLS, setup wizard potentially still open, confirmed MFA not enforced, a registered webhook that errored on invocation, a High-rated known-CVE match, an `auth --check-permissions` role confirmed able to create/edit workflows (satisfies an authenticated RCE precondition)
- **Medium** — unauthenticated metrics/owner endpoint exposure, no rate-limiting observed on `/rest/login`, a webhook path confirmed to exist behind its own auth or that timed out, `auth --enumerate` confirming stored credentials exist on the instance
- **Low** — missing security headers, internal hostname disclosure, a live `webhook-test` endpoint, MFA posture that couldn't be determined, `auth --enumerate` confirming the full user list is enumerable, a workflow's credential *reference* found via `auth --export-workflows`

Exit codes: `0` = nothing Critical/High found, `1` = at least one Critical/High finding, `2` = target(s) couldn't be confirmed as n8n (scan mode only).

## For Testers

### Report language

Split it by what was actually run — the passive checks, the opt-in active flags, and `auth` mode carry different disclosure implications.

**Passive/read-only checks** (always run):

> n8ked was used to audit the n8n instance(s) in scope for unauthenticated exposure and misconfiguration. The tool issued read-only HTTP requests via curl against n8n's documented REST and API endpoints to determine whether access controls, MFA enforcement, CORS policy, and security headers were configured as expected, and inspected any data returned from unauthenticated requests for hardcoded secrets.

**If `--test-cred` or `--userpass` was used**, add:

> A limited number of credential pairs were tested against the instance's `/rest/login` endpoint to assess authentication strength. [State the number of pairs tested and their source.]

**If `--webhook-brute` was used**, add:

> A wordlist of candidate paths was tested against the instance's webhook endpoint(s) to determine whether any workflow could be triggered without authentication. Any path that returned a successful response represents a live invocation of the corresponding workflow at the time of testing. [Document which paths returned a hit, and coordinate with the client on any workflow that appears to have executed as a result.]

**If the `auth` subcommand was used following a successful credential test**, add:

> Following confirmation of valid credentials, the resulting authenticated session was used to enumerate the scope of access available to that account — including the number of workflows, credentials, and users visible, this account's role and permissions, and [if `--export-workflows` was used] a review of existing workflow definitions for hardcoded secrets. All requests in this phase were read-only (`GET`); no workflow was created, modified, or executed, and no credential values were retrieved (n8n's credential store remains encrypted at rest even to an authenticated session).

**If a `--poc`-printed command was subsequently run by hand to validate a finding**, add:

> [Name the specific CVE], reported by n8ked as a version-range/nuclei-confirmed match, was manually validated against the instance to confirm exploitability. [Document the exact command run, the target, the observed result, and confirm this was within the agreed scope and rules of engagement before it was attempted.]

### Defensibility of n8ked

The core tool relies on data returned from multiple endpoints that self-report information. `--poc` is passive: it makes no additional requests. The opt-in active flags (`--test-cred`, `--userpass`, `--check-lockout`, `--webhook-brute`) are the deliberate exception to that read-only posture and should be represented as such: they are authentication attempts and, in the case of `--webhook-brute`, live workflow invocations.

`auth` mode is a distinct third category, not a new form of access: it does nothing that wasn't already authorized the moment a credential test or brute force succeeded. It reuses that already-established, already-in-scope session to run `GET`-only enumeration — no new authentication attempts, no workflow creation or execution, and no credential values are ever retrieved (they stay encrypted at rest regardless of session). Document it as a distinct phase in your notes so a reviewer can see exactly where "found valid creds" ends and "used them to enumerate scope" begins.

## Scope and safety notes

- By default, every check is a `GET` request except the endpoint sweep's method-tampering follow-up and the optional `--test-cred`/`--userpass`, which send `POST /rest/login`.
- `--userpass` and `--check-lockout` send real authentication attempts and can trip a real account lockout policy — confirm this is within scope before running either broadly.
- `--webhook-brute` is the most consequential active flag in the base tool: a non-miss result is a genuine, live invocation of whatever that workflow does. Treat every hit as something that already happened on the client's system.
- `--poc` itself makes no additional requests — it only ever prints commands. Running a printed command by hand is genuine exploitation and needs the same scope confirmation as any other active technique here.
- **Session cookie files are as sensitive as a plaintext password** — anyone with the file has the same access as the account it was captured from, for as long as the session stays valid. `--save-cookies` writes with `chmod 600`, but treat the file (and the directory it lives in) accordingly: don't commit it, don't leave it on a shared box, and clean it up at the end of an engagement same as you would a captured credential.
- `auth` mode confirms and enumerates; it does not escalate. It never attempts a `--poc` command automatically, never creates or runs a workflow, and never retrieves a decrypted credential value — even when `--check-permissions` confirms the account *could* be used for more.
- Secret values are masked by default (both in scan mode and via `auth --export-workflows`); use `--reveal-secrets` deliberately when you need the real value.
- Use only against hosts you are authorized to test.

## Roadmap / ideas

- Normalize duplicate origins in `--eyewitness` mode
- Optional concurrency for large `--file`/`--eyewitness` runs
- Bundle a default webhook-path wordlist with the repo
- Keep the `--poc` CVE database current as new n8n CVEs are disclosed
- Machine-readable (`--json`) output for `auth` mode, matching scan mode's format
- Confirm a stable "who am I" endpoint across n8n versions for `auth --check-permissions` (currently falls back to `GET /rest/login`, which isn't verified stable on every release)
- Auto-annotate `--poc` CVE rows as "precondition confirmed" when a preceding `auth --check-permissions` run already established it, instead of "authenticated (verify manually)"
- Follow-up basic-auth guessing against `--webhook-brute` hits that come back `AUTH-REQUIRED`

</div>

<hr>
<div align="center">
Made with ❤️ by The Heretic
</div>
