# H1DorkCollector

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Automated HackerOne Hacktivity report-link collector.**
Pull *every* publicly disclosed report for a vulnerability class (XSS, SSRF, RCE, …)
through the official HackerOne API — with a completeness guarantee,
crash-safe resumable runs, and multi-engine fallbacks.

> **Tip:** add a screenshot or GIF of a live run here — READMEs with visuals
> get far more traction.

## Why

Bug bounty research, attack-surface study, write-up mining ("how do people
actually find stored XSS at Shopify?") all start from the same thing:
**a complete list of disclosed reports**. The Hacktivity UI is infinite
scroll and won't give you everything. This tool takes a vulnerability class
and gets you all of it — and *proves* it got all of it.

## Features

- **Completeness by construction** — paginates until the API's natural end.
  If a deep-pagination wall is hit, it attacks the result set from both ends
  (descending + ascending sort) and *verifies* the two passes actually meet
  before claiming the collection is complete
- **One query per weakness** — avoids the silent ~950-item truncation that
  big OR-group queries hit on this API
- **Ctrl+C-safe / crash-safe** — every fetched page is checkpointed to disk
  instantly (`<output>.partial.jsonl`)
- **Resume** — re-run the same command after an interrupt: finished queries
  are skipped, the interrupted one continues where it stopped
- **4 engines** — official HackerOne API (recommended), Google Custom Search,
  SerpAPI, HackerOne GraphQL
- **Sane defaults** — 429/Retry-After handling, exponential backoff,
  respects the server's 50-items/page cap
- **Output formats** — human-readable txt, links-only txt, JSON, JSONL, CSV

## Requirements

- Python 3.9+
- A free [HackerOne](https://hackerone.com) account + API token
- `requests` (auto-installed on first run if missing)

## Setup — HackerOne API token (free, ~2 minutes)

Log in to your HackerOne account, go to
**https://hackerone.com/settings/api_token/edit**, and click
**Create API token**. Then export your credentials:

    export H1_USERNAME="your_hackerone_username"
    export H1_TOKEN="your_api_token"

Add those two lines to your `~/.bashrc` or `~/.zshrc` to make them permanent.

### Optional engines

| Engine | Env variables | Where to get them | Free tier |
|---|---|---|---|
| `google-cse` | `GOOGLE_API_KEY`, `GOOGLE_CSE_ID` | [Google Cloud console](https://console.cloud.google.com/apis/credentials) + [Programmable Search Engine](https://programmablesearchengine.google.com/) (restrict it to `hackerone.com`) | 100 req/day |
| `serpapi` | `SERPAPI_KEY` | [serpapi.com](https://serpapi.com/) | 100 req/month |
| `hackerone-gql` | none | — (unofficial internal API, may break) | — |

## Usage

    # every disclosed XSS report (the classic)
    python3 h1dork.py --cwe-preset xss -o xss_all.txt

    # SSRF, exported as CSV
    python3 h1dork.py --cwe-preset ssrf --format csv -o ssrf.csv

    # single weakness by name
    python3 h1dork.py -v "SQL Injection"

    # raw Lucene query (Hacktivity syntax)
    python3 h1dork.py --query 'cwe:"SSRF" AND disclosed:true'

    # only the links, one per line (pipe-friendly)
    python3 h1dork.py --cwe-preset idor --links-only -o idor_urls.txt

    # a list of vulnerability names from a file
    python3 h1dork.py --vuln-list vulns.txt

    # list all built-in presets
    python3 h1dork.py --list-presets

Typical run: the `xss` preset fires 5 queries (one per weakness variant)
and takes ~3–5 minutes with the default 0.6 s delay.

### Interrupted a run?

Just re-run **the same command**:

- completed queries are skipped instantly (from the checkpoint)
- the interrupted query resumes mid-pagination
- when everything is done, the checkpoint is removed automatically

Force a fresh start with `rm <output>.partial.jsonl`.

## Built-in presets

| Preset | CWE | Weakness names |
|---|---|---|
| `xss` | 79 | Cross-Site Scripting (XSS) + DOM/Generic/Reflected/Stored variants |
| `sqli` | 89 | SQL Injection |
| `ssrf` | 918 | Server-Side Request Forgery (SSRF) |
| `idor` | 639 | Insecure Direct Object Reference (IDOR) |
| `rce` | 78, 94 | Remote Code Execution, Code Injection |
| `xxe` | 611 | XML External Entities (XXE) |
| `csrf` | 352 | Cross-Site Request Forgery (CSRF) |
| `open-redirect` | 601 | Open Redirect |
| `path-traversal` | 22, 23, 35, 36 | Path Traversal |
| `cmd-injection` | 78 | Command Injection - Generic, OS Command Injection |
| `auth-bypass` | 287, 288, 290, 303 | Authentication Bypass variants |
| `info-disclosure` | 200, 209, 532 | Information Disclosure variants |
| `privesc` | 269 | Privilege Escalation |
| `race-condition` | 362, 367 | Race Condition, TOCTOU |
| `subdomain-takeover` | — | Subdomain Takeover |
| `business-logic` | 840 | Business Logic Errors |
| `broken-access` | 862, 863, 732 | Secure Design / Access Control |

## How completeness is guaranteed

1. **Pass 1** paginates newest → oldest until the API returns a partial or
   empty page → natural end → the whole set is retrieved (this covers
   everything under ~1900 results per weakness name — the common case)
2. If a **deep-pagination wall** is hit instead, **pass 2** paginates
   oldest → newest; if the two passes overlap, their union is provably the
   full set. An ascending-sort sanity check runs first — no false
   "complete" claims
3. If the passes don't meet, the script tries **date-window bisection**
   (support is probed at runtime) and tells you honestly if it can't
   recover the middle slice

## Observed HackerOne API behavior (undocumented)

Facts this tool is built around — discovered empirically, not in the docs:

- `page[size]` is server-capped at **50**; requesting 100 *shrinks* the
  reachable pagination window
- **simple single-term queries** (`cwe:"..."`) paginate to their natural end
- **OR-group queries** (`cwe:("A" OR "B" ...)`) silently truncate around
  ~950–1000 items — hence the one-query-per-weakness design
- the `cwe:` filter matches weakness **names**, case-insensitively
- `cwe:<number>` (e.g. `cwe:79`) is **not** supported
- deep-pagination is silent: the API returns `data: []` instead of an error

## FAQ

**Why do I get fewer results than the Hacktivity UI shows?**

The `cwe:` filter does exact weakness-name matching against H1's taxonomy.
If a report is tagged with a name you're not querying (or no name at all),
it won't match. Check the exact string in the Hacktivity weakness filter
dropdown or on any report's *Weakness* field, then query it with `--query`.

**Where is SSTI?**

There is no SSTI entry in H1's weakness taxonomy. Server-side template
injection reports are tagged *Code Injection* / *Remote Code Execution*
(consequence-based taxonomy), and client-side template injection is tagged
*XSS*. Collect `rce` + `xss` and filter titles:

    grep -ihE "ssti|template|jinja|twig|freemarker|velocity|mako|smarty" \
      -A1 rce_all.txt xss_all.txt | grep "URL:" | awk '{print $2}' | sort -u

**How do I add my own vulnerability class?**

Find the exact weakness name (Hacktivity filter dropdown → type it in),
probe it cheaply (`--query 'cwe:"My Weakness" AND disclosed:true'` — a bad
name costs one request), then add it to the `CWE_PRESETS` dict in
`h1dork.py`.

**Rate limits?**

429s are handled automatically with `Retry-After`. Keep the default
`--delay 0.6` — you're a guest on their API.

## Legal & responsible use

- This tool only queries **publicly disclosed** Hacktivity data, through
  **HackerOne's official API**, using **your own credentials**
- Respect the HackerOne API terms of use and rate limits
- Don't use the collected data to harass programs or researchers
- Provided for research and educational purposes; no liability for misuse

## License

MIT — see [LICENSE](LICENSE).
