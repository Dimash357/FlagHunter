# 🛡 FlagHunter v2 — Web Jeopardy CTF triage scanner

Paste a CTF challenge URL → FlagHunter maps the app, names the **most likely
vulnerabilities**, shows the **entry point, confidence and evidence**, and hands
you a **step-by-step manual-verification plan with ready Linux/Kali commands**.

It is a **triage and guidance** tool for **authorized** targets, not an
auto-exploitation framework. It never claims a vulnerability is *confirmed*
without reproducible evidence, and it never extracts protected data or posts a
flag for you.

Built for the real CTF workflow: your team gets VPN access to a lab network, you
open a challenge on the platform, copy the target web app's URL into FlagHunter,
and it tells you where to look first. It scans **only the target you give it** —
never the competition platform.

## Supported vulnerability classes (exactly these 10)

| # | Category | Local detection | Safe active check |
|---|----------|-----------------|-------------------|
| 1 | SQL Injection | DB-error signatures, query params | single-quote error diff |
| 2 | Cookie-based Auth Bypass | privilege cookies, JWTs | — (manual: flip value) |
| 3 | IDOR | numeric id params | — (manual: two accounts) |
| 4 | XSS | reflected params, DOM sinks | marker reflection (unencoded) |
| 5 | Unrestricted File Upload | file-input forms | — (manual: type bypass) |
| 6 | SSRF | url/redirect/webhook params | — (manual: listener) |
| 7 | Command Injection | shell primitives, `id`/`uname` output | time-based `sleep` (opt-in confirm) |
| 8 | Broken Access Control | admin routes reachable (200) | — (manual: role diff) |
| 9 | XXE | XML surfaces, entity signatures | — (manual: entity probe) |
| 10 | SSTI | render-string sinks, engine errors | arithmetic marker (`{{7*7}}→49`) |

## How it works

```
URL ─▶ scope guard ─▶ crawler ─▶ local detectors ─▶ flag hints ─▶ (opt) active probes ─▶ playbooks ─▶ (opt) AI ─▶ report
         │               │            │                                   │                              │
    hosts/ports/     pages, forms,  signatures +                    reflection / DB-error /         Gemini reviews only
    VPN, redirects   params, cookies, structural reasoning          template-math evidence          ambiguous findings
                     JS & API eps    (most-likely + entry point)
```

* **Local detectors run first.** Gemini (optional) only reviews *ambiguous*
  findings and adds caveats — it never replaces the rule engine and never sees
  raw bodies, cookies or secrets.
* **Confidence & status** are explicit: `candidate` (pattern/structure) →
  `indicator` (weak active signal) → `evidence` (reproducible, e.g. input
  reflected verbatim). Nothing is labelled a confirmed exploit automatically.
* **Scope is enforced on every request** (including each redirect hop), so a
  scan can't wander onto the platform or an out-of-scope host.

## Setup (Linux / Kali)

```bash
git clone <your-fork-url> FlagHunter && cd FlagHunter
./scripts/setup.sh          # creates .venv, installs deps, copies .env, runs tests
. .venv/bin/activate
```

Manual equivalent:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env        # optional: add GEMINI_API_KEY for AI review
```

Gemini is optional — leave `GEMINI_API_KEY` empty to run fully offline.

## Usage (CLI)

Scan an authorized challenge on a VPN lab network (private IPs + any port):

```bash
python -m flaghunter --url http://10.10.14.7:8080/ --authorized --allow-private --active
```

Non-standard port, explicitly allowed:

```bash
python -m flaghunter --url http://10.10.14.7:31337/ --authorized --allow-private --ports 31337 --active
```

Add the opt-in intrusive time-based command-injection probe (benign `sleep`):

```bash
python -m flaghunter --url http://target/ --authorized --allow-private --active --confirm-intrusive
```

Analyze a downloaded/extracted challenge bundle (source files):

```bash
python -m flaghunter --path ./challenge_src --ai
```

Key flags:

| Flag | Meaning |
|------|---------|
| `--authorized` | **Required** for URL scans — you confirm you may test it |
| `--allow-private` | allow private / VPN / loopback targets |
| `--allow-any-port` / `--ports 8081,9000` | allow non-standard ports |
| `--host H` | add another in-scope host (repeatable) |
| `--active` | safe active checks (reflection, DB errors, template math) |
| `--confirm-intrusive` | also run the time-based `sleep` probe (implies `--active`) |
| `--ai` | Gemini review of ambiguous findings |
| `--max-pages` / `--max-depth` / `--timeout` | crawl bounds |

Reports are written to `output/<...>/report.html` (interactive) and
`report.json`.

## Usage (dashboard)

```bash
uvicorn flaghunter.web:app --host 127.0.0.1 --port 8787
# open http://127.0.0.1:8787
```

The dashboard shows **live scan progress**, a **category breakdown**, **filters**
(by category and status), **evidence**, **copy-able commands**, the **AI review**
panel, and **JSON/HTML export**. File-path scans in the UI are restricted to
`./examples`; use the CLI for arbitrary folders. Do not expose the dashboard to
the internet.

## What a finding gives you

Each finding carries: category, entry point (`param` / `cookie:name` / `body`),
method, severity, confidence, status, evidence, and a playbook:

```
[SSTI] evidence (conf 0.85)
  GET http://target/render  entry: name
  evidence: Template arithmetic evaluated server-side (fh9k3x{{7*7}} -> fh9k3x49)

  Manual verification
   1. Inject fh{{7*7}} / fh${7*7} / fh<%= 7*7 %> into the `name` parameter.
   2. If the response contains 'fh49', it was evaluated server-side (SSTI).
   ...
  Commands
   curl -sik 'http://target/render?name=fh%7B%7B7%2A7%7D%7D' | grep -n fh49
   ...
  Expected
   Vulnerable: the response shows 'fh49'. Safe: the literal fh{{7*7}} is returned.
```

## CTF flag hints

FlagHunter surfaces *where a flag might be* using only content already fetched —
flag-format tokens (value redacted), interesting HTML comments, hidden fields,
JS variables, `robots.txt`/`sitemap` paths, and suspicious files (`.bak`, `.git`,
`/backup`, …). It does **not** auto-exploit or extract protected data.

## Modules

| File | Role |
|------|------|
| `scope.py` | scope/VPN/port enforcement, redirect validation |
| `http_client.py` | compression, manual in-scope redirects, size caps |
| `crawler.py` | pages, forms, params, cookies, JS & API endpoints, dedup |
| `rules.py` + `rules/patterns.yaml` | response-oriented signatures (10 cats) |
| `detectors.py` | passive + structural detectors + safe active prober |
| `playbook.py` | manual steps + Kali/curl commands + expected result |
| `flaghints.py` | non-exploitative flag-location hints |
| `ai.py` | optional Gemini review of ambiguous findings |
| `report.py` + `ui.py` | JSON + interactive HTML report / dashboard renderer |
| `web.py` | FastAPI dashboard with live progress |
| `analyzer.py` | local file / bundle analysis |

## Tests

```bash
python -m unittest discover -s tests -v
```

Includes end-to-end tests against a bundled vulnerable fixture app
(`tests/fixture_app.py`) that exercise the crawler, structural detectors and the
active prober (reflected XSS, error-based SQLi, SSTI).

## Safety & limitations

- **Authorized targets only.** URL scans require `--authorized`. Scan the
  challenge, never the platform. Scope is re-checked on every request/redirect.
- Active checks are **observational** in the safe tier (benign markers, a single
  quote, template arithmetic). Potentially intrusive checks require
  `--confirm-intrusive`, and even then stay benign (a `sleep`).
- FlagHunter does **not** auto-exploit, bypass auth, upload shells, read
  protected files, or extract/submit flags — those are manual steps it hands you.
- Signatures are heuristics; a `/admin` link or an `innerHTML=` is **not** proof.
  Verify every finding with the provided steps.
- No ZIP auto-extraction (decompression-bomb / traversal safety) — unpack trusted
  bundles yourself first.
- The crawler issues GET requests only; GET can still have side effects on poorly
  built apps, so scan isolated lab targets.

## License

See `LICENSE`.
