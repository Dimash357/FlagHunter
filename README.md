# FlagHunter v1.0 — CTF Site + File Analyzer

A **working passive MVP**, not an exploit framework or a guarantee of finding every vulnerability. Covers ten requested vulnerability families with heuristic signatures, extracts forms/links, flags possible CTF tokens, produces HTML/JSON reports and optionally requests Gemini feedback. All detections are **candidates**, not proven vulnerabilities. It does **not** brute-force, exploit, upload payloads, access private data, or extract remote flags.

## Windows setup (CMD)

```bat
cd FlagHunter_Full
py -3 -m venv env
env\Scripts\activate
python -m pip install -r requirements.txt
copy .env.example .env
```

Edit `.env` with Notepad, add your own key to `GEMINI_API_KEY`. Never commit `.env`.

> `gemini-3.5-flash-lite` is a **configurable model ID**, not guaranteed available to your account. If the API returns 404/503, change `GEMINI_MODEL` to a model available to your key. Rule-based analysis still works when AI fails. The implementation uses the Gemini `generateContent` endpoint; availability depends on the account and current API.

## Run

Analyze bundled sample files:

```bat
python -m flaghunter --path examples --out output
start output\report.html
```

Analyze any local folder:

```bat
python -m flaghunter --path "C:\path\to\ctf-files" --ai --out output
```

Analyze your own local web app (must be running):

```bat
python -m flaghunter --url http://127.0.0.1:8000 --authorized --allow-private --ai --out output
```

Analyze an authorized public lab:

```bat
python -m flaghunter --url https://your-authorized-lab.example --authorized --out output
```

Launch dashboard:

```bat
uvicorn flaghunter.web:app --host 127.0.0.1 --port 8787
```

Open http://127.0.0.1:8787. The web UI restricts file paths to `examples/`. For arbitrary local folders use the CLI. Do not expose the dashboard to the Internet.

## Tests

```bat
python -m unittest discover -s tests -v
```

## Modules

- `analyzer.py`: file and HTML/form parsing
- `crawler.py`: limited same-host GET-only crawler, no redirects, DNS/IP validation, bounded depth
- `rules.py` + `rules/patterns.yaml`: 10 vulnerability-category heuristics and CTF flag detection
- `ai.py`: optional Gemini reviewer of ambiguous findings; errors never stop scanning
- `report.py`: HTML and JSON
- `web.py`: local dashboard
- `__main__.py`: CLI

## Security & limitations

- Authorized systems only. URL scans require `--authorized`.
- The crawler performs GET requests only, but GET can still cause side effects on poorly designed sites. Scan isolated labs.
- No credentialed sessions, no automatic exploitation, no remote flag extraction, no verified IDOR/auth bypass tests.
- A reference to `/admin` or an `innerHTML` assignment is **not proof** of a vulnerability.
- Private networks and localhost require `--allow-private`; DNS checks reduce but do not fully eliminate rebinding risks. Do not use as a multi-user hosted service.
- The AI receives only sanitized category/title/confidence metadata, not raw page contents or credentials.
- File analysis supports text-like extensions, skips large files and common dependency folders; no ZIP extraction to avoid archive traversal and decompression bombs. Unzip trusted challenge bundles manually first.
- Pattern rules are extensible YAML; adapt to your own labs.

## Next development steps

Add structured authenticated role-differential checks, AST-based taint analysis, reproducible test fixtures per vulnerability, and optional consent-gated active probes. Keep candidate vs confirmed findings separate.
