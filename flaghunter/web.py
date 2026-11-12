import uuid
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from .service import scan
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title='FlagHunter')
JOBS = {}

class ScanRequest(BaseModel):
    url: str | None = None
    path: str | None = None
    authorized: bool = False
    allow_private: bool = False
    ai: bool = False

HTML = r'''<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>FlagHunter</title>
<style>
body{font:16px system-ui;max-width:740px;margin:4rem auto;padding:0 18px;background:#0d1423;color:white}
input:not([type=checkbox]){padding:12px;width:100%;margin:8px 0;background:#1b2940;color:white;border:1px solid #54627a;border-radius:6px;box-sizing:border-box}
button{background:#3989d3;color:white;border:0;padding:12px 20px;border-radius:6px;cursor:pointer}button:disabled{opacity:.55;cursor:wait}
label{display:block;margin:14px 0}a{color:#9bd4ff}pre{white-space:pre-wrap;overflow-wrap:anywhere}
</style></head><body>
<h1>🛡 FlagHunter</h1><p>Authorized passive CTF site and file scanner</p>
<label>URL (for web scan)<input id="url" placeholder="http://127.0.0.1:8000"></label>
<label>Local path (instead of URL)<input id="path" placeholder="examples"></label>
<label><input type="checkbox" id="authorized"> I am authorized to scan this URL</label>
<label><input type="checkbox" id="allow_private"> Allow localhost/private lab targets</label>
<label><input type="checkbox" id="ai"> Gemini AI review</label>
<button id="scanBtn" type="button" onclick="run()">Scan</button>
<pre id="result" role="status" aria-live="polite"></pre>
<script>
async function run() {
  const el = document.getElementById('result');
  const btn = document.getElementById('scanBtn');
  el.textContent = 'Scanning...';
  btn.disabled = true;
  try {
    const data = {
      url: document.getElementById('url').value.trim() || null,
      path: document.getElementById('path').value.trim() || null,
      authorized: document.getElementById('authorized').checked,
      allow_private: document.getElementById('allow_private').checked,
      ai: document.getElementById('ai').checked
    };
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(data)
    });
    const json = await response.json();
    if (!response.ok) throw new Error(json.detail ? String(json.detail) : JSON.stringify(json));
    el.textContent = `Scanned: ${json.scanned}; findings: ${json.findings}; errors: ${json.errors}\n`;
    const link = document.createElement('a');
    link.href = json.report;
    link.textContent = 'Open HTML report';
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    el.appendChild(link);
  } catch (error) {
    el.textContent = 'Error: ' + error.message;
  } finally {
    btn.disabled = false;
  }
}
</script></body></html>'''

@app.get('/', response_class=HTMLResponse)
async def home():
    return HTML

@app.post('/api/scan')
async def api_scan(req: ScanRequest):
    if bool(req.url) == bool(req.path):
        raise HTTPException(400, 'Provide URL or path, not both')
    if req.url and not req.authorized:
        raise HTTPException(400, 'Authorization confirmation required')
    if req.path:
        allowed = (Path.cwd() / 'examples').resolve()
        target = Path(req.path).resolve()
        if target != allowed and allowed not in target.parents:
            raise HTTPException(400, 'Web UI file scans restricted to ./examples; use CLI for other paths')
    job = uuid.uuid4().hex
    try:
        result, report = await scan(
            url=req.url, path=req.path, authorized=req.authorized,
            allow_private=req.allow_private, ai=req.ai,
            out=f'output/{job}', max_pages=15, max_depth=2
        )
    except (ValueError, OSError) as error:
        raise HTTPException(400, str(error)) from error
    JOBS[job] = str(report)
    return {
        'job': job, 'scanned': len(result.scanned),
        'findings': len(result.findings), 'errors': len(result.errors),
        'report': f'/reports/{job}'
    }

@app.get('/reports/{job}')
async def report(job: str):
    if job not in JOBS:
        raise HTTPException(404, 'Unknown report')
    return FileResponse(JOBS[job], media_type='text/html')
