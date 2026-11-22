"""FastAPI dashboard.

Starts a scan as a background job and streams progress to the browser, then
renders the result with the shared renderer (filters, evidence, copy-able
commands, AI review, JSON/HTML export). File-path scans are restricted to
``./examples`` for safety; use the CLI for arbitrary local folders.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel

from .scope import ScopeError, parse_ports
from .service import scan
from .ui import REPORT_CSS, REPORT_JS

load_dotenv()

app = FastAPI(title="FlagHunter")
JOBS: dict[str, dict] = {}


class ScanRequest(BaseModel):
    url: str | None = None
    path: str | None = None
    authorized: bool = False
    allow_private: bool = False
    allow_any_port: bool = False
    ports: str | None = None
    active: bool = False
    confirm_intrusive: bool = False
    ai: bool = False
    max_pages: int = 20
    max_depth: int = 2


async def _run_job(job_id: str, req: ScanRequest) -> None:
    job = JOBS[job_id]

    def on_progress(p: dict) -> None:
        job["progress"] = p
        job["phase"] = "crawling"

    try:
        job["phase"] = "starting"
        ports = parse_ports(req.ports) if req.ports else set()
        result, report = await scan(
            url=req.url, path=req.path, authorized=req.authorized,
            allow_private=req.allow_private, allow_any_port=req.allow_any_port,
            ports=ports, active=req.active, confirm_intrusive=req.confirm_intrusive,
            ai=req.ai, out=f"output/{job_id}",
            max_pages=max(1, min(req.max_pages, 60)),
            max_depth=max(0, min(req.max_depth, 4)),
            on_progress=on_progress,
        )
        job["phase"] = "done"
        job["state"] = "done"
        job["report"] = str(report)
        job["result"] = result.to_dict()
    except (ValueError, ScopeError, OSError) as exc:
        job["state"] = "error"
        job["phase"] = "error"
        job["error"] = str(exc)
    except Exception as exc:  # noqa: BLE001
        job["state"] = "error"
        job["phase"] = "error"
        job["error"] = f"{type(exc).__name__}: {exc}"


@app.post("/api/scan")
async def api_scan(req: ScanRequest):
    if bool(req.url) == bool(req.path):
        raise HTTPException(400, "Provide a URL or a path, not both")
    if req.url and not req.authorized:
        raise HTTPException(400, "Authorization confirmation required for URL scans")
    if req.path:
        allowed = (Path.cwd() / "examples").resolve()
        target = Path(req.path).resolve()
        if target != allowed and allowed not in target.parents:
            raise HTTPException(400, "Web UI file scans are restricted to ./examples; use the CLI for other paths")
    job_id = uuid.uuid4().hex
    JOBS[job_id] = {"state": "running", "phase": "queued", "progress": {}, "error": None}
    asyncio.create_task(_run_job(job_id, req))
    return {"job": job_id}


@app.get("/api/scan/{job_id}")
async def api_status(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Unknown job")
    return JSONResponse({
        "state": job["state"], "phase": job.get("phase"),
        "progress": job.get("progress", {}), "error": job.get("error"),
        "result": job.get("result"),
    })


@app.get("/reports/{job_id}.json")
async def report_json(job_id: str):
    job = JOBS.get(job_id)
    if not job or not job.get("result"):
        raise HTTPException(404, "Unknown report")
    return JSONResponse(job["result"])


@app.get("/reports/{job_id}")
async def report_html(job_id: str):
    job = JOBS.get(job_id)
    if not job or not job.get("report"):
        raise HTTPException(404, "Unknown report")
    return FileResponse(job["report"], media_type="text/html")


PAGE = """<!doctype html><html lang="ru"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>FlagHunter</title><style>__CSS__
.form{display:grid;grid-template-columns:1fr 1fr;gap:10px 16px;background:var(--panel);
border:1px solid var(--line);border-radius:12px;padding:16px;margin:10px 0}
.form label{display:flex;gap:8px;align-items:center;font-size:13px;color:var(--muted)}
.form .full{grid-column:1/-1}
.form input[type=text],.form input[type=number]{width:100%;padding:10px;background:#0f1b30;color:var(--ink);
border:1px solid var(--line);border-radius:8px}
.run{background:var(--accent);color:#05101f;border:0;border-radius:8px;padding:11px 20px;font-weight:600;cursor:pointer}
.run:disabled{opacity:.5;cursor:wait}
.prog{height:8px;background:#22314d;border-radius:5px;overflow:hidden;margin:8px 0}
.prog>i{display:block;height:100%;width:0;background:linear-gradient(90deg,#5cc0ff,#5cff9f);transition:width .3s}
@media(max-width:620px){.form{grid-template-columns:1fr}}
</style></head><body><div class="wrap">
<h1>🛡 FlagHunter</h1>
<p class="sub">Authorized Web Jeopardy CTF scanner &middot; paste the challenge URL, triage likely vulns, get manual-verification commands.</p>
<p class="note">Scan only the authorised CTF target. Do not scan the competition platform. URL scans require the authorization checkbox.</p>
<div class="form">
  <label class="full">Target URL <input type="text" id="url" placeholder="http://10.10.14.7:8080/"></label>
  <label class="full">…or local path (./examples only in UI) <input type="text" id="path" placeholder="examples"></label>
  <label><input type="checkbox" id="authorized"> I am authorized to scan this target</label>
  <label><input type="checkbox" id="allow_private"> Allow private / VPN / localhost</label>
  <label><input type="checkbox" id="active"> Safe active checks (reflection / errors)</label>
  <label><input type="checkbox" id="confirm_intrusive"> Confirm intrusive probe (time-based)</label>
  <label><input type="checkbox" id="allow_any_port"> Allow any port</label>
  <label>Extra ports <input type="text" id="ports" placeholder="8081,9000"></label>
  <label>Max pages <input type="number" id="max_pages" value="20" min="1" max="60"></label>
  <label>Max depth <input type="number" id="max_depth" value="2" min="0" max="4"></label>
  <label><input type="checkbox" id="ai"> Gemini AI review (ambiguous only)</label>
  <div class="full"><button class="run" id="run">Scan</button>
    <a class="btn ghost" id="full" target="_blank" rel="noopener" style="display:none">Open full report ↗</a></div>
</div>
<div id="status" class="small muted"></div>
<div class="prog" id="progwrap" style="display:none"><i id="progbar"></i></div>
<div id="root"></div>
</div>
<script>__JS__</script>
<script>
const $=id=>document.getElementById(id);
function val(id){return $(id).value.trim();}
function chk(id){return $(id).checked;}
async function run(){
  const btn=$('run');btn.disabled=true;$('root').innerHTML='';$('full').style.display='none';
  $('progwrap').style.display='block';$('progbar').style.width='3%';
  $('status').textContent='Starting…';
  const body={url:val('url')||null,path:val('path')||null,authorized:chk('authorized'),
    allow_private:chk('allow_private'),allow_any_port:chk('allow_any_port'),ports:val('ports')||null,
    active:chk('active'),confirm_intrusive:chk('confirm_intrusive'),ai:chk('ai'),
    max_pages:parseInt(val('max_pages')||'20'),max_depth:parseInt(val('max_depth')||'2')};
  let start;
  try{
    const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    start=await r.json();
    if(!r.ok)throw new Error(start.detail||JSON.stringify(start));
  }catch(e){$('status').textContent='Error: '+e.message;btn.disabled=false;$('progwrap').style.display='none';return;}
  const job=start.job;
  const poll=setInterval(async()=>{
    const s=await(await fetch('/api/scan/'+job)).json();
    const p=s.progress||{};
    if(s.phase==='crawling'&&p.max_pages){
      const pct=Math.min(90,Math.round((p.fetched/p.max_pages)*90));
      $('progbar').style.width=Math.max(5,pct)+'%';
      $('status').textContent=`Crawling… ${p.fetched}/${p.max_pages} pages, ${p.findings||0} findings · ${p.current||''}`;
    }else{$('status').textContent='Phase: '+(s.phase||s.state);}
    if(s.state==='done'){clearInterval(poll);$('progbar').style.width='100%';
      $('status').textContent='Done.';btn.disabled=false;
      $('full').href='/reports/'+job;$('full').style.display='inline-block';
      renderResult(s.result,$('root'));setTimeout(()=>$('progwrap').style.display='none',600);}
    if(s.state==='error'){clearInterval(poll);$('status').textContent='Error: '+(s.error||'scan failed');
      btn.disabled=false;$('progwrap').style.display='none';}
  },700);
}
$('run').addEventListener('click',run);
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
async def home():
    return PAGE.replace("__CSS__", REPORT_CSS).replace("__JS__", REPORT_JS)
