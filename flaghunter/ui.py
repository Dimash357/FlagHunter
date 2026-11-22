"""Shared dashboard CSS + client-side renderer.

Both the static HTML report (:mod:`flaghunter.report`) and the live dashboard
(:mod:`flaghunter.web`) render findings with the same JavaScript, so the two
always look and behave identically. The renderer takes the scan result as a
plain dict (the JSON report) and builds: a summary bar, a "most likely"
panel, category/status filters, finding cards (evidence + numbered manual
steps + copy-able Kali commands + expected result), flag hints, endpoints,
cookies, the AI review and errors.
"""

from __future__ import annotations

REPORT_CSS = r"""
:root{--bg:#0d1423;--panel:#162339;--panel2:#1b2a44;--line:#2c3e5c;--ink:#e8edf7;
--muted:#9fb1cc;--accent:#5ca8ff;}
*{box-sizing:border-box}
body{font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--ink);margin:0}
.wrap{max-width:1080px;margin:0 auto;padding:22px 18px 80px}
h1{font-size:22px;margin:0 0 2px}h2{font-size:17px;margin:28px 0 10px;color:#bcd4f5}
a{color:#9bd4ff}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.sub{color:var(--muted);font-size:13px;margin:0 0 14px}
.bar{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 14px;min-width:96px}
.stat b{display:block;font-size:20px}.stat span{color:var(--muted);font-size:12px}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0 4px}
.btn{background:var(--panel2);color:var(--ink);border:1px solid var(--line);border-radius:999px;
padding:6px 12px;font-size:12px;cursor:pointer}
.btn.on{background:var(--accent);color:#05101f;border-color:var(--accent);font-weight:600}
.btn.ghost{border-radius:8px}
.card{background:var(--panel);border:1px solid var(--line);border-left-width:4px;border-radius:10px;
padding:14px 16px;margin:12px 0}
.card h3{margin:0 0 6px;font-size:15px}
.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:4px 0}
.tag{font-size:11px;padding:2px 8px;border-radius:999px;border:1px solid var(--line);color:var(--muted)}
.sev-critical{border-left-color:#ff5c7a}.sev-high{border-left-color:#ff8a3d}
.sev-medium{border-left-color:#ffd24a}.sev-low{border-left-color:#5cc0ff}.sev-info{border-left-color:#5c6f8f}
.badge{font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px}
.b-evidence{background:#123d28;color:#6ee7a8}.b-indicator{background:#3d3312;color:#ffd24a}
.b-candidate{background:#22314d;color:#9fb1cc}.b-needs-confirmation{background:#3d1f12;color:#ff9f6e}
.meter{height:6px;border-radius:4px;background:#22314d;overflow:hidden;width:120px;display:inline-block;vertical-align:middle}
.meter>i{display:block;height:100%;background:linear-gradient(90deg,#5cc0ff,#5cff9f)}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0f1b30;border:1px solid var(--line);
border-radius:8px;padding:10px 12px;margin:6px 0;font-size:12.5px}
.cmd{position:relative}
.cmd .copy{position:absolute;top:6px;right:6px;font-size:11px;padding:3px 9px}
ol{margin:6px 0;padding-left:20px}ol li{margin:3px 0}
.muted{color:var(--muted)}.small{font-size:12px}
.exp{border-left:3px solid var(--accent);padding:4px 10px;margin:6px 0;color:#cfe0f7;font-size:13px}
.hint{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:8px 12px;margin:6px 0;font-size:13px}
.note{background:#1a2740;border:1px solid var(--line);border-radius:8px;padding:10px 14px;font-size:12.5px;color:var(--muted)}
table{border-collapse:collapse;width:100%;font-size:12.5px;margin:6px 0}
td,th{border:1px solid var(--line);padding:6px 8px;text-align:left;overflow-wrap:anywhere}
th{background:var(--panel2)}
.hidden{display:none}
"""

# The renderer is intentionally dependency-free vanilla JS.
REPORT_JS = r"""
const CATLABEL = {};
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function el(tag,cls,html){const e=document.createElement(tag);if(cls)e.className=cls;if(html!=null)e.innerHTML=html;return e;}
let STATE={cat:'ALL',status:'ALL',data:null};

function statusBadge(s){const cls='b-'+s;return `<span class="badge ${cls}">${esc(s)}</span>`;}
function meter(c){const pct=Math.round((c||0)*100);return `<span class="meter"><i style="width:${pct}%"></i></span> <span class="small muted">${pct}%</span>`;}

function copyBtn(text){const b=el('button','btn ghost copy','Copy');b.addEventListener('click',()=>{navigator.clipboard&&navigator.clipboard.writeText(text);b.textContent='Copied';setTimeout(()=>b.textContent='Copy',1200);});return b;}

function findingCard(f){
  const c=el('div','card sev-'+(f.severity||'info'));
  c.dataset.cat=f.category;c.dataset.status=f.status;
  c.appendChild(el('h3',null,esc(f.category_label||f.category)+' &middot; '+esc(f.title)));
  const row=el('div','row');
  row.innerHTML=`${statusBadge(f.status)} <span class="tag">severity: ${esc(f.severity)}</span>
    <span class="tag">${esc(f.method||'GET')}</span>
    <span class="tag">source: ${esc(f.source)}</span> ${meter(f.confidence)}`;
  c.appendChild(row);
  const loc=el('div','small muted');
  loc.innerHTML='&#128205; '+esc(f.location)+(f.entry_point?(' &nbsp; entry: <b>'+esc(f.entry_point)+'</b>'):'');
  c.appendChild(loc);
  if(f.evidence){const p=el('pre');p.textContent='evidence: '+f.evidence;c.appendChild(p);}
  if(f.verification&&f.verification.length){
    c.appendChild(el('div','small muted',' '));
    c.appendChild(el('div',null,'<b class="small">Manual verification</b>'));
    const ol=el('ol');f.verification.forEach(s=>ol.appendChild(el('li','small',esc(s))));c.appendChild(ol);
  }
  if(f.commands&&f.commands.length){
    c.appendChild(el('div',null,'<b class="small">Kali / Linux commands</b>'));
    f.commands.forEach(cmd=>{const box=el('div','cmd');const pre=el('pre');pre.textContent=cmd;
      box.appendChild(pre);box.appendChild(copyBtn(cmd));c.appendChild(box);});
    const all=f.commands.join('\n');const ab=copyBtn(all);ab.textContent='Copy all';ab.className='btn ghost';
    c.appendChild(ab);
  }
  if(f.expected){c.appendChild(el('div','exp',esc(f.expected)));}
  return c;
}

function applyFilters(){
  document.querySelectorAll('#findings .card').forEach(c=>{
    const okC=STATE.cat==='ALL'||c.dataset.cat===STATE.cat;
    const okS=STATE.status==='ALL'||c.dataset.status===STATE.status;
    c.classList.toggle('hidden',!(okC&&okS));
  });
}

function renderResult(data,root){
  STATE.data=data;
  const m=data.metadata||{};const sum=m.summary||{};
  root.innerHTML='';
  // summary
  const bar=el('div','bar');
  const stats=[['vuln_findings','Vuln findings'],['endpoints','Endpoints'],
    ['cookies','Cookies'],['flag_hints','Flag hints'],['errors','Errors']];
  stats.forEach(([k,lab])=>{const s=el('div','stat');
    s.innerHTML=`<b>${sum[k]!=null?sum[k]:(data[k]||0)}</b><span>${lab}</span>`;bar.appendChild(s);});
  root.appendChild(bar);

  // most likely
  if(data.most_likely&&data.most_likely.length){
    root.appendChild(el('h2',null,'Most likely vulnerabilities'));
    const ml=el('div');data.most_likely.forEach(f=>{const r=el('div','hint');
      r.innerHTML=`${statusBadge(f.status)} <b>${esc(f.category_label||f.category)}</b> &middot; ${esc(f.title)}
        <div class="small muted">${esc(f.location)} ${f.entry_point?('&middot; '+esc(f.entry_point)):''} ${meter(f.confidence)}</div>`;
      ml.appendChild(r);});root.appendChild(ml);
  }

  // filters
  root.appendChild(el('h2',null,'Findings'));
  const counts=data.category_counts||{};
  const tb=el('div','toolbar');
  const cats=['ALL'].concat(Object.keys(counts).sort((a,b)=>counts[b]-counts[a]));
  cats.forEach(cat=>{const b=el('button','btn'+(cat==='ALL'?' on':''),
    cat==='ALL'?'All':(esc(cat)+' ('+counts[cat]+')'));
    b.addEventListener('click',()=>{STATE.cat=cat;tb.querySelectorAll('.btn').forEach(x=>x.classList.remove('on'));b.classList.add('on');applyFilters();});
    tb.appendChild(b);});
  root.appendChild(tb);
  const tb2=el('div','toolbar');
  [['ALL','All statuses'],['evidence','evidence'],['indicator','indicator'],
   ['candidate','candidate'],['needs-confirmation','needs-confirmation']].forEach(([st,lab])=>{
    const b=el('button','btn'+(st==='ALL'?' on':''),esc(lab));
    b.addEventListener('click',()=>{STATE.status=st;tb2.querySelectorAll('.btn').forEach(x=>x.classList.remove('on'));b.classList.add('on');applyFilters();});
    tb2.appendChild(b);});
  root.appendChild(tb2);

  const fc=el('div');fc.id='findings';
  (data.findings||[]).forEach(f=>fc.appendChild(findingCard(f)));
  if(!(data.findings||[]).length)fc.appendChild(el('div','note','No findings.'));
  root.appendChild(fc);

  // flag hints
  if(data.flag_hints&&data.flag_hints.length){
    root.appendChild(el('h2',null,'CTF flag hints'));
    data.flag_hints.forEach(h=>{const d=el('div','hint');
      d.innerHTML=`<span class="tag">${esc(h.kind)}</span> ${esc(h.detail)}
        <div class="small muted">${esc(h.location)}</div>`;root.appendChild(d);});
  }

  // endpoints
  if(data.endpoints&&data.endpoints.length){
    root.appendChild(el('h2',null,'Discovered endpoints ('+data.endpoints.length+')'));
    let t='<table><tr><th>Method</th><th>URL</th><th>Params</th><th>Source</th></tr>';
    data.endpoints.forEach(e=>{t+=`<tr><td>${esc(e.method)}</td><td>${esc(e.url)}</td>
      <td>${esc((e.params||[]).join(', '))}</td><td>${esc(e.source)}${e.note?(' / '+esc(e.note)):''}</td></tr>`;});
    root.appendChild(el('div',null,t+'</table>'));
  }

  // cookies
  if(data.cookies&&data.cookies.length){
    root.appendChild(el('h2',null,'Cookies'));
    let t='<table><tr><th>Name</th><th>HttpOnly</th><th>Secure</th><th>SameSite</th><th>Privilege?</th></tr>';
    data.cookies.forEach(c=>{t+=`<tr><td>${esc(c.name)}</td><td>${c.httponly}</td><td>${c.secure}</td>
      <td>${esc(c.samesite||'-')}</td><td>${c.looks_privilege?'yes':'-'}</td></tr>`;});
    root.appendChild(el('div',null,t+'</table>'));
  }

  // AI
  const ai=m.ai||{};
  root.appendChild(el('h2',null,'AI review'));
  if(ai.status==='ok'){root.appendChild(el('pre',null,esc(ai.analysis||'')));}
  else{root.appendChild(el('div','note','AI review: '+esc(ai.status||'disabled')+(ai.reason?(' - '+esc(ai.reason)):'')));}

  // errors
  if(data.errors&&data.errors.length){
    root.appendChild(el('h2',null,'Errors / notes ('+data.errors.length+')'));
    root.appendChild(el('pre',null,esc(data.errors.join('\n'))));
  }
}
"""
