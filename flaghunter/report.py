"""Write the JSON report and a self-contained interactive HTML report.

The HTML embeds the JSON result and renders it with the shared client-side
renderer in :mod:`flaghunter.ui`, so the offline report has the same filters,
copy-able commands and panels as the live dashboard. A "Download JSON" button
exports the embedded data.
"""

from __future__ import annotations

import json
from pathlib import Path

from .ui import REPORT_CSS, REPORT_JS


def _embed(data: dict) -> str:
    # Safe to inline inside <script>: break the only dangerous sequence.
    return json.dumps(data, ensure_ascii=False).replace("</", "<\\/")


def render_html(data: dict) -> str:
    target = data.get("target", "")
    sm = data.get("metadata", {}).get("summary", {})
    top = ""
    if sm.get("top_category"):
        top = f" &middot; most likely: <b>{sm['top_category']}</b>"
    return f"""<!doctype html>
<html lang="ru"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>FlagHunter report</title>
<style>{REPORT_CSS}</style>
</head><body><div class="wrap">
<h1>🛡 FlagHunter &middot; scan report</h1>
<p class="sub">Target: <b>{json.dumps(target)[1:-1]}</b>{top}</p>
<p class="note">Findings are <b>candidates / indicators</b>, not confirmed exploits. Verify each one by hand on your
authorised target. Only scan the CTF challenge URL you were given — never the competition platform itself.</p>
<div class="toolbar"><button class="btn ghost" id="dl">⬇ Download JSON</button></div>
<div id="root"></div>
</div>
<script id="data" type="application/json">{_embed(data)}</script>
<script>{REPORT_JS}</script>
<script>
const DATA=JSON.parse(document.getElementById('data').textContent);
renderResult(DATA,document.getElementById('root'));
document.getElementById('dl').addEventListener('click',()=>{{
  const blob=new Blob([JSON.stringify(DATA,null,2)],{{type:'application/json'}});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='flaghunter-report.json';a.click();
}});
</script>
</body></html>"""


def save_report(result, out) -> Path:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    data = result.to_dict()
    (out / "report.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "report.html").write_text(render_html(data), encoding="utf-8")
    return out / "report.html"
